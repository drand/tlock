package drnd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// EncryptWithRound will encrypt the plaintext that can only be decrypted in the
// future specified round.
func EncryptWithRound(ctx context.Context, dst io.Writer, plaintext io.Reader, network string, chainHash string, armor bool, round uint64) error {
	ni, err := retrieveNetworkInfo(ctx, network, chainHash)
	if err != nil {
		return fmt.Errorf("network info: %w", err)
	}

	roundData, err := ni.client.Get(ctx, round)
	if err != nil {
		return fmt.Errorf("client get round: %w", err)
	}

	return encrypt(dst, plaintext, ni, chainHash, armor, roundData.Round(), roundData.Signature())
}

// EncryptWithDuration will encrypt the plaintext that can only be decrypted in the
// future specified duration.
func EncryptWithDuration(ctx context.Context, dst io.Writer, plaintext io.Reader, network string, chainHash string, armor bool, duration time.Duration) error {
	ni, err := retrieveNetworkInfo(ctx, network, chainHash)
	if err != nil {
		return fmt.Errorf("network info: %w", err)
	}

	roundIDHash, roundID, err := calculateRound(duration, ni)
	if err != nil {
		return fmt.Errorf("calculate future round: %w", err)
	}

	return encrypt(dst, plaintext, ni, chainHash, armor, roundID, roundIDHash)
}

// encrypt provides base functionality for all encryption operations.
func encrypt(dst io.Writer, plaintext io.Reader, ni networkInfo, chainHash string, armor bool, round uint64, roundSignature []byte) error {
	suite, err := retrievePairingSuite()
	if err != nil {
		return fmt.Errorf("pairing suite: %w", err)
	}

	inputData, err := io.ReadAll(plaintext)
	if err != nil {
		return fmt.Errorf("reading input data: %w", err)
	}

	const fileKeySize int = 32
	dek := make([]byte, fileKeySize)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("random key: %w", err)
	}

	cipherDek, err := ibe.Encrypt(suite, ni.chain.PublicKey, roundSignature, dek)
	if err != nil {
		return fmt.Errorf("encrypt dek: %w", err)
	}

	cipherText, err := aeadEncrypt(dek, inputData)
	if err != nil {
		return fmt.Errorf("encrypt input: %w", err)
	}

	if err := write(dst, cipherDek, cipherText, round, chainHash, armor); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

// Decrypt reads the ciphertext from the encrypted tle source and returns the
// original plaintext.
func Decrypt(ctx context.Context, dst io.Writer, network string, ciphertext io.Reader) error {
	cipherInfo, err := read(ciphertext)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	ni, err := retrieveNetworkInfo(ctx, network, cipherInfo.chainHash)
	if err != nil {
		return fmt.Errorf("network info: %w", err)
	}

	suite, err := retrievePairingSuite()
	if err != nil {
		return fmt.Errorf("pairing suite: %w", err)
	}

	clientResult, err := ni.client.Get(ctx, cipherInfo.roundID)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("too early to decrypt")
		}
		return fmt.Errorf("client get round: %w", err)
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(clientResult.Signature()); err != nil {
		return fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	var dekKyberPoint bls.KyberG1
	if err := dekKyberPoint.UnmarshalBinary(cipherInfo.dek.kyberPoint); err != nil {
		return fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	dekCipherText := ibe.Ciphertext{
		U: &dekKyberPoint,
		V: cipherInfo.dek.cipherV,
		W: cipherInfo.dek.cipherW,
	}

	dek, err := ibe.Decrypt(suite, ni.chain.PublicKey, &dekSignature, &dekCipherText)
	if err != nil {
		return fmt.Errorf("decrypt dek: %w", err)
	}

	plaintext, err := aeadDecrypt(dek, cipherInfo.text)
	if err != nil {
		return fmt.Errorf("decrypt data: %w", err)
	}

	if _, err := dst.Write(plaintext); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	return nil
}

// =============================================================================

// networkInfo provides network and chain information.
type networkInfo struct {
	client client.Client
	chain  *chain.Info
}

// retrieveNetworkInfo accesses the specified network for the specified chain
// hash to extract information.
func retrieveNetworkInfo(ctx context.Context, network string, chainHash string) (networkInfo, error) {
	hash, err := hex.DecodeString(chainHash)
	if err != nil {
		return networkInfo{}, fmt.Errorf("decoding chain hash: %w", err)
	}

	client, err := dhttp.New(network, hash, transport())
	if err != nil {
		return networkInfo{}, fmt.Errorf("creating client: %w", err)
	}

	chain, err := client.Info(ctx)
	if err != nil {
		return networkInfo{}, fmt.Errorf("getting client information: %w", err)
	}

	ni := networkInfo{
		client: client,
		chain:  chain,
	}

	return ni, nil
}

// retrievePairingSuite returns the pairing suite to use.
func retrievePairingSuite() (pairing.Suite, error) {
	return bls.NewBLS12381Suite(), nil
}

// transport sets reasonable defaults for the connection.
func transport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// calculateRound will generate the round information based on the specified duration.
func calculateRound(duration time.Duration, ni networkInfo) (roundIDHash []byte, roundID uint64, err error) {

	// We need to get the future round number based on the duration. The following
	// call will do the required calculations based on the network `period` property
	// and return a uint64 representing the round number in the future. This round
	// number is used to encrypt the data and will also be used by the decrypt function.
	roundID = ni.client.RoundAt(time.Now().Add(duration))

	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundID)); err != nil {
		return nil, 0, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), roundID, nil
}
