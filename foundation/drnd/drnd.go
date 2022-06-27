package drnd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// Network represents a network that is used to encrypt and decrypt a DEK
// (Data Encryption Key) for use in encrypting and decrypting messages.
type Network interface {
	Host() string
	ChainHash() string
	Client(ctx context.Context) (client.Client, error)
	PublicKey(ctx context.Context) (kyber.Point, error)
}

// =============================================================================

// EncryptWithRound will encrypt the plaintext that can only be decrypted in the
// future specified round.
func EncryptWithRound(ctx context.Context, out io.Writer, in io.Reader, network Network, round uint64, armor bool) error {
	client, err := network.Client(ctx)
	if err != nil {
		return fmt.Errorf("network client: %w", err)
	}

	roundData, err := client.Get(ctx, round)
	if err != nil {
		return fmt.Errorf("client get round: %w", err)
	}

	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	return encrypt(out, in, publicKey, network.ChainHash(), roundData.Round(), roundData.Signature(), armor)
}

// EncryptWithDuration will encrypt the plaintext that can only be decrypted in the
// future specified duration.
func EncryptWithDuration(ctx context.Context, out io.Writer, in io.Reader, network Network, duration time.Duration, armor bool) error {
	client, err := network.Client(ctx)
	if err != nil {
		return fmt.Errorf("network client: %w", err)
	}

	roundIDHash, roundID, err := calculateRound(duration, client)
	if err != nil {
		return fmt.Errorf("calculate future round: %w", err)
	}

	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	return encrypt(out, in, publicKey, network.ChainHash(), roundID, roundIDHash, armor)
}

// encrypt provides base functionality for all encryption operations.
func encrypt(out io.Writer, in io.Reader, publickKey kyber.Point, chainHash string, roundID uint64, roundSignature []byte, armor bool) error {
	suite, err := retrievePairingSuite()
	if err != nil {
		return fmt.Errorf("pairing suite: %w", err)
	}

	inputData, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("reading input data: %w", err)
	}

	const fileKeySize int = 32
	dek := make([]byte, fileKeySize)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("random key: %w", err)
	}

	cipherDEK, err := ibe.Encrypt(suite, publickKey, roundSignature, dek)
	if err != nil {
		return fmt.Errorf("encrypt dek: %w", err)
	}

	cipherText, err := aeadEncrypt(dek, inputData)
	if err != nil {
		return fmt.Errorf("encrypt input: %w", err)
	}

	metadata := metadata{
		roundID:   roundID,
		chainHash: chainHash,
	}

	if err := write(out, cipherDEK, cipherText, metadata, armor); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

// Decrypt reads the ciphertext from the encrypted tle source and writes the
// original data to the output.
func Decrypt(ctx context.Context, out io.Writer, in io.Reader, network Network) error {
	file, err := read(in)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	plainDEK, err := DecryptDEK(ctx, file.cipherDEK, network, file.metadata.roundID)
	if err != nil {
		return fmt.Errorf("decrypt dek: %w", err)
	}

	plainData, err := DecryptData(plainDEK, file.cipherData)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if _, err := out.Write(plainData); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	return nil
}

// DecryptDEK attempts to decrypt an encrypted DEK against the provided network
// for the specified round.
func DecryptDEK(ctx context.Context, cipherDEK cipherDEK, network Network, roundID uint64) (plainDEK []byte, err error) {
	client, err := network.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("network client: %w", err)
	}

	suite, err := retrievePairingSuite()
	if err != nil {
		return nil, fmt.Errorf("pairing suite: %w", err)
	}

	clientResult, err := client.Get(ctx, roundID)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("too early to decrypt")
		}
		return nil, fmt.Errorf("client get round: %w", err)
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(clientResult.Signature()); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	var dekKyberPoint bls.KyberG1
	if err := dekKyberPoint.UnmarshalBinary(cipherDEK.kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	dek := ibe.Ciphertext{
		U: &dekKyberPoint,
		V: cipherDEK.cipherV,
		W: cipherDEK.cipherW,
	}

	plainDEK, err = ibe.Decrypt(suite, publicKey, &dekSignature, &dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}

// DecryptData decrypts the message with the specified data encryption key.
func DecryptData(plainDEK []byte, cipherData []byte) (plainData []byte, err error) {
	plainData, err = aeadDecrypt(plainDEK, cipherData)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plainData, nil
}

// =============================================================================

// retrievePairingSuite returns the pairing suite to use.
func retrievePairingSuite() (pairing.Suite, error) {
	return bls.NewBLS12381Suite(), nil
}

// calculateRound will generate the round information based on the specified duration.
func calculateRound(duration time.Duration, client client.Client) (roundIDHash []byte, roundID uint64, err error) {

	// We need to get the future round number based on the duration. The following
	// call will do the required calculations based on the network `period` property
	// and return a uint64 representing the round number in the future. This round
	// number is used to encrypt the data and will also be used by the decrypt function.
	roundID = client.RoundAt(time.Now().Add(duration))

	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundID)); err != nil {
		return nil, 0, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), roundID, nil
}
