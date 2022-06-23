package drnd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// EncryptWithRound will encrypt the message to be decrypted in the future based
// on the specified round.
func EncryptWithRound(ctx context.Context, dst io.Writer, dataToEncrypt io.Reader, network string, chainHash string, round uint64) error {
	ni, err := retrieveNetworkInfo(ctx, network, chainHash)
	if err != nil {
		return fmt.Errorf("network info: %w", err)
	}

	roundData, err := ni.client.Get(ctx, round)
	if err != nil {
		return fmt.Errorf("client get round: %w", err)
	}

	return encrypt(dst, dataToEncrypt, ni, chainHash, roundData.Round(), roundData.Signature())
}

// EncryptWithDuration will encrypt the message to be decrypted in the future based
// on the specified duration.
func EncryptWithDuration(ctx context.Context, dst io.Writer, dataToEncrypt io.Reader, network string, chainHash string, duration time.Duration) error {
	ni, err := retrieveNetworkInfo(ctx, network, chainHash)
	if err != nil {
		return fmt.Errorf("network info: %w", err)
	}

	roundIDHash, roundID, err := calculateRound(duration, ni)
	if err != nil {
		return fmt.Errorf("calculate future round: %w", err)
	}

	return encrypt(dst, dataToEncrypt, ni, chainHash, roundID, roundIDHash)
}

// Decrypt reads the encrypted output from the Encrypt function and decrypts
// the message if the time allows it.
func Decrypt(ctx context.Context, network string, dataToDecrypt io.Reader) ([]byte, error) {
	di, err := decode(dataToDecrypt)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ni, err := retrieveNetworkInfo(ctx, network, di.chainHash)
	if err != nil {
		return nil, fmt.Errorf("network info: %w", err)
	}

	suite, err := retrievePairingSuite()
	if err != nil {
		return nil, fmt.Errorf("pairing suite: %w", err)
	}

	clientResult, err := ni.client.Get(ctx, di.roundID)
	if err != nil {
		return nil, fmt.Errorf("client get round: %w", err)
	}

	var g2 bls.KyberG2
	if err := g2.UnmarshalBinary(clientResult.Signature()); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	var g1 bls.KyberG1
	if err := g1.UnmarshalBinary(di.kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	newCipherText := ibe.Ciphertext{
		U: &g1,
		V: di.cipherV,
		W: di.cipherW,
	}

	dek, err := ibe.Decrypt(suite, ni.chain.PublicKey, &g2, &newCipherText)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	data, err := aeadDecrypt(dek, di.encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return data, nil
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

// encrypt provides base functionality for all encryption operations.
func encrypt(dst io.Writer, dataToEncrypt io.Reader, ni networkInfo, chainHash string, round uint64, roundSignature []byte) error {
	suite, err := retrievePairingSuite()
	if err != nil {
		return fmt.Errorf("pairing suite: %w", err)
	}

	inputData, err := io.ReadAll(dataToEncrypt)
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

	encryptedData, err := aeadEncrypt(dek, inputData)
	if err != nil {
		return fmt.Errorf("encrypt input: %w", err)
	}

	if err := encode(dst, cipherDek, encryptedData, round, chainHash); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

// encode the meta data and encrypted data to the destination.
func encode(dst io.Writer, cipherDek *ibe.Ciphertext, encryptedData []byte, roundID uint64, chainHash string) error {
	kyberPoint, err := cipherDek.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary: %w", err)
	}

	fmt.Fprintln(dst, strconv.Itoa(int(roundID)))
	fmt.Fprintln(dst, chainHash)

	ww := bufio.NewWriter(dst)
	defer ww.Flush()

	fmt.Fprintf(ww, "%010d", len(kyberPoint))
	ww.Write(kyberPoint)

	fmt.Fprintf(ww, "%010d", len(cipherDek.V))
	ww.Write(cipherDek.V)

	fmt.Fprintf(ww, "%010d", len(cipherDek.W))
	ww.Write(cipherDek.W)

	fmt.Fprintf(ww, "%010d", len(encryptedData))
	ww.Write(encryptedData)

	return nil
}

// decodeInfo represents the different parts of any encrypted data.
type decodeInfo struct {
	roundID       uint64
	chainHash     string
	kyberPoint    []byte
	cipherV       []byte
	cipherW       []byte
	encryptedData []byte
}

// decode the encrypted data into its different parts.
func decode(src io.Reader) (decodeInfo, error) {
	rr := bufio.NewReader(src)

	roundIDStr, err := readHeaderLine(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read roundID: %w", err)
	}

	roundID, err := strconv.Atoi(roundIDStr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to convert round: %w", err)
	}

	chainHash, err := readHeaderLine(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read chain hash: %w", err)
	}

	kyberPoint, err := readPayloadBytes(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read kyber point: %w", err)
	}

	cipherV, err := readPayloadBytes(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read cipher v: %w", err)
	}

	cipherW, err := readPayloadBytes(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read cipher w: %w", err)
	}

	encryptedData, err := readPayloadBytes(rr)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("failed to read cipher w: %w", err)
	}

	di := decodeInfo{
		roundID:       uint64(roundID),
		chainHash:     chainHash,
		kyberPoint:    kyberPoint,
		cipherV:       cipherV,
		cipherW:       cipherW,
		encryptedData: encryptedData,
	}

	return di, nil
}

// readPayloadBytes reads the section of the payload.
func readPayloadBytes(rr *bufio.Reader) ([]byte, error) {
	lenStr := make([]byte, 10)
	if _, err := rr.Read(lenStr); err != nil {
		return nil, err
	}

	len, err := strconv.Atoi(string(lenStr))
	if err != nil {
		return nil, err
	}

	data := make([]byte, len)
	if _, err := rr.Read(data); err != nil {
		return nil, err
	}

	return data, nil
}

// readHeaderLine reads a line of header information.
func readHeaderLine(rr *bufio.Reader) (string, error) {
	text, err := rr.ReadString('\n')
	if err != nil {
		return "", err
	}

	return text[:len(text)-1], nil
}
