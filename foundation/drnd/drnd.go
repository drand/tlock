package drnd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
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

	return encrypt(dst, dataToEncrypt, network, ni, chainHash, roundData.Round(), roundData.Signature())
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

	return encrypt(dst, dataToEncrypt, network, ni, chainHash, roundID, roundIDHash)
}

// Decrypt reads the encrypted output from the Encrypt function and decrypts
// the message if the time allows it.
func Decrypt(ctx context.Context, dataToDecrypt io.Reader) ([]byte, error) {
	di, err := decode(dataToDecrypt)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ni, err := retrieveNetworkInfo(ctx, di.network, di.chainHash)
	if err != nil {
		return nil, fmt.Errorf("network info: %w", err)
	}

	suite, err := retrievePairingSuite()
	if err != nil {
		return nil, fmt.Errorf("pairing suite: %w", err)
	}

	// Get returns the randomness at `round` or an error. If it does not exist
	// yet, it will return an EOF error (HTTP 404).
	clientResult, err := ni.client.Get(ctx, di.roundID)
	if err != nil {
		return nil, fmt.Errorf("client get round: %w", err)
	}

	// If we can get the data from the future round above, we need to create
	// another kyber point but this time using Group2.
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

	decryptedData, err := ibe.Decrypt(suite, ni.chain.PublicKey, &g2, &newCipherText)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return decryptedData, nil
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

// encode the meta data and encrypted data to the destination.
func encode(dst io.Writer, cipher *ibe.Ciphertext, roundID uint64, network string, chainHash string) error {
	kyberPoint, err := cipher.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary: %w", err)
	}

	// Write the header as plain text.
	// Hash the header data using sha256 and write it.
	// Encode the cipher data into binary encoding and write it.

	rn := strconv.Itoa(int(roundID))
	nt := network
	ch := chainHash
	// kp := base64.StdEncoding.EncodeToString(kyberPoint)
	// cv := base64.StdEncoding.EncodeToString(cipher.V)
	// cw := base64.StdEncoding.EncodeToString(cipher.W)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, kyberPoint)
	binary.Write(buf, binary.LittleEndian, cipher.V)
	binary.Write(buf, binary.LittleEndian, cipher.W)

	if _, err := fmt.Fprintf(dst, "%s\n%s\n%s\n%s", rn, nt, ch, buf); err != nil {
		return fmt.Errorf("writing encrypted message: %w", err)
	}

	return nil
}

// decodeInfo represents the different parts of any encrypted data.
type decodeInfo struct {
	roundID    uint64
	network    string
	chainHash  string
	kyberPoint []byte
	cipherV    []byte
	cipherW    []byte
}

// decode the encrypted data into its different parts.
func decode(src io.Reader) (decodeInfo, error) {
	encryptedData, err := io.ReadAll(src)
	if err != nil {
		return decodeInfo{}, fmt.Errorf("reading encrypted data: %w", err)
	}

	parts := strings.Split(string(encryptedData), "\n")
	if len(parts) != 4 {
		return decodeInfo{}, fmt.Errorf("invalid encrypted data: parts %d: %w", len(parts), err)
	}

	roundID, err := strconv.Atoi(parts[0])
	if err != nil {
		return decodeInfo{}, fmt.Errorf("parsing round id: %w", err)
	}

	network := parts[1]
	chainHash := parts[2]

	res := []byte{}

	binary.Read(src, binary.LittleEndian, res)

	fmt.Println(string(res))

	// kyberPoint, err := base64.StdEncoding.DecodeString(parts[3])
	// if err != nil {
	// 	return decodeInfo{}, fmt.Errorf("decoding kyber point: %w", err)
	// }

	// cipherV, err := base64.StdEncoding.DecodeString(parts[4])
	// if err != nil {
	// 	return decodeInfo{}, fmt.Errorf("decoding cipher v: %w", err)
	// }

	// cipherW, err := base64.StdEncoding.DecodeString(parts[5])
	// if err != nil {
	// 	return decodeInfo{}, fmt.Errorf("decoding cipher w: %w", err)
	// }

	di := decodeInfo{
		roundID:   uint64(roundID),
		network:   network,
		chainHash: chainHash,
		// kyberPoint: kyberPoint,
		// cipherV:    cipherV,
		// cipherW:    cipherW,
	}

	return di, nil
}

// encrypt provides base functionality for all encryption operations.
func encrypt(dst io.Writer, dataToEncrypt io.Reader, network string, ni networkInfo, chainHash string, round uint64, roundSignature []byte) error {
	suite, err := retrievePairingSuite()
	if err != nil {
		return fmt.Errorf("pairing suite: %w", err)
	}

	inputData, err := io.ReadAll(dataToEncrypt)
	if err != nil {
		return fmt.Errorf("reading input data: %w", err)
	}

	cipher, err := ibe.Encrypt(suite, ni.chain.PublicKey, roundSignature, inputData)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if err := encode(dst, cipher, round, network, chainHash); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}
