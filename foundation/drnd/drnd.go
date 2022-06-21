package drnd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// Drnd represents a distributed random API for encrypting and decrypting.
type Drnd struct {
	transport http.RoundTripper
	client    client.Client
	publicKey kyber.Point
	suite     pairing.Suite
}

// New constructs a distributed random value for encrypting and decrypting.
func New(ctx context.Context, network string, chainHash string, transport http.RoundTripper) (*Drnd, error) {
	hash, err := hex.DecodeString(chainHash)
	if err != nil {
		return nil, fmt.Errorf("decoding chain hash: %w", err)
	}

	client, err := dhttp.New(network, hash, transport)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	info, err := client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting client information: %w", err)
	}

	d := Drnd{
		transport: transport,
		client:    client,
		publicKey: info.PublicKey,
		suite:     bls.NewBLS12381Suite(),
	}

	return &d, nil
}

// Encrypt will encrypt the message to be decrypted in the future based on the
// specified duration.
func (d *Drnd) Encrypt(w io.Writer, duration time.Duration, message []byte) error {

	// We need to get the future round number based on the duration. The following
	// call will do the required calculations based on the network `period` property
	// and return a uint64 representing the round number in the future. This round
	// number is used to encrypt the data and will also be used by the decrypt function.
	round := d.client.RoundAt(time.Now().Add(duration))

	// Generate the future round ID based on the duration for the encrypt call.
	roundID, err := generateRoundID(round)
	if err != nil {
		return fmt.Errorf("get future round: %w", err)
	}

	// Encrypt the message.
	chipher, err := ibe.Encrypt(d.suite, d.publicKey, roundID, message)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Marshal the kyber point as it represents a part of the encrypted data.
	kyberPoint, err := chipher.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal binary: %w", err)
	}

	// Encode the encrypted data into base 64 for writing.
	kp := base64.StdEncoding.EncodeToString(kyberPoint)
	cv := base64.StdEncoding.EncodeToString(chipher.V)
	cw := base64.StdEncoding.EncodeToString(chipher.W)
	rn := strconv.Itoa(int(round))

	// Write encrypted message and separate each part with a dot.
	if _, err := fmt.Fprintf(w, "%s.%s.%s.%s", kp, cv, cw, rn); err != nil {
		return fmt.Errorf("writing encrypted message: %w", err)
	}

	return nil
}

// Decrypt reads the encrypted message from the reader and the round id for
// when it is valid to decrypt the message. If the round is available on the
// network used to encrypt, the message will be decrypted.
func (d *Drnd) Decrypt(ctx context.Context, r io.Reader) ([]byte, error) {

	// Read the encrypted message from the reader.
	encryptedData, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading encrypted data: %w", err)
	}

	// Split the encrypted message into its separate parts.
	parts := strings.Split(string(encryptedData), ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid encrypted data: parts %d: %w", len(parts), err)
	}

	// Decode each part out of the base64 encoding.
	kp, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding kyber point: %w", err)
	}
	cv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding cipher v: %w", err)
	}
	cw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding cipher w: %w", err)
	}
	rn, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, fmt.Errorf("parsing round id: %w", err)
	}

	// Recreate the kyber point, using Group1 (Ciphertext.U property)
	var g1 bls.KyberG1
	if err := g1.UnmarshalBinary(kp); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	// Get the future round number data. If it does not exist yet, it will
	// return an EOF error (HTTP 404).
	clientResult, err := d.client.Get(ctx, uint64(rn))
	if err != nil {
		return nil, fmt.Errorf("client get round: %w", err)
	}

	// If we can get the data from the future round above, we need to create
	// another kyber point but this time using Group2.
	var g2 bls.KyberG2
	if err := g2.UnmarshalBinary(clientResult.Signature()); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	// Construct a cipher text value.
	newCipherText := ibe.Ciphertext{
		U: &g1,
		V: cv,
		W: cw,
	}

	// Perform the decryption.
	decryptedData, err := ibe.Decrypt(d.suite, d.publicKey, &g2, &newCipherText)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return decryptedData, nil
}

// generateRoundID will generate a sha256 representing the future round id.
func generateRoundID(round uint64) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(round)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}
	return h.Sum(nil), nil
}
