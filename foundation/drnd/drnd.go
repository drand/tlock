// Package drnd provides an API for encrypting and decrypting data using
// drand time lock encryption.
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

const ErrTooEarly = "too early to decrypt"

// Network represents a network that is used to encrypt and decrypt a DEK
// (Data Encryption Key) for use in encrypting and decrypting data.
type Network interface {
	Host() string
	ChainHash() string
	PairingSuite() pairing.Suite
	Client(ctx context.Context) (client.Client, error)
	PublicKey(ctx context.Context) (kyber.Point, error)
	RoundByNumber(ctx context.Context, roundNumber uint64) (roundID uint64, roundSignature []byte, err error)
	RoundByDuration(ctx context.Context, duration time.Duration) (roundID uint64, roundSignature []byte, err error)
}

// Encrypter declares an API for encrypting plain data with the specified key.
type Encrypter interface {
	Encrypt(key []byte, plainData []byte) (cipherData []byte, err error)
}

// Decrypter declares an API for decrypting cipher data with the specified key.
type Decrypter interface {
	Decrypt(key []byte, cipherData []byte) (plainData []byte, err error)
}

// =============================================================================

// EncryptWithRound will encrypt the data that is read by the reader which can
// only be decrypted in the future specified round.
func EncryptWithRound(ctx context.Context, out io.Writer, in io.Reader, network Network, enc Encrypter, roundNumber uint64, armor bool) error {
	roundID, roundSignature, err := network.RoundByNumber(ctx, roundNumber)
	if err != nil {
		return fmt.Errorf("round by number: %w", err)
	}

	return encrypt(ctx, out, in, enc, network, roundID, roundSignature, armor)
}

// EncryptWithDuration will encrypt the data that is read by the reader which can
// only be decrypted in the future specified duration.
func EncryptWithDuration(ctx context.Context, out io.Writer, in io.Reader, network Network, enc Encrypter, duration time.Duration, armor bool) error {
	roundID, roundSignature, err := network.RoundByDuration(ctx, duration)
	if err != nil {
		return fmt.Errorf("round by duration: %w", err)
	}

	return encrypt(ctx, out, in, enc, network, roundID, roundSignature, armor)
}

// encrypt provides base functionality for all encryption operations.
func encrypt(ctx context.Context, out io.Writer, in io.Reader, enc Encrypter, network Network, roundID uint64, roundSignature []byte, armor bool) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("reading input data: %w", err)
	}

	const fileKeySize int = 32
	dek := make([]byte, fileKeySize)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("random key: %w", err)
	}

	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	cipherDEK, err := ibe.Encrypt(network.PairingSuite(), publicKey, roundSignature, dek)
	if err != nil {
		return fmt.Errorf("encrypt dek: %w", err)
	}

	cipherData, err := enc.Encrypt(dek, data)
	if err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}

	metadata := metadata{
		roundID:   roundID,
		chainHash: network.ChainHash(),
	}

	if err := write(out, cipherDEK, cipherData, metadata, armor); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

// =============================================================================

// Decrypt will decrypt the data that is read by the reader and writes the
// original data to the output.
func Decrypt(ctx context.Context, out io.Writer, in io.Reader, network Network, dec Decrypter) error {
	file, err := read(in)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	plainDEK, err := decryptDEK(ctx, file.cipherDEK, network, file.metadata.roundID)
	if err != nil {
		return fmt.Errorf("decrypt dek: %w", err)
	}

	plainData, err := dec.Decrypt(plainDEK, file.cipherData)
	if err != nil {
		return fmt.Errorf("decrypt data: %w", err)
	}

	if _, err := out.Write(plainData); err != nil {
		return fmt.Errorf("write data: %w", err)
	}

	return nil
}

// decryptDEK attempts to decrypt an encrypted DEK against the provided network
// for the specified round.
func decryptDEK(ctx context.Context, cipherDEK cipherDEK, network Network, roundNumber uint64) (plainDEK []byte, err error) {
	_, roundSignature, err := network.RoundByNumber(ctx, roundNumber)
	if err != nil {
		return nil, errors.New(ErrTooEarly)
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(roundSignature); err != nil {
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

	plainDEK, err = ibe.Decrypt(network.PairingSuite(), publicKey, &dekSignature, &dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}

// =============================================================================

// CalculateRound will generate the round information based on the specified duration.
func CalculateRound(ctx context.Context, duration time.Duration, network Network) (roundID uint64, roundSignature []byte, err error) {
	client, err := network.Client(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("client: %w", err)
	}

	// We need to get the future round number based on the duration. The following
	// call will do the required calculations based on the network `period` property
	// and return a uint64 representing the round number in the future. This round
	// number is used to encrypt the data and will also be used by the decrypt function.
	roundID = client.RoundAt(time.Now().Add(duration))

	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundID)); err != nil {
		return 0, nil, fmt.Errorf("sha256 write: %w", err)
	}

	return roundID, h.Sum(nil), nil
}
