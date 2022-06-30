// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/drand/drand/client"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/kyber/pairing"
)

// ErrTooEarly represents an error when a decryption operation happens early.
const ErrTooEarly = "too early to decrypt"

// =============================================================================

// Metadata represents the metadata that must exist in the encrypted output
// to support CipherDEK decryption.
type Metadata struct {
	RoundID   uint64
	ChainHash string
}

// CipherDEK represents the encrypted data encryption key (DEK) needed to decrypt
// the cipher data.
type CipherDEK struct {
	KyberPoint []byte
	CipherV    []byte
	CipherW    []byte
}

// CipherInfo represents the different parts of the fully encrypted output.
type CipherInfo struct {
	Metadata   Metadata  // Metadata provides information to decrypt the CipherDEK.
	CipherDEK  CipherDEK // CipherDEK represents the key to decrypt the CipherData.
	CipherData []byte    // CipherData represents the data that has been encrypted.
}

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	Host() string
	ChainHash() string
	PairingSuite() pairing.Suite
	Client(ctx context.Context) (client.Client, error)
	PublicKey(ctx context.Context) (kyber.Point, error)
	RoundByNumber(ctx context.Context, roundNumber uint64) (roundID uint64, roundSignature []byte, err error)
	RoundByDuration(ctx context.Context, duration time.Duration) (roundID uint64, roundSignature []byte, err error)
}

// Decoder knows how to decode CipherInfo from the specified source.
type Decoder interface {
	Decode(in io.Reader) (CipherInfo, error)
}

// Encoder knows how to encode CipherInfo to the specified destination.
type Encoder interface {
	Encode(out io.Writer, cipherDEK *ibe.Ciphertext, cipherData []byte, md Metadata, armor bool) error
}

// Encrypter encrypts plain data with the specified key.
type Encrypter interface {
	Encrypt(key []byte, plainData []byte) (cipherData []byte, err error)
}

// Decrypter decrypts cipher data with the specified key.
type Decrypter interface {
	Decrypt(key []byte, cipherData []byte) (plainData []byte, err error)
}

// =============================================================================

// EncryptWithRound will encrypt the data that is read by the reader which can
// only be decrypted in the future specified round.
func EncryptWithRound(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, roundNumber uint64, armor bool) error {
	roundID, roundSignature, err := network.RoundByNumber(ctx, roundNumber)
	if err != nil {
		return fmt.Errorf("round by number: %w", err)
	}

	return encrypt(ctx, out, in, encoder, network, encrypter, roundID, roundSignature, armor)
}

// EncryptWithDuration will encrypt the data that is read by the reader which can
// only be decrypted in the future specified duration.
func EncryptWithDuration(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, duration time.Duration, armor bool) error {
	roundID, roundSignature, err := network.RoundByDuration(ctx, duration)
	if err != nil {
		return fmt.Errorf("round by duration: %w", err)
	}

	return encrypt(ctx, out, in, encoder, network, encrypter, roundID, roundSignature, armor)
}

// encrypt provides base functionality for all encryption operations.
func encrypt(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, encrypter Encrypter, roundID uint64, roundSignature []byte, armor bool) error {
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

	cipherData, err := encrypter.Encrypt(dek, data)
	if err != nil {
		return fmt.Errorf("encrypt data: %w", err)
	}

	metadata := Metadata{
		RoundID:   roundID,
		ChainHash: network.ChainHash(),
	}

	if err := encoder.Encode(out, cipherDEK, cipherData, metadata, armor); err != nil {
		return fmt.Errorf("encode: %w", err)
	}

	return nil
}

// =============================================================================

// Decrypt will decrypt the data that is read by the reader and writes the
// original data to the output.
func Decrypt(ctx context.Context, out io.Writer, in io.Reader, decoder Decoder, network Network, decrypter Decrypter) error {
	info, err := decoder.Decode(in)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	plainDEK, err := decryptDEK(ctx, info.CipherDEK, network, info.Metadata.RoundID)
	if err != nil {
		return fmt.Errorf("decrypt dek: %w", err)
	}

	plainData, err := decrypter.Decrypt(plainDEK, info.CipherData)
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
func decryptDEK(ctx context.Context, cipherDEK CipherDEK, network Network, roundNumber uint64) (plainDEK []byte, err error) {
	client, err := network.Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("network client: %w", err)
	}

	latestRound := client.RoundAt(time.Now())

	if roundNumber > latestRound {
		return nil, errors.New(ErrTooEarly)
	}

	_, roundSignature, err := network.RoundByNumber(ctx, roundNumber)
	if err != nil {
		return nil, fmt.Errorf("round by number: %w", err)
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(roundSignature); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	var dekKyberPoint bls.KyberG1
	if err := dekKyberPoint.UnmarshalBinary(cipherDEK.KyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	dek := ibe.Ciphertext{
		U: &dekKyberPoint,
		V: cipherDEK.CipherV,
		W: cipherDEK.CipherW,
	}

	plainDEK, err = ibe.Decrypt(network.PairingSuite(), publicKey, &dekSignature, &dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}
