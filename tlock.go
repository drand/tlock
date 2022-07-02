// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/common/scheme"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
)

// ErrTooEarly represents an error when a decryption operation happens early.
var ErrTooEarly = errors.New("too early to decrypt")

// =============================================================================

// MetaData represents the metadata that must exist in the encrypted output
// to support CipherDEK decryption.
type MetaData struct {
	RoundNumber uint64
	ChainHash   string
}

// CipherDEK represents the encrypted data encryption key (DEK) needed to decrypt
// the cipher data.
type CipherDEK struct {
	KyberPoint []byte
	CipherV    []byte
	CipherW    []byte
}

// CipherInfo represents the data that is encoded and decoded.
type CipherInfo struct {
	MetaData   MetaData  // Metadata provides information to decrypt the CipherDEK.
	CipherDEK  CipherDEK // CipherDEK represents the key to decrypt the CipherData.
	CipherData []byte    // CipherData represents the data that has been encrypted.
}

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	Host() string
	ChainHash() string
	PublicKey(ctx context.Context) (kyber.Point, error)
	IsReadyToDecrypt(ctx context.Context, roundNumber uint64) (id []byte, ready bool)
	RoundNumber(ctx context.Context, t time.Time) (uint64, error)
}

// Decoder knows how to decode CipherInfo from the specified source.
type Decoder interface {
	Decode(in io.Reader, armor bool) (CipherInfo, error)
}

// Encoder knows how to encode CipherInfo to the specified destination.
type Encoder interface {
	Encode(out io.Writer, cipherInfo CipherInfo, armor bool) error
}

// DataEncrypter encrypts plain data with the specified key.
type DataEncrypter interface {
	Encrypt(key []byte, plainData []byte) (cipherData []byte, err error)
}

// DataDecrypter decrypts cipher data with the specified key.
type DataDecrypter interface {
	Decrypt(key []byte, cipherData []byte) (plainData []byte, err error)
}

// =============================================================================

// Encrypter provides an API for time lock encryption.
type Encrypter struct {
	network       Network
	dataEncrypter DataEncrypter
	encoder       Encoder
}

// New constructs a Tlock for use with the specified network, encrypter, and encoder.
func NewEncrypter(network Network, dataEncrypter DataEncrypter, encoder Encoder) Encrypter {
	return Encrypter{
		network:       network,
		dataEncrypter: dataEncrypter,
		encoder:       encoder,
	}
}

// Encrypt will encrypt the data that is read by the reader which can only be
// decrypted in the future specified round.
func (t Encrypter) Encrypt(ctx context.Context, out io.Writer, in io.Reader, roundNumber uint64, armor bool) error {
	id, err := calculateEncryptionID(roundNumber)
	if err != nil {
		return fmt.Errorf("round by number: %w", err)
	}

	return encrypt(ctx, out, in, t.encoder, t.network, t.dataEncrypter, roundNumber, id, armor)
}

// calculateEncryptionID will generate the id required for encryption.
func calculateEncryptionID(roundNumber uint64) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundNumber)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), nil
}

// encrypt constructs a data encryption key that is encrypted with the time
// lock encryption for the specifed round. Then the input source is encrypted
// and encoded to the output destination in 64k byte chunks.
func encrypt(ctx context.Context, out io.Writer, in io.Reader, encoder Encoder, network Network, dataEncrypter DataEncrypter, roundNumber uint64, id []byte, armor bool) error {

	// Create the DEK for this encryption.
	const fileKeySize int = 32
	dek := make([]byte, fileKeySize)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("random key: %w", err)
	}
	publicKey, err := network.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}

	// Encrypt the DEK using time lock encryption.
	cipherText, err := ibe.Encrypt(bls.NewBLS12381Suite(), publicKey, id, dek)
	if err != nil {
		return fmt.Errorf("encrypt dek: %w", err)
	}

	// Construct the cipher information that will be written to
	// the ouput destination.
	kyberPoint, err := cipherText.U.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal kyber point: %w", err)
	}
	cipherInfo := CipherInfo{
		MetaData: MetaData{
			RoundNumber: roundNumber,
			ChainHash:   network.ChainHash(),
		},
		CipherDEK: CipherDEK{
			KyberPoint: kyberPoint,
			CipherV:    cipherText.V,
			CipherW:    cipherText.W,
		},
	}

	// Encrypt the source data in 64k byte chunks, encoding the MetaData and
	// CipherDEK with each unique chunk of encrypted data that is written.

	var done bool
	var data [1024 * 64]byte

	for {
		if done {
			return nil
		}

		// Read in a 64k chunk of data from the input source.
		n, err := io.ReadFull(in, data[:])

		// io.EOF:              There were no bytes left to read.
		// io.ErrUnexpectedEOF: We read the last remaining bytes from the input source.
		// err != nil           There is a problem with the encoding.
		switch {
		case errors.Is(err, io.EOF):
			return nil

		case errors.Is(err, io.ErrUnexpectedEOF):
			done = true

		case err != nil:
			return fmt.Errorf("decoding input data: %w", err)
		}

		// Encrypt the chunk of data.
		cipherInfo.CipherData, err = dataEncrypter.Encrypt(dek, data[:n])
		if err != nil {
			return fmt.Errorf("encrypt data: %w", err)
		}

		// Encode this chunk of data to the output destination.
		if err := encoder.Encode(out, cipherInfo, armor); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
}

// =============================================================================

// Decrypter provides an API for time lock decryption.
type Decrypter struct {
	network       Network
	dataDecrypter DataDecrypter
	decoder       Decoder
}

// New constructs a Tlock for use with the specified network, decrypter, and decoder.
func NewDecrypter(network Network, dataDecrypter DataDecrypter, decoder Decoder) Decrypter {
	return Decrypter{
		network:       network,
		dataDecrypter: dataDecrypter,
		decoder:       decoder,
	}
}

// Decrypt decode the input source for a CipherData value. For each CipherData
// value that is decoded, the DEK is decrypted with time lock decryption so
// the cipher data can then be decrypted with that key and written to the
// specified output destination.
func (t Decrypter) Decrypt(ctx context.Context, out io.Writer, in io.Reader, armor bool) error {
	var done bool

	for {
		if done {
			return nil
		}

		// Read and decode the next cipherInfo that exists in the input source.
		info, err := t.decoder.Decode(in, armor)

		// io.EOF:              There were no bytes left to read.
		// io.ErrUnexpectedEOF: We read the last remaining bytes from the input source.
		// err != nil           There is a problem with the decoding.
		switch {
		case errors.Is(err, io.EOF):
			return nil

		case errors.Is(err, io.ErrUnexpectedEOF):
			done = true

		case err != nil:
			return fmt.Errorf("decoding input data: %w", err)
		}

		// Decrypt the dek using time lock decryption.
		plainDEK, err := decryptDEK(ctx, info.CipherDEK, t.network, info.MetaData.RoundNumber)
		if err != nil {
			return fmt.Errorf("decrypt dek: %w", err)
		}

		// Decrypt the chunk of data returned with the cipherInfo.
		plainData, err := t.dataDecrypter.Decrypt(plainDEK, info.CipherData)
		if err != nil {
			return fmt.Errorf("decrypt data: %w", err)
		}

		// Write the decrypted data to the destination.
		if _, err := out.Write(plainData); err != nil {
			return fmt.Errorf("write data: %w", err)
		}
	}
}

// decryptDEK attempts to decrypt an encrypted DEK against the provided network
// for the specified round.
func decryptDEK(ctx context.Context, cipherDEK CipherDEK, network Network, roundNumber uint64) (plainDEK []byte, err error) {
	id, ready := network.IsReadyToDecrypt(ctx, roundNumber)
	if !ready {
		return nil, ErrTooEarly
	}

	var dekSignature bls.KyberG2
	if err := dekSignature.UnmarshalBinary(id); err != nil {
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

	b := chain.Beacon{
		Round:     roundNumber,
		Signature: id,
	}
	sch := scheme.Scheme{
		ID:              scheme.UnchainedSchemeID,
		DecouplePrevSig: true,
	}
	if err := chain.NewVerifier(sch).VerifyBeacon(b, publicKey); err != nil {
		return nil, fmt.Errorf("verify beacon: %w", err)
	}

	dek := ibe.Ciphertext{
		U: &dekKyberPoint,
		V: cipherDEK.CipherV,
		W: cipherDEK.CipherW,
	}

	plainDEK, err = ibe.Decrypt(bls.NewBLS12381Suite(), publicKey, &dekSignature, &dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return plainDEK, nil
}
