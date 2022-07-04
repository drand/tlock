// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"filippo.io/age"
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

// NewEncrypter constructs a Tlock for use with the specified network, encrypter, and encoder.
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
	if armor {
		// TODO
		fmt.Println("Not implemented yet")
	}
	w, err := age.Encrypt(out, &TLERecipient{network: t.network, round: roundNumber})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if _, err := io.Copy(w, in); err != nil {
		return fmt.Errorf("%v", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%v", err)
	}

	return nil
}

// calculateEncryptionID will generate the id required for encryption.
func calculateEncryptionID(roundNumber uint64) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundNumber)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), nil
}

type TLERecipient struct {
	round   uint64
	network Network
}

var _ age.Recipient = &TLERecipient{}

func (t *TLERecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	l := &age.Stanza{
		Type: "tlock",
		Args: []string{strconv.FormatUint(t.round, 10), t.network.ChainHash()},
	}

	id, err := calculateEncryptionID(t.round)
	if err != nil {
		return nil, fmt.Errorf("round by number: %w", err)
	}

	publicKey, err := t.network.PublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	// Encrypt the DEK using time lock encryption.
	cipherText, err := ibe.Encrypt(bls.NewBLS12381Suite(), publicKey, id, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	// Construct the cipher information that will be written to
	// the ouput destination.
	kyberPoint, err := cipherText.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	cipher := append(kyberPoint, cipherText.V...)
	cipher = append(cipher, cipherText.W...)
	l.Body = cipher

	return []*age.Stanza{l}, nil
}

type TLEIdentity struct {
	network Network
}

var _ age.Identity = &TLEIdentity{}

func (t *TLEIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type == "tlock" && len(stanzas) != 1 {
			return nil, errors.New("a tlock recipient must be the only one")
		}
	}

	block := stanzas[0]

	if block.Type != "tlock" {
		return nil, fmt.Errorf("%w: not a tlock recipient block", age.ErrIncorrectIdentity)
	}
	if len(block.Args) != 2 {
		return nil, fmt.Errorf("%w: invalid tlock recipient block", age.ErrIncorrectIdentity)
	}

	blockRound, err := strconv.ParseUint(block.Args[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid block round", age.ErrIncorrectIdentity)
	}

	if t.network.ChainHash() != block.Args[1] {
		return nil, fmt.Errorf("%w: invalid chainhash", age.ErrIncorrectIdentity)
	}

	cipherDEK, err := readCipherDEK(bytes.NewReader(block.Body))
	if err != nil {
		return nil, fmt.Errorf("%w: unable to read tlock block: %v", age.ErrIncorrectIdentity, err)
	}

	plainDEK, err := decryptDEK(context.Background(), cipherDEK, t.network, blockRound)
	if err != nil {
		return nil, fmt.Errorf("%w: error while decrypting filekey: %v", age.ErrIncorrectIdentity, err)
	}

	return plainDEK, nil
}

const (
	kyberPointLen = 48
	cipherVLen    = 32
	cipherWLen    = 32
)

func readCipherDEK(in io.Reader) (CipherDEK, error) {
	kyberPoint, err := readBytes(in, kyberPointLen)
	if err != nil {
		return CipherDEK{}, fmt.Errorf("read kyber point: %w", err)
	}

	cipherV, err := readBytes(in, cipherVLen)
	if err != nil {
		return CipherDEK{}, fmt.Errorf("read cipher v: %w", err)
	}

	cipherW, err := readBytes(in, cipherWLen)
	if err != nil {
		return CipherDEK{}, fmt.Errorf("read cipher w: %w", err)
	}

	cd := CipherDEK{
		KyberPoint: kyberPoint,
		CipherV:    cipherV,
		CipherW:    cipherW,
	}

	return cd, nil
}

// readBytes reads the specified number of bytes from the reader.
func readBytes(in io.Reader, length int) ([]byte, error) {
	data := make([]byte, length)
	n, err := io.ReadFull(in, data)

	switch {
	case err == io.EOF:
		return []byte{}, io.EOF

	case err == io.ErrUnexpectedEOF:
		return data[:n], io.ErrUnexpectedEOF

	case err != nil:
		return []byte{}, err
	}

	return data[:n], nil
}

// =============================================================================

// Decrypter provides an API for time lock decryption.
type Decrypter struct {
	network       Network
	dataDecrypter DataDecrypter
	decoder       Decoder
}

// NewDecrypter constructs a Tlock for use with the specified network, decrypter, and decoder.
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
	plainReader, err := age.Decrypt(in, &TLEIdentity{network: t.network})
	if err != nil {
		return fmt.Errorf("%w: unable to decrypt", err)
	}
	if _, err := io.Copy(out, plainReader); err != nil {
		return fmt.Errorf("%w: unable to copy", err)
	}
	return nil
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
