// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/drand/drand/chain"
	"github.com/drand/drand/common/scheme"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
)

// ErrTooEarly represents an error when a decryption operation happens early.
var ErrTooEarly = errors.New("too early to decrypt")

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	ChainHash() string
	PublicKey() kyber.Point
	Signature(roundNumber uint64) ([]byte, error)
}

// =============================================================================

// Tlock provides an API for time lock encryption and decryption.
type Tlock struct {
	network Network
}

// New constructs a tlock for the specified network which can encrypt data that
// can be decrypted until the future.
func New(network Network) Tlock {
	return Tlock{
		network: network,
	}
}

// Encrypt will encrypt the source and write that to the destination. The encrypted
// data will not be decryptable until the specified round is reached by the network.
func (t Tlock) Encrypt(dst io.Writer, src io.Reader, roundNumber uint64) (err error) {
	w, err := age.Encrypt(dst, &tleRecipient{network: t.network, roundNumber: roundNumber})
	if err != nil {
		return fmt.Errorf("age encrypt: %w", err)
	}

	defer func() {
		if err = w.Close(); err != nil {
			err = fmt.Errorf("close: %w", err)
		}
	}()

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// Decrypt will decrypt the source and write that to the destination. The decrypted
// data will not be decryptable unless the specified round from the encrypt call
// is reached by the network.
func (t Tlock) Decrypt(dst io.Writer, src io.Reader) error {
	rr := bufio.NewReader(src)

	if start, _ := rr.Peek(len(armor.Header)); string(start) == armor.Header {
		src = armor.NewReader(rr)
	} else {
		src = rr
	}

	r, err := age.Decrypt(src, &tleIdentity{network: t.network})
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// =============================================================================

// TimeLock encrypts the specified data for the given round number. The data
// can't be decrypted until the specified round is reached by the network in use.
func TimeLock(publicKey kyber.Point, roundNumber uint64, data []byte) (*ibe.Ciphertext, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundNumber)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}
	id := h.Sum(nil)

	cipherText, err := ibe.Encrypt(bls.NewBLS12381Suite(), publicKey, id, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	return cipherText, nil
}

// TimeUnlock decrypts the specified ciphertext for the given beacon. The
// ciphertext can't be decrypted until the specified round is reached by the network in use.
func TimeUnlock(publicKey kyber.Point, beacon chain.Beacon, ciphertext *ibe.Ciphertext) ([]byte, error) {
	sch := scheme.Scheme{
		ID:              scheme.UnchainedSchemeID,
		DecouplePrevSig: true,
	}
	if err := chain.NewVerifier(sch).VerifyBeacon(beacon, publicKey); err != nil {
		return nil, fmt.Errorf("verify beacon: %w", err)
	}

	var signature bls.KyberG2
	if err := signature.UnmarshalBinary(beacon.Signature); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}

	data, err := ibe.Decrypt(bls.NewBLS12381Suite(), &signature, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return data, nil
}

// =============================================================================

// These constants define the size of the different CipherDEK fields.
const (
	kyberPointLen = 48
	cipherVLen    = 16
	cipherWLen    = 16
)

// CiphertextToBytes converts a ciphertext value to a set of bytes.
func CiphertextToBytes(ciphertext *ibe.Ciphertext) ([]byte, error) {
	kyberPoint, err := ciphertext.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	b := make([]byte, kyberPointLen+cipherVLen+cipherWLen)
	copy(b, kyberPoint)
	copy(b[kyberPointLen:], ciphertext.V)
	copy(b[kyberPointLen+cipherVLen:], ciphertext.W)

	return b, nil
}

// BytesToCiphertext converts bytes to a ciphertext.
func BytesToCiphertext(b []byte) (*ibe.Ciphertext, error) {
	expLen := kyberPointLen + cipherVLen + cipherWLen
	if len(b) != expLen {
		return nil, fmt.Errorf("incorrect length: exp: %d got: %d", expLen, len(b))
	}

	kyberPoint := make([]byte, kyberPointLen)
	copy(kyberPoint, b[:kyberPointLen])

	cipherV := make([]byte, cipherVLen)
	copy(cipherV, b[kyberPointLen:kyberPointLen+cipherVLen])

	cipherW := make([]byte, cipherVLen)
	copy(cipherW, b[kyberPointLen+cipherVLen:])

	var u bls.KyberG1
	if err := u.UnmarshalBinary(kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
	}

	ct := ibe.Ciphertext{
		U: &u,
		V: cipherV,
		W: cipherW,
	}

	return &ct, nil
}
