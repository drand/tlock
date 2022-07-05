// Package tlock provides an API for encrypting/decrypting data using
// drand time lock encryption. This allows data to be encrypted and only
// decrypted in the future.
package tlock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/drand/kyber"
)

// ErrTooEarly represents an error when a decryption operation happens early.
var ErrTooEarly = errors.New("too early to decrypt")

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	Host() string
	ChainHash() string
	PublicKey() (kyber.Point, error)
	IsReadyToDecrypt(roundNumber uint64) (id []byte, ready bool)
	RoundNumber(t time.Time) (uint64, error)
}

// =============================================================================

// Encrypter provides an API for time lock encryption.
type Encrypter struct {
	network Network
}

// NewEncrypter constructs a tlock Encrypter for the specified network which
// can encrypt data that can't be decrypted until the future.
func NewEncrypter(network Network) Encrypter {
	return Encrypter{
		network: network,
	}
}

// Encrypt will encrypt the source and write that to the destination. The encrypted
// data will not be decryptable until the specified round is reached by the network.
func (t Encrypter) Encrypt(dst io.Writer, src io.Reader, roundNumber uint64) error {
	w, err := age.Encrypt(dst, &tleRecipient{network: t.network, round: roundNumber})
	if err != nil {
		return fmt.Errorf("age encrypt: %w", err)
	}

	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// =============================================================================

// Decrypter provides an API for time lock decryption.
type Decrypter struct {
	network Network
}

// NewDecrypter constructs a tlock Decrypter for the specified network which
// can decrypt data that was encrypted by the Encrypter.
func NewDecrypter(network Network) Decrypter {
	return Decrypter{
		network: network,
	}
}

// Decrypt will decrypt the source and write that to the destination. The decrypted
// data will not be decryptable unless the specified round from the encrypt call
// is reached by the network.
func (t Decrypter) Decrypt(dst io.Writer, src io.Reader) error {
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
