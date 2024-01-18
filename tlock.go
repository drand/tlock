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
	"github.com/drand/drand/chain"
	"github.com/drand/drand/crypto"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"gopkg.in/yaml.v3"
)

// ErrTooEarly represents an error when a decryption operation happens early.
var ErrTooEarly = errors.New("too early to decrypt")
var ErrInvalidPublicKey = errors.New("the public key received from the network to encrypt this was infinity and thus insecure")

// =============================================================================

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	ChainHash() string
	Current(time.Time) uint64
	PublicKey() kyber.Point
	Scheme() crypto.Scheme
	Signature(roundNumber uint64) ([]byte, error)
	SwitchChainHash(string) error
}

// =============================================================================

// Tlock provides an API for time lock encryption and decryption.
type Tlock struct {
	network        Network
	trustChainhash bool
}

// New constructs a tlock for the specified network which can encrypt data that
// can be decrypted until the future. By default a new network will trust the
// chainhash it sees in ciphertexts and try and use these unless Strict was
// called to prevent it.
func New(network Network) Tlock {
	return Tlock{
		network:        network,
		trustChainhash: true,
	}
}

func (t Tlock) Strict() Tlock {
	t.trustChainhash = false
	return t
}

// Encrypt will encrypt the source and write that to the destination. The encrypted
// data will not be decryptable until the specified round is reached by the network.
func (t Tlock) Encrypt(dst io.Writer, src io.Reader, roundNumber uint64) (err error) {
	w, err := age.Encrypt(dst, &tleRecipient{network: t.network, roundNumber: roundNumber})
	if err != nil {
		return fmt.Errorf("hybrid encrypt: %w", err)
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

	r, err := age.Decrypt(src, &tleIdentity{network: t.network, trustChainhash: t.trustChainhash})
	if err != nil {
		return fmt.Errorf("hybrid decrypt: %w", err)
	}

	if _, err := io.Copy(dst, r); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

// Metadata will return details about the drand network
func (t Tlock) Metadata(dst io.Writer) (err error) {
	type Metadata struct {
		ChainHash string `yaml:"chain_hash"`
		Current   uint64 `yaml:"current"`
		PublicKey string `yaml:"public_key"`
		Scheme    string `yaml:"scheme"`
	}
	scheme := t.network.Scheme()
	metadata := Metadata{
		ChainHash: t.network.ChainHash(),
		Current:   t.network.Current(time.Now()),
		PublicKey: t.network.PublicKey().String(),
		Scheme:    scheme.String(),
	}
	metadataBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("error marshalling metadata: %w", err)
	}
	if _, err := dst.Write(metadataBytes); err != nil {
		return fmt.Errorf("error writing metadata: %w", err)
	}
	return nil
}

// =============================================================================

// TimeLock encrypts the specified data for the given round number. The data
// can't be decrypted until the specified round is reached by the network in use.
func TimeLock(scheme crypto.Scheme, publicKey kyber.Point, roundNumber uint64, data []byte) (*ibe.Ciphertext, error) {
	if publicKey.Equal(publicKey.Null()) {
		return nil, ErrInvalidPublicKey
	}

	id := scheme.DigestBeacon(&chain.Beacon{
		Round: roundNumber,
	})

	var cipherText *ibe.Ciphertext
	var err error
	switch scheme.Name {
	case crypto.ShortSigSchemeID:
		// the ShortSigSchemeID uses the wrong DST for G1, so we keep it for retro-compatibility
		cipherText, err = ibe.EncryptCCAonG2(bls.NewBLS12381SuiteWithDST(bls.DefaultDomainG2(), bls.DefaultDomainG2()), publicKey, id, data)
	case crypto.UnchainedSchemeID:
		cipherText, err = ibe.EncryptCCAonG1(bls.NewBLS12381Suite(), publicKey, id, data)
	case crypto.SigsOnG1ID:
		cipherText, err = ibe.EncryptCCAonG2(bls.NewBLS12381Suite(), publicKey, id, data)
	default:
		return nil, fmt.Errorf("unsupported drand scheme '%s'", scheme.Name)
	}

	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	return cipherText, nil
}

// TimeUnlock decrypts the specified ciphertext for the given beacon. The
// ciphertext can't be decrypted until the specified round is reached by the network in use.
func TimeUnlock(scheme crypto.Scheme, publicKey kyber.Point, beacon chain.Beacon, ciphertext *ibe.Ciphertext) ([]byte, error) {
	if err := scheme.VerifyBeacon(&beacon, publicKey); err != nil {
		return nil, fmt.Errorf("verify beacon: %w", err)
	}

	var data []byte
	var err error
	switch scheme.Name {
	case crypto.ShortSigSchemeID:
		var signature bls.KyberG1
		if err := signature.UnmarshalBinary(beacon.Signature); err != nil {
			return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
		}
		// the ShortSigSchemeID uses the wrong DST for G1, so we keep it for retro-compatibility
		data, err = ibe.DecryptCCAonG2(bls.NewBLS12381SuiteWithDST(bls.DefaultDomainG2(), bls.DefaultDomainG2()), &signature, ciphertext)
	case crypto.UnchainedSchemeID:
		var signature bls.KyberG2
		if err := signature.UnmarshalBinary(beacon.Signature); err != nil {
			return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
		}
		data, err = ibe.DecryptCCAonG1(bls.NewBLS12381Suite(), &signature, ciphertext)
	case crypto.SigsOnG1ID:
		var signature bls.KyberG1
		if err := signature.UnmarshalBinary(beacon.Signature); err != nil {
			return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
		}
		data, err = ibe.DecryptCCAonG2(bls.NewBLS12381Suite(), &signature, ciphertext)
	default:
		return nil, fmt.Errorf("unsupported drand scheme '%s'", scheme.Name)
	}

	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}

	return data, nil
}

// =============================================================================

// These constants define the size of the different CipherDEK fields.
const (
	cipherVLen = 16
	cipherWLen = 16
)

// CiphertextToBytes converts a ciphertext value to a set of bytes.
func CiphertextToBytes(scheme crypto.Scheme, ciphertext *ibe.Ciphertext) ([]byte, error) {
	kyberPoint, err := ciphertext.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal kyber point: %w", err)
	}

	kyberPointLen := ciphertext.U.MarshalSize()
	if kyberPointLen != scheme.KeyGroup.PointLen() {
		return nil, fmt.Errorf("unsupported type (MarshalSize %d) for U: %T", kyberPointLen, ciphertext.U)
	}

	b := make([]byte, kyberPointLen+cipherVLen+cipherWLen)
	copy(b, kyberPoint)
	copy(b[kyberPointLen:], ciphertext.V)
	copy(b[kyberPointLen+cipherVLen:], ciphertext.W)

	return b, nil
}

// BytesToCiphertext converts bytes to a ciphertext.
func BytesToCiphertext(scheme crypto.Scheme, b []byte) (*ibe.Ciphertext, error) {
	kyberPointLen := scheme.KeyGroup.PointLen()
	if tot := kyberPointLen + cipherVLen + cipherWLen; len(b) != tot {
		return nil, fmt.Errorf("incorrect length: exp: %d got: %d", tot, len(b))
	}

	kyberPoint := make([]byte, kyberPointLen)
	copy(kyberPoint, b[:kyberPointLen])

	cipherV := make([]byte, cipherVLen)
	copy(cipherV, b[kyberPointLen:kyberPointLen+cipherVLen])

	cipherW := make([]byte, cipherVLen)
	copy(cipherW, b[kyberPointLen+cipherVLen:])

	u := scheme.KeyGroup.Point()
	if err := u.UnmarshalBinary(kyberPoint); err != nil {
		return nil, fmt.Errorf("unmarshal kyber point (type %T): %w", scheme.KeyGroup, err)
	}

	ct := ibe.Ciphertext{
		U: u,
		V: cipherV,
		W: cipherW,
	}

	return &ct, nil
}
