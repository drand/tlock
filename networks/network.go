// Package networks allows to represent and work with various tlock-compatible networks.
package networks

import (
	"time"

	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
)

// Network represents a system that provides support for encrypting/decrypting
// a DEK based on a future time.
type Network interface {
	ChainHash() string
	PublicKey() kyber.Point
	Scheme() crypto.Scheme
	Signature(roundNumber uint64) ([]byte, error)
	SwitchChainHash(string) error
	RoundNumber(time.Time) uint64
}
