// Package fixed implements the Network interface for the tlock package without actual networking.
package fixed

import (
	"errors"
	"time"

	chain "github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"

	"github.com/drand/kyber"
)

// Network represents the network support using the drand http client.
type Network struct {
	chainHash string
	publicKey kyber.Point
	scheme    *crypto.Scheme
	period    time.Duration
	genesis   int64
	fixedSig  []byte
}

// ErrNotUnchained represents an error when the informed chain belongs to a
// chained network.
var ErrNotUnchained = errors.New("not an unchained network")

// NewNetwork constructs a network with static, fixed data
func NewNetwork(chainHash string, publicKey kyber.Point, sch *crypto.Scheme, period time.Duration, genesis int64, sig []byte) (*Network, error) {
	switch sch.Name {
	case crypto.ShortSigSchemeID:
	case crypto.SigsOnG1ID:
	case crypto.UnchainedSchemeID:
	default:
		return nil, ErrNotUnchained
	}

	return &Network{
		chainHash: chainHash,
		publicKey: publicKey,
		scheme:    sch,
		period:    period,
		genesis:   genesis,
		fixedSig:  sig,
	}, nil
}

// ChainHash returns the chain hash for this network.
func (n *Network) ChainHash() string {
	return n.chainHash
}

// Current returns the current round for that network at the given date.
func (n *Network) Current(date time.Time) uint64 {
	return chain.CurrentRound(date.Unix(), n.period, n.genesis)
}

// PublicKey returns the kyber point needed for encryption and decryption.
func (n *Network) PublicKey() kyber.Point {
	return n.publicKey
}

// Scheme returns the drand crypto Scheme used by the network.
func (n *Network) Scheme() crypto.Scheme {
	return *n.scheme
}

// Signature only returns a fixed signature if set with the fixed network
func (n *Network) Signature(_ uint64) ([]byte, error) {
	return n.fixedSig, nil
}

// RoundNumber will return the latest round of randomness that is available
func (n *Network) RoundNumber(t time.Time) uint64 {
	// + 1 because round 1 happened at genesis time
	// integer division makes sure it ticks only every period
	return uint64(((t.Unix() - n.genesis) / int64(n.period.Seconds())) + 1)
}

// SwitchChainHash allows to start using another chainhash on the same host network
func (n *Network) SwitchChainHash(c string) error {
	n.chainHash = c
	return nil
}
