// Package fixed implements the Network interface for the tlock package without actual networking.
package fixed

import (
	"encoding/json"
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
	case crypto.BN254UnchainedOnG1SchemeID:
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

type infoV2 struct {
	PublicKey   chain.HexBytes `json:"public_key"`
	ID          string         `json:"beacon_id,beaconID"`
	Period      int64          `json:"period"`
	Scheme      string         `json:"scheme"`
	GenesisTime int64          `json:"genesis_time"`
	ChainHash   string         `json:"chain_hash,hash"`
}

func FromInfo(jsonInfo string) (*Network, error) {
	info := new(infoV2)
	err := json.Unmarshal([]byte(jsonInfo), info)
	if err != nil {
		return nil, err
	}
	sch, err := crypto.SchemeFromName(info.Scheme)
	if err != nil {
		return nil, err
	}
	public := sch.KeyGroup.Point()
	if err := public.UnmarshalBinary(info.PublicKey); err != nil {
		return nil, err
	}
	return NewNetwork(info.ChainHash, public, sch, time.Duration(info.Period)*time.Second, info.GenesisTime, nil)
}

func (n *Network) SetSignature(sig []byte) {
	n.fixedSig = sig
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
