// Package http implements the Network interface for the tlock package.
package http

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/common/chain"
	"github.com/drand/drand/v2/crypto"

	dhttp "github.com/drand/go-clients/client/http"
	dclient "github.com/drand/go-clients/drand"
	"github.com/drand/kyber"
)

// timeout represents the maximum amount of time to wait for network operations.
const timeout = 15 * time.Second

// ErrNotUnchained represents an error when the informed chain belongs to a
// chained network.
var ErrNotUnchained = errors.New("not an unchained network")

// Network represents the network support using the drand http client.
type Network struct {
	chainHash string
	host      string
	client    dclient.Client
	publicKey kyber.Point
	scheme    crypto.Scheme
	period    time.Duration
	genesis   int64
}

func NewFromJson(jsonStr string) (*Network, error) {
	info, err := chain.InfoFromJSON(bytes.NewBufferString(jsonStr))
	if err != nil {
		return nil, fmt.Errorf("NFJ1: Unmarshal json error: %w on %q", err, jsonStr)
	}
	//var info *chain.Info
	err = json.Unmarshal([]byte(jsonStr), info)
	if err != nil {
		return nil, fmt.Errorf("NFJ2: Unmarshal json error: %w on %q", err, jsonStr)
	}

	client, err := dhttp.NewWithInfo(nil, "", info, transport())
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	sch, err := crypto.SchemeFromName(info.Scheme)
	if err != nil {
		return nil, ErrNotUnchained
	}
	network := Network{
		chainHash: info.HashString(),
		host:      "",
		client:    client,
		publicKey: info.PublicKey,
		scheme:    *sch,
		period:    info.Period,
		genesis:   info.GenesisTime,
	}

	return &network, nil

}

// NewNetwork constructs a network for use that will use the http client.
func NewNetwork(host string, chainHash string) (*Network, error) {
	if !strings.HasPrefix(host, "http") {
		host = "https://" + host
	}
	_, err := url.Parse(host + "/" + chainHash)
	if err != nil {
		log.Fatal(err)
	}

	hash, err := hex.DecodeString(chainHash)
	if err != nil {
		return nil, fmt.Errorf("decoding chain hash: %w", err)
	}

	client, err := dhttp.New(context.Background(), nil, host, hash, transport())
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	info, err := client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting client information: %w", err)
	}

	if info.HashString() != chainHash {
		return nil, fmt.Errorf("chain hash mistmatch: (requested) %s!=%s (received)", chainHash, info.HashString())
	}

	sch, err := crypto.SchemeFromName(info.Scheme)
	if err != nil {
		return nil, ErrNotUnchained
	}

	switch sch.Name {
	case crypto.ShortSigSchemeID:
	case crypto.SigsOnG1ID:
	case crypto.UnchainedSchemeID:
	case crypto.BN254UnchainedOnG1SchemeID:
	default:
		return nil, ErrNotUnchained
	}

	network := Network{
		chainHash: chainHash,
		host:      host,
		client:    client,
		publicKey: info.PublicKey,
		scheme:    *sch,
		period:    info.Period,
		genesis:   info.GenesisTime,
	}

	return &network, nil
}

// ChainHash returns the chain hash for this network.
func (n *Network) ChainHash() string {
	return n.chainHash
}

// Current returns the current round for that network at the given date.
func (n *Network) Current(date time.Time) uint64 {
	return common.CurrentRound(date.Unix(), n.period, n.genesis)
}

// PublicKey returns the kyber point needed for encryption and decryption.
func (n *Network) PublicKey() kyber.Point {
	return n.publicKey
}

// Scheme returns the drand crypto Scheme used by the network.
func (n *Network) Scheme() crypto.Scheme {
	return n.scheme
}

// Signature makes a call to the network to retrieve the signature for the
// specified round number.
func (n *Network) Signature(roundNumber uint64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := n.client.Get(ctx, roundNumber)
	if err != nil {
		return nil, err
	}

	return result.GetSignature(), nil
}

// RoundNumber will return the latest round of randomness that is available
// for the specified time. To handle a duration construct time like this:
// time.Now().Add(6*time.Second)
func (n *Network) RoundNumber(t time.Time) uint64 {
	return n.client.RoundAt(t)
}

// SwitchChainHash allows to start using another chainHash on the same host network
func (n *Network) SwitchChainHash(new string) error {
	test, err := NewNetwork(n.host, new)
	if err != nil {
		return err
	}
	*n = *test
	return nil
}

// transport sets reasonable defaults for the connection.
func transport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
	}
}
