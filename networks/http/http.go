// Package http implements the Network interface for the tlock package.
package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
)

// Network represents the network support using the drand http client.
type Network struct {
	host      string
	chainHash string
	client    client.Client
	publicKey kyber.Point
}

// NewNetwork constructs a network for use that will use the http client.
func NewNetwork(host string, chainHash string) *Network {
	return &Network{
		host:      host,
		chainHash: chainHash,
	}
}

// Host returns the host network information.
func (n *Network) Host() string {
	return n.host
}

// ChainHash returns the chain hash for this network.
func (n *Network) ChainHash() string {
	return n.chainHash
}

// PairingSuite returns the pairing suite to use.
func (*Network) PairingSuite() pairing.Suite {
	return bls.NewBLS12381Suite()
}

// Client returns an HTTP client used to talk to the network.
func (n *Network) Client(ctx context.Context) (client.Client, error) {
	if n.client != nil {
		return n.client, nil
	}

	hash, err := hex.DecodeString(n.chainHash)
	if err != nil {
		return nil, fmt.Errorf("decoding chain hash: %w", err)
	}

	client, err := dhttp.New(n.host, hash, transport())
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	n.client = client
	return client, nil
}

// PublicKey returns the kyber point needed for encryption and decryption.
func (n *Network) PublicKey(ctx context.Context) (kyber.Point, error) {
	if n.publicKey != nil {
		return n.publicKey, nil
	}

	if n.client == nil {
		n.Client(ctx)
	}

	chain, err := n.client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting client information: %w", err)
	}

	n.publicKey = chain.PublicKey
	return chain.PublicKey, nil

}

// IsReadyToDecrypt makes a call to the network to validate it's time to decrypt
// and if so, the required id is returned.
func (n *Network) IsReadyToDecrypt(ctx context.Context, roundNumber uint64) ([]byte, bool) {
	client, err := n.Client(ctx)
	if err != nil {
		return nil, false
	}

	result, err := client.Get(ctx, roundNumber)
	if err != nil {
		return nil, false
	}

	return result.Signature(), true
}

// CalculateEncryptionID will generate the id required for encryption.
func (*Network) CalculateEncryptionID(roundNumber uint64) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(chain.RoundToBytes(roundNumber)); err != nil {
		return nil, fmt.Errorf("sha256 write: %w", err)
	}

	return h.Sum(nil), nil
}

// GetEncryptionRoundAndID will generate the round information based on the
// specified duration.
func (n *Network) GetEncryptionRoundAndID(ctx context.Context, duration time.Duration) (uint64, []byte, error) {
	client, err := n.Client(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("client: %w", err)
	}

	roundNumber := client.RoundAt(time.Now().Add(duration))

	id, err := n.CalculateEncryptionID(roundNumber)
	if err != nil {
		return 0, nil, fmt.Errorf("id: %w", err)
	}

	return roundNumber, id, nil
}

// =============================================================================

// transport sets reasonable defaults for the connection.
func transport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
