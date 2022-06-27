package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/drand/drand/client"
	dhttp "github.com/drand/drand/client/http"
	"github.com/drand/kyber"
	"github.com/drand/tlock/foundation/drnd"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	network := NewHTTPNetwork(flags.Network, flags.Chain)

	if flags.Duration != "" {
		duration, err := time.ParseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, out, in, network, duration, flags.Armor)
	}

	return drnd.EncryptWithRound(ctx, out, in, network, flags.Round, flags.Armor)
}

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	network := NewHTTPNetwork(flags.Network, flags.Chain)

	if err := drnd.Decrypt(ctx, out, in, network); err != nil {
		return err
	}

	return nil
}

// =============================================================================

// HTTPNetwork provides network and chain information.
type HTTPNetwork struct {
	host      string
	chainHash string
	client    client.Client
	publicKey kyber.Point
}

func NewHTTPNetwork(host string, chainHash string) *HTTPNetwork {
	return &HTTPNetwork{
		host:      host,
		chainHash: chainHash,
	}
}

func (n *HTTPNetwork) Client(ctx context.Context) (client.Client, error) {
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

func (n *HTTPNetwork) PublicKey(ctx context.Context) (kyber.Point, error) {
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

// Network returns the network being used.
func (n *HTTPNetwork) Host() string {
	return n.host
}

// ChainHash returns the chain hash for this network.
func (n *HTTPNetwork) ChainHash() string {
	return n.chainHash
}

// transport sets reasonable defaults for the connection.
func transport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
