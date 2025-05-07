package tlock

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/drand/tlock/networks/http"
)

const (
	testnetHost      = "http://pl-us.testnet.drand.sh/"
	testnetChainHash = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"
)

func Test_WrapUnwrap(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}

	recipient := Recipient{
		roundNumber: network.RoundNumber(time.Now()),
		network:     network,
	}

	// 16 is the constant fileKeySize
	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatalf("rand read filekey: %s", err)
	}

	stanza, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatalf("wrap error %s", err)
	}

	identity := Identity{
		network: network,
	}

	b, err := identity.Unwrap(stanza)
	if err != nil {
		t.Fatalf("unwrap error %s", err)
	}

	if !bytes.Equal(b, fileKey) {
		t.Fatalf("decrypted filekey is invalid; expected %d; got %d", len(b), len(fileKey))
	}
}
