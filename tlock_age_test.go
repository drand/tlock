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
	testnetChainHash = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
)

func Test_WrapUnwrap(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}

	latestRound, err := network.RoundNumber(time.Now())
	if err != nil {
		t.Fatalf("client: %s", err)
	}

	recipient := tleRecipient{
		round:   latestRound,
		network: network,
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

	identity := tleIdentity{
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
