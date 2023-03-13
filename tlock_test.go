package tlock_test

import (
	"bytes"
	_ "embed" // Calls init function.
	"errors"
	"github.com/drand/drand/crypto"
	bls "github.com/drand/kyber-bls12381"
	"os"
	"testing"
	"time"

	"github.com/drand/drand/chain"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

var (
	//go:embed test_artifacts/data.txt
	dataFile []byte
)

const (
	testnetHost      = "https://pl-us.testnet.drand.sh/"
	testnetChainHash = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
	mainnetHost      = "https://api.drand.sh/"
	mainnetChainHash = "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
)

func TestEarlyDecryptionWithDuration(t *testing.T) {
	for host, hash := range map[string]string{testnetHost: testnetChainHash, mainnetHost: mainnetChainHash} {
		network, err := http.NewNetwork(host, hash)
		if err != nil {
			t.Fatalf("network error %s", err)
		}

		// =========================================================================
		// Encrypt

		// Read the plaintext data to be encrypted.
		in, err := os.Open("test_artifacts/data.txt")
		if err != nil {
			t.Fatalf("reader error %s", err)
		}
		defer in.Close()

		// Write the encoded information to this buffer.
		var cipherData bytes.Buffer

		// Enough duration to check for a non-existing beacon.
		duration := 10 * time.Second

		roundNumber := network.RoundNumber(time.Now().Add(duration))
		if err := tlock.New(network).Encrypt(&cipherData, in, roundNumber); err != nil {
			t.Fatalf("encrypt with duration error %s", err)
		}

		// =========================================================================
		// Decrypt

		// Write the decoded information to this buffer.
		var plainData bytes.Buffer

		// We DO NOT wait for the future beacon to exist.
		err = tlock.New(network).Decrypt(&plainData, &cipherData)
		if err == nil {
			t.Fatal("expecting decrypt error")
		}

		if !errors.Is(err, tlock.ErrTooEarly) {
			t.Fatalf("expecting decrypt error to contain '%s'; got %s", tlock.ErrTooEarly, err)
		}
	}
}

func TestEarlyDecryptionWithRound(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}
	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer in.Close()

	var cipherData bytes.Buffer
	futureRound := network.RoundNumber(time.Now().Add(1 * time.Minute))

	if err := tlock.New(network).Encrypt(&cipherData, in, futureRound); err != nil {
		t.Fatalf("encrypt with round error %s", err)
	}

	// =========================================================================
	// Decrypt

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	if err == nil {
		t.Fatal("expecting decrypt error")
	}

	if !errors.Is(err, tlock.ErrTooEarly) {
		t.Fatalf("expecting decrypt error to contain '%s'; got %s", tlock.ErrTooEarly, err)
	}
}

func TestEncryptionWithDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	// Enough duration to check for a non-existing beacon.
	duration := 4 * time.Second

	roundNumber := network.RoundNumber(time.Now().Add(duration))
	if err := tlock.New(network).Encrypt(&cipherData, in, roundNumber); err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	// =========================================================================
	// Decrypt

	time.Sleep(5 * time.Second)

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	if err := tlock.New(network).Decrypt(&plainData, &cipherData); err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestEncryptionWithRound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	futureRound := network.RoundNumber(time.Now().Add(6 * time.Second))
	if err := tlock.New(network).Encrypt(&cipherData, in, futureRound); err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	// =========================================================================
	// Decrypt

	var plainData bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(10 * time.Second)

	if err := tlock.New(network).Decrypt(&plainData, &cipherData); err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestTimeLockUnlock(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetChainHash)
	if err != nil {
		t.Fatalf("network error %s", err)
	}

	futureRound := network.RoundNumber(time.Now())

	id, err := network.Signature(futureRound)
	if err != nil {
		t.Fatalf("ready to decrypt error %s", err)
	}

	data := []byte(`anything`)

	cipherText, err := tlock.TimeLock(network.Scheme(), network.PublicKey(), futureRound, data)
	if err != nil {
		t.Fatalf("timelock error %s", err)
	}

	beacon := chain.Beacon{
		Round:     futureRound,
		Signature: id,
	}

	b, err := tlock.TimeUnlock(network.Scheme(), network.PublicKey(), beacon, cipherText)
	if err != nil {
		t.Fatalf("timeunlock error %s", err)
	}

	if !bytes.Equal(data, b) {
		t.Fatalf("unexpected bytes; expected len %d; got %d", len(data), len(b))
	}
}

func TestCannotEncryptWithPointAtInfinity(t *testing.T) {
	suite := bls.NewBLS12381Suite()
	t.Run("on G2", func(t *testing.T) {
		infinity := suite.G2().Scalar().Zero()
		pointAtInfinity := suite.G2().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchainedSwapped(), pointAtInfinity, 10, []byte("deadbeef"))

		if err != tlock.ErrInvalidPublicKey {
			t.Fatalf("expected error when encrypting with point at infinity")
		}
	})

	t.Run("on G1", func(t *testing.T) {
		infinity := suite.G1().Scalar().Zero()
		pointAtInfinity := suite.G1().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchained(), pointAtInfinity, 10, []byte("deadbeef"))

		if err != tlock.ErrInvalidPublicKey {
			t.Fatalf("expected error when encrypting with point at infinity")
		}
	})

}
