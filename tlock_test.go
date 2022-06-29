package tlock_test

import (
	"bytes"
	"context"
	_ "embed" // Calls init function.
	"os"
	"strings"
	"testing"
	"time"

	"github.com/drand/tlock"
	"github.com/drand/tlock/encrypters/aead"
	"github.com/drand/tlock/networks/http"
)

var (
	//go:embed test_artifacts/decryptedFile.bin
	decryptedFile []byte

	//go:embed test_artifacts/encryptedFile.bin
	encryptedFile []byte

	//go:embed test_artifacts/data.txt
	dataFile []byte
)

const (
	testnetHost      = "http://pl-us.testnet.drand.sh/"
	testnetChainHash = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
)

func Test_EarlyDecryptionWithDuration(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	// Enough duration to check for an non-existing beacon.
	duration := 10 * time.Second

	var encryptedBuffer bytes.Buffer
	err = tlock.EncryptWithDuration(context.Background(), &encryptedBuffer, reader, network, aead, duration, false)
	if err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	var decryptedBuffer bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = tlock.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err == nil {
		t.Fatal("expecting decrypt error")
	}

	if !strings.Contains(err.Error(), tlock.ErrTooEarly) {
		t.Fatalf("expecting decrypt error to contain '%s'; got %s", tlock.ErrTooEarly, err)
	}
}

func Test_EarlyDecryptionWithRound(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	client, err := network.Client(context.Background())
	if err != nil {
		t.Fatalf("client error :%s", err)
	}

	futureRound := client.RoundAt(time.Now().Add(1 * time.Minute))

	var encryptedBuffer bytes.Buffer
	err = tlock.EncryptWithRound(context.Background(), &encryptedBuffer, reader, network, aead, futureRound, false)
	if err != nil {
		t.Fatalf("encrypt with round error %s", err)
	}

	//==========================================================================
	// The encrypted buffer was written. We need to decrypt to make sure it worked.
	var decryptedBuffer bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = tlock.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err == nil {
		t.Fatal("expecting decrypt error")
	}

	if !strings.Contains(err.Error(), tlock.ErrTooEarly) {
		t.Fatalf("expecting decrypt error to contain '%s'; got %s", tlock.ErrTooEarly, err)
	}
}

func Test_EncryptionWithDuration(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	// This is the testnetwork period.
	duration := 3 * time.Second

	var encryptedBuffer bytes.Buffer
	err = tlock.EncryptWithDuration(context.Background(), &encryptedBuffer, reader, network, aead, duration, false)
	if err != nil {
		t.Fatalf("encrypt with duration error %s", err)
	}

	//==========================================================================
	// The encrypted buffer was written. We need to decrypt to make sure it worked.
	var decryptedBuffer bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(4 * time.Second)

	err = tlock.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err != nil {
		t.Fatalf("decrypt error %s", err)
	}

	if !bytes.Equal(decryptedBuffer.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(decryptedBuffer.Bytes()))
	}
}

func Test_EncryptionWithRound(t *testing.T) {
	network := http.New(testnetHost, testnetChainHash)

	// read the data to be encrypted.
	reader, err := os.Open("test_artifacts/data.txt")
	if err != nil {
		t.Fatalf("reader error %s", err)
	}
	defer reader.Close()

	var aead aead.AEAD

	client, err := network.Client(context.Background())
	if err != nil {
		t.Fatalf("client error :%s", err)
	}

	futureRound := client.RoundAt(time.Now().Add(6 * time.Second))

	var encryptedBuffer bytes.Buffer
	err = tlock.EncryptWithRound(context.Background(), &encryptedBuffer, reader, network, aead, futureRound, false)
	if err != nil {
		t.Fatalf("encrypt with round error %s", err)
	}

	//==========================================================================
	// The encrypted buffer was written. We need to decrypt to make sure it worked.
	var decryptedBuffer bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(10 * time.Second)

	err = tlock.Decrypt(context.Background(), &decryptedBuffer, &encryptedBuffer, network, aead)
	if err != nil {
		t.Fatalf("decrypt error: %s", err)
	}

	if !bytes.Equal(decryptedBuffer.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(decryptedBuffer.Bytes()))
	}
}
