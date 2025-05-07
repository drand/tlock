package tlock_test

import (
	"bytes"
	_ "embed" // Calls init function.
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	chain "github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata/data.txt
	dataFile []byte
	//go:embed testdata/lorem.txt
	loremBytes []byte
)

const (
	testnetHost           = "http://pl-us.testnet.drand.sh/"
	testnetUnchainedOnEVM = "ddb3665060932c267aacde99049ea31f3f5a049b1741c31cf71cd5d7d11a8da2"
	testnetQuicknetT      = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"
	mainnetHost           = "http://api.drand.sh/"
	mainnetQuicknet       = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

func TestEarlyDecryptionWithDuration(t *testing.T) {
	for host, hashes := range map[string][]string{testnetHost: {testnetUnchainedOnEVM, testnetQuicknetT},
		mainnetHost: {mainnetQuicknet}} {
		for _, hash := range hashes {
			network, err := http.NewNetwork(host, hash)
			require.NoError(t, err)

			// =========================================================================
			// Encrypt

			// Read the plaintext data to be encrypted.
			in, err := os.Open("testdata/data.txt")
			require.NoError(t, err)
			defer in.Close()

			// Write the encoded information to this buffer.
			var cipherData bytes.Buffer

			// Enough duration to check for a non-existent beacon.
			duration := 10 * time.Second

			roundNumber := network.RoundNumber(time.Now().Add(duration))
			err = tlock.New(network).Encrypt(&cipherData, in, roundNumber)
			require.NoError(t, err)

			// =========================================================================
			// Decrypt

			// Write the decoded information to this buffer.
			var plainData bytes.Buffer

			// We DO NOT wait for the future beacon to exist.
			err = tlock.New(network).Decrypt(&plainData, &cipherData)
			require.ErrorIs(t, err, tlock.ErrTooEarly)
		}
	}
}

func TestEarlyDecryptionWithRound(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("testdata/data.txt")
	require.NoError(t, err)
	defer in.Close()

	var cipherData bytes.Buffer
	futureRound := network.RoundNumber(time.Now().Add(1 * time.Minute))

	err = tlock.New(network).Encrypt(&cipherData, in, futureRound)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	// We DO NOT wait for the future beacon to exist.
	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.ErrorIs(t, err, tlock.ErrTooEarly)
}

func TestEncryptionWithDuration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("testdata/data.txt")
	require.NoError(t, err)
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	// Enough duration to check for a non-existent beacon.
	duration := 4 * time.Second

	roundNumber := network.RoundNumber(time.Now().Add(duration))
	err = tlock.New(network).Encrypt(&cipherData, in, roundNumber)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	time.Sleep(5 * time.Second)

	// Write the decoded information to this buffer.
	var plainData bytes.Buffer

	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.NoError(t, err)

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestDecryptVariousChainhashes(t *testing.T) {
	dir := "./testdata"
	prefix := "lorem-"

	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
	require.NoError(t, err)

	for _, file := range files {
		if strings.HasPrefix(file.Name(), prefix) {
			t.Run("Decrypt-"+file.Name(), func(ts *testing.T) {
				filePath := filepath.Join(dir, file.Name())
				cipherData, err := os.Open(filePath)
				require.NoError(ts, err)
				var plainData bytes.Buffer
				err = tlock.New(network).Decrypt(&plainData, cipherData)
				if errors.Is(err, tlock.ErrWrongChainhash) {
					require.Contains(ts, file.Name(), "timevault-mainnet-2024")
					return
				}

				require.NoError(ts, err)

				if !bytes.Equal(plainData.Bytes(), loremBytes) {
					ts.Fatalf("decrypted file is invalid; expected %d; got %d:\n %v \n %v", len(loremBytes), len(plainData.Bytes()), loremBytes, plainData.Bytes())
				}
			})
		}
	}
}

func TestDecryptStrict(t *testing.T) {
	dir := "./testdata"
	prefix := "lorem-"

	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
	require.NoError(t, err)

	for _, file := range files {
		if strings.Contains(file.Name(), "testnet-unchained-3s-2024") {
			continue
		}
		if strings.Contains(file.Name(), "timevault-testnet-2024") {
			continue
		}
		if strings.HasPrefix(file.Name(), prefix) {
			t.Run("DontDecryptStrict-"+file.Name(), func(ts *testing.T) {
				filePath := filepath.Join(dir, file.Name())
				cipherData, err := os.Open(filePath)
				require.NoError(ts, err)
				var plainData bytes.Buffer
				err = tlock.New(network).Strict().Decrypt(&plainData, cipherData)
				require.ErrorIs(ts, err, tlock.ErrWrongChainhash)
			})
		}
	}
}

func TestEncryptionWithRound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("testdata/data.txt")
	require.NoError(t, err)
	defer in.Close()

	// Write the encoded information to this buffer.
	var cipherData bytes.Buffer

	futureRound := network.RoundNumber(time.Now().Add(6 * time.Second))
	err = tlock.New(network).Encrypt(&cipherData, in, futureRound)
	require.NoError(t, err)

	// =========================================================================
	// Decrypt

	var plainData bytes.Buffer

	// Wait for the future beacon to exist.
	time.Sleep(10 * time.Second)

	err = tlock.New(network).Decrypt(&plainData, &cipherData)
	require.NoError(t, err)

	if !bytes.Equal(plainData.Bytes(), dataFile) {
		t.Fatalf("decrypted file is invalid; expected %d; got %d", len(dataFile), len(plainData.Bytes()))
	}
}

func TestTimeLockUnlock(t *testing.T) {
	network, err := http.NewNetwork(testnetHost, testnetQuicknetT)
	require.NoError(t, err)

	futureRound := network.RoundNumber(time.Now())

	id, err := network.Signature(futureRound)
	require.NoError(t, err)

	data := []byte(`anything`)

	cipherText, err := tlock.TimeLock(network.Scheme(), network.PublicKey(), futureRound, data)
	require.NoError(t, err)

	beacon := chain.Beacon{
		Round:     futureRound,
		Signature: id,
	}

	b, err := tlock.TimeUnlock(network.Scheme(), network.PublicKey(), beacon, cipherText)
	require.NoError(t, err)

	if !bytes.Equal(data, b) {
		t.Fatalf("unexpected bytes; expected len %d; got %d", len(data), len(b))
	}
}

func TestCannotEncryptWithPointAtInfinity(t *testing.T) {
	suite := bls.NewBLS12381Suite()
	t.Run("on G2", func(t *testing.T) {
		infinity := suite.G2().Scalar().Zero()
		pointAtInfinity := suite.G2().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchainedG1(), pointAtInfinity, 10, []byte("deadbeef"))
		require.ErrorIs(t, err, tlock.ErrInvalidPublicKey)
	})

	t.Run("on G1", func(t *testing.T) {
		infinity := suite.G1().Scalar().Zero()
		pointAtInfinity := suite.G1().Point().Mul(infinity, nil)

		_, err := tlock.TimeLock(*crypto.NewPedersenBLSUnchained(), pointAtInfinity, 10, []byte("deadbeef"))
		require.ErrorIs(t, err, tlock.ErrInvalidPublicKey)
	})

}

func TestDecryptText(t *testing.T) {
	cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEyMDQwODgzIDUyZGI5YmE3
MGUwY2MwZjZlYWY3ODAzZGQwNzQ0N2ExZjU0Nzc3MzVmZDNmNjYxNzkyYmE5NDYw
MGM4NGU5NzEKa1JjK01NSEUwS005b1V0SmNLTWZGb1JFVzBXN1JQbTNtdzZpVUJ1
cGNXVkZkZDJQb1h6U0JrK25TM01BNnBKNwpHZDl3REhmVU5hTldXTWw2cGVia2Jh
OUVNZGJDWnBuQVNtOWFIb3hqUitwaGFVT2xoS1ppZGl5ZHBLSStPS2N0CmxvT2ZP
SW9KaGtndTVTRnJUOGVVQTJUOGk3aTBwQlBzTDlTWUJUZEJQb28KLS0tIEl6Q1Js
WSt1RXp0d21CbEg0cTFVZGNJaW9pS2l0M0c0bHVxNlNjT2w3UUUKDI4cDlPHPgjy
UnBmtsw6U2LlKh8iDf0E1PfwDenmKFfQaAGm0WLxdlzP8Q==
-----END AGE ENCRYPTED FILE-----`
	t.Run("With valid network", func(tt *testing.T) {
		network, err := http.NewNetwork(mainnetHost, mainnetQuicknet)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(tt, err)

		require.Equal(tt, "hello world", plainData.String())
	})

	t.Run("With invalid network", func(tt *testing.T) {
		network, err := http.NewNetwork(testnetHost, testnetUnchainedOnEVM)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.ErrorIs(tt, err, tlock.ErrWrongChainhash)
	})

	t.Run("With quicknet-t invalid network", func(tt *testing.T) {
		network, err := http.NewNetwork(testnetHost, testnetQuicknetT)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.ErrorIs(tt, err, tlock.ErrWrongChainhash)
	})
}

func TestInteropWithJS(t *testing.T) {
	t.Run("on Mainnet with G1 sigs", func(t *testing.T) {
		cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEyMDQxMTI1IDUyZGI5YmE3
MGUwY2MwZjZlYWY3ODAzZGQwNzQ0N2ExZjU0Nzc3MzVmZDNmNjYxNzkyYmE5NDYw
MGM4NGU5NzEKbDNtWFdseFRIS0YxQi9HZGYyMzJ0cmkveDFWZk5zVDMwS002eExV
NXUwbFFqQVdNSFJmVHJYbnFJOWpHWWM4ZApETmVodVhaUm8zay9HVzVMVDNaN1M1
d3JVN0lvQVNQUy9xY3JjODNIWEplY25wTXVJS1ZTM3Fyc0NvZzJiZW1OCjVJQmRD
VDU4UUZGeVJ5QzRlRUFZU092NWl0b3E2UWw1RDh6WEtVdmdTTFkKLS0tIEk5c0th
Mi9yeEF2ZDFlL1paTFlIV2VZYkVZVjlreDFidE1wWm1rMU51QkUKxCgEsEjSEixh
4nEBtpolrubLO6WwhfWuh5ZFewjuXbSyrJGreivurDm+7y5stuDO6xPVRpcU+eSQ
RLrz
-----END AGE ENCRYPTED FILE-----`
		expected := "hello world and other things"
		network, err := http.NewNetwork(mainnetHost, mainnetQuicknet)
		require.NoError(t, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(t, err)

		require.Equal(t, expected, plainData.String())
	})

	t.Run("on testnet with quicknet-t", func(t *testing.T) {
		cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDE2MjQ5MTAgY2M5YzM5ODQ0
MjczN2NiZDE0MTUyNjYwMDkxOWVkZDY5ZjFkNmY5YjRhZGI2N2U0ZDkxMmZiYzY0
MzQxYTlhNQpqTTVLOEhWVUFrOFFkNStIL0ZQOHplRkZPSEs4T0pjVG1FNW9LSW1z
bytQRmRDM3lycEdtRGFtck9XMGVycDcxCkVuS1hqL216dmI3RThFMDZMWTNWZEh5
SWh3UFhWWFJlREZ5SHZiTWNPMDdNcWFLamV5MWRNMkMwTHR1SjNpWUoKeENEaEJQ
RDF3K3JjbEtNenI3QU5VVldWa3FmMHd0aGtxTmw3VEEwK0RjQQotLS0gUWFpL0U5
VDNsVkpZT3F2Mk14NWRIU3IzbnhuUUsyaTdsS0ptclNoNk9lOAqkjk0Ypkj6JxKk
5ZxeTXAsxRyy9yptL4yKgd2i/J7k/O3C0Te7yPwsdkUC
-----END AGE ENCRYPTED FILE-----`
		expected := "test today\n"
		network, err := http.NewNetwork(testnetHost, testnetQuicknetT)
		require.NoError(t, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(t, err)

		require.Equal(t, expected, plainData.String())
	})

}
