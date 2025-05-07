package tlock_test

import (
	"bytes"
	_ "embed" // Calls init function.
	"encoding/hex"
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
	"github.com/drand/tlock/networks/fixed"
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
	mainnetEvm            = "04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3"
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
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}
	tests := []struct {
		name      string
		host      string
		chainhash string
	}{
		{
			"quicknetT",
			testnetHost,
			testnetQuicknetT,
		},
		{
			"quicknet",
			mainnetHost,
			mainnetQuicknet,
		},
		{
			"evmnet",
			mainnetHost,
			mainnetEvm,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := http.NewNetwork(tt.host, tt.chainhash)
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
		})
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
		network, err := fixed.FromInfo(`{"public_key":"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a","period":3,"genesis_time":1692803367,"genesis_seed":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","chain_hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","scheme":"bls-unchained-g1-rfc9380","beacon_id":"quicknet"}`)
		require.NoError(tt, err)
		sig, err := hex.DecodeString("929906c959032ab363c9f26570d215d66f5c06cb0c44fe508c12bb5839f04ec895bb6868e5b9ff13ab289bdb5266b394")
		require.NoError(tt, err)

		network.SetSignature(sig)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(tt, err)

		require.Equal(tt, "hello world", plainData.String())
	})

	t.Run("With invalid network", func(tt *testing.T) {
		network, err := fixed.FromInfo(`{"public_key":"07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b","period":3,"genesis_time":1727521075,"genesis_seed":"cd7ad2f0e0cce5d8c288f2dd016ffe7bc8dc88dbb229b3da2b6ad736490dfed6","chain_hash":"04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3","scheme":"bls-bn254-unchained-on-g1","beacon_id":"evmnet"}`)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Strict().Decrypt(&plainData, testReader)
		require.ErrorIs(tt, err, tlock.ErrWrongChainhash)
	})

	t.Run("With quicknet-t invalid network", func(tt *testing.T) {
		network, err := fixed.FromInfo(`{"public_key":"b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da","period":3,"genesis_time":1689232296,"genesis_seed":"40d49d910472d4adb1d67f65db8332f11b4284eecf05c05c5eacd5eef7d40e2d","chain_hash":"cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5","scheme":"bls-unchained-g1-rfc9380","beacon_id":"quicknet-t"}`)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Strict().Decrypt(&plainData, testReader)
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
