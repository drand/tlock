package tlock_test

import (
	"bytes"
	_ "embed" // Calls init function.
	"github.com/drand/drand/crypto"
	bls "github.com/drand/kyber-bls12381"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
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
	testnetHost          = "https://pl-us.testnet.drand.sh/"
	testnetChainHashOnG2 = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
	testnetQuicknetT     = "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5"
	mainnetHost          = "https://api.drand.sh/"
	mainnetFastnet       = "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
	mainnetQuicknet      = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

func TestEarlyDecryptionWithDuration(t *testing.T) {
	for host, hashes := range map[string][]string{testnetHost: {testnetChainHashOnG2, testnetQuicknetT},
		mainnetHost: {mainnetFastnet, mainnetQuicknet}} {
		for _, hash := range hashes {
			network, err := http.NewNetwork(host, hash)
			require.NoError(t, err)

			// =========================================================================
			// Encrypt

			// Read the plaintext data to be encrypted.
			in, err := os.Open("test_artifacts/data.txt")
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
	network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
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

	network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
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

func TestEncryptionWithRound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live testing in short mode")
	}

	network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
	require.NoError(t, err)

	// =========================================================================
	// Encrypt

	// Read the plaintext data to be encrypted.
	in, err := os.Open("test_artifacts/data.txt")
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
	network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
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
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDIgZGJkNTA2ZDZlZjc2ZTVm
Mzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0YzQ5
MwpzRXAvVVpBQXlDSjE1QUxDaUFnQ1E2cEd1elJXS0kzMkpsQnBxUFAzcHVvdWRT
a2w0OXJ0NC9rMmd0UHlVMTRxCkN3MERjVUJVUlloT2UrRjZsSE9lTFgwMkZNMjk3
UGpwNlBZL09WY3NoblhqMTVMbU9FeXV1MjlDcmJGQXU3SmgKcWxlbjFtaXBONWUz
eFpVQysxQWtjS1Z3SU9uRjJWaW8veUpkNEUyVHhQWQotLS0gN21xSHhranNqMEND
UG9qN2haU0FWdEpFK0pUZzUwWmVsVS9YRWdOaDRadwpeDBRfXZtLOC49GlI+Kozr
z6hgtLUPYvAimgekc+CeyJ8fb/0MVrpq/Ewnx1MpKig8nQ==
-----END AGE ENCRYPTED FILE-----`
	t.Run("With valid network", func(tt *testing.T) {
		network, err := http.NewNetwork(mainnetHost, mainnetFastnet)
		require.NoError(tt, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(tt, err)

		require.Equal(tt, "Hello drand World\n", plainData.String())
	})

	t.Run("With invalid network", func(tt *testing.T) {
		network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
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
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEgZGJkNTA2ZDZlZjc2ZTVm
Mzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0YzQ5
MwpvMTZVWGpocTM2Y0U0aExDY3B2SThMNEJhNzNLbXZ1T3dUR0x4L2QvMWdISTdk
cDBWbE9IeUhXYUxaalNEUUlSCkIxZHBJeG82RVVLekFMU1FtQ1VFbjhwZHNHMHRy
anlsZjJPTFZHelNYdFhwQXhPSEljbnY2SVp1ck1sZ3RybDIKTk1KOWhsSWZoOFEz
Z3MrWGNCc0F2NGY2L2k5dVJlZlFJeUhtU1AvMDZxdwotLS0gbEtQSXMzeVNZMmUw
RndkR1oyL0xFTkZILzl4Y3NBOU5EWXRGcDBObmZidwpiI9yHPl4yVTbeImtNOklv
Ds7/d2pdgkRooMJ58zoZd+AFXtAn2+7yGehvtkrWoSxgA8cf1aLuHFTAHho=
-----END AGE ENCRYPTED FILE-----`
		expected := "hello world and other things"
		network, err := http.NewNetwork(mainnetHost, mainnetFastnet)
		require.NoError(t, err)

		testReader := strings.NewReader(cipher)
		var plainData bytes.Buffer

		err = tlock.New(network).Decrypt(&plainData, testReader)
		require.NoError(t, err)

		require.Equal(t, expected, plainData.String())
	})

	t.Run("on Testnet with G2 sigs", func(t *testing.T) {
		cipher := `-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEgNzY3Mjc5N2Y1NDhmM2Y0
NzQ4YWM0YmYzMzUyZmM2YzZiNjQ2OGM5YWQ0MGFkNDU2YTM5NzU0NWM2ZTJkZjVi
ZgpnQUNaY1NzYm55Q0ZneEsrSVB4WFpvcGY5SEZrSG1XUFZRallneWNiZmtKTk1P
VUVUUDM2SU1wNGR1YktNTnBHClJOZkJ5VzZYYlZJVHhtK0tUWnBEa2poVXVxazdl
WDEwRTAxTXB4VkxDancKLS0tIENjeTd4N2VSeUh5Sk54eVFKTGRjQ3ZEQjZTRDA4
ZEFUb0ZyZS9aSHpyWVkKKwNyX6cuEEENAjic1ew7k8G6vyxDrY5NWFbAhkKy0IrN
jLK74v9Latit5qAD7Gu/zTIsQXMuCuUf7ma7
-----END AGE ENCRYPTED FILE-----`
		expected := "hello world and other things"
		network, err := http.NewNetwork(testnetHost, testnetChainHashOnG2)
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
