package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/drand/drand/v2/crypto"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/fixed"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	lvl := new(slog.LevelVar)
	lvl.Set(slog.LevelDebug)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))

	// Set the global logger if needed (depends on your use case)
	slog.SetDefault(logger)

	// Run tests
	code := m.Run()

	os.Exit(code) // Ensure proper exit after tests
}

func TestNewIdentity(t *testing.T) {
	t.Skip("require internet connectivity")
	name, data, err := page.ParseIdentity("AGE-PLUGIN-TLOCK-1Q9TXSAR5WPEN5TE0V9CXJTNYWFSKUEPWWD5Z7ERZVS6NQDNYXEJKVDEKV56KVVECXENRGVTRXC6NZERRVGURQWRRX43XXCNYXU6NGDE3VD3NGETPVESNXE35V3NRWCTYX3JNGCE58YEJ74QEJUM")
	slog.Info("ParseIdentity", "name", name, "data", data)
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, err := hex.DecodeString("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e")
	require.NoError(t, err)
	pk := new(bls.KyberG2)
	require.NoError(t, pk.UnmarshalBinary(pkb))
	network, err := fixed.NewNetwork("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493", pk, crypto.NewPedersenBLSUnchainedSwapped(), 0, 0, nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		data    []byte
		want    age.Identity
		wantErr bool
	}{
		{
			name:    "empty",
			data:    []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "valid-tlock-rs",
			data:    data,
			want:    tlock.NewIdentity(network, true),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewIdentity(nil)(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIdentity() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if fmt.Sprintf("%s", got) != fmt.Sprintf("%s", tt.want) {
				t.Errorf("NewIdentity() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRecipient(t *testing.T) {
	name, data, err := page.ParseRecipient("age1tlock1yrda2pkkaamwtuux7swx28wtszx9hj7h23cucn40506d77k5unzfxc9qhp32w5nlaca8xx7tty5q4d4t6ck4czmw5q7ufh0kvyhaljwsruqux92z2sthryp5wh43a3npt7xsmu9ckmww8pvpr4kulr97lwr4ne0xz63al5z5ey5fgpmxmxjmnku3uwmf0ewhp2t4rq0qqlu8ljj7lng8rlmrqvpvft27")
	slog.Info("ParseIdentity", "name", name, "data", data)
	t.Log(data)
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, _ := hex.DecodeString("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e")
	pk := new(bls.KyberG2)
	pk.UnmarshalBinary(pkb)
	network, err := fixed.NewNetwork("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493", pk, crypto.NewPedersenBLSUnchained(), 0, 0, nil)

	tests := []struct {
		name    string
		data    []byte
		want    *tlock.Recipient
		wantErr bool
	}{
		{
			"valid",
			data,
			tlock.NewRecipient(network, 3),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRecipient(nil)(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRecipient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if sgot := fmt.Sprintf("%v", got); sgot == "" || sgot != fmt.Sprintf("%v", tt.want) {
				t.Errorf("strings mismatch:\n%v !=\n%v", got, tt.want)
			}
		})
	}
}

func TestEncodeRecipient(t *testing.T) {
	name, wanted, err := page.ParseRecipient("age1tlock1ypfdhxa8pcxvpah277qrm5r5g7sl23mhxh7n7eshj2afgcqvsn5hzcyreu8j394daelt3d0srl9d8yfzztzr0cq886g3lwgqytf7wcqc8jxyk3gtdg9xcwkx54mk5tgsv3gs68lvwkxfy8xz9v8p0e364a9ukhkkvvzda88cpx7jwn988w454adxa8rk5j7qnemw46yerm67eez6lsnjrenyqvg8g67n")
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, _ := hex.DecodeString("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
	chainhash, _ := hex.DecodeString("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")

	if got := createRecipient(chainhash, pkb, 1692803367, 3, -1); !bytes.Equal(got, wanted) {
		t.Errorf("EncodeRecipient() = \t%v,\n\t\t\t\t\t\t\t want \t%v", got, wanted)
	}
}
