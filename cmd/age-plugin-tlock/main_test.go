package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/drand/drand/crypto"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/fixed"
	"github.com/stretchr/testify/require"
)

func TestNewIdentity(t *testing.T) {
	name, data, err := page.ParseIdentity("AGE-PLUGIN-TLOCK-1Q9TXSAR5WPEN5TE0V9CXJTNYWFSKUEPWWD5Z7ERZVS6NQDNYXEJKVDEKV56KVVECXENRGVTRXC6NZERRVGURQWRRX43XXCNYXU6NGDE3VD3NGETPVESNXE35V3NRWCTYX3JNGCE58YEJ74QEJUM")
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, _ := hex.DecodeString("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e")
	pk := new(bls.KyberG2)
	pk.UnmarshalBinary(pkb)
	network, err := fixed.NewNetwork("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493", pk, crypto.NewPedersenBLSUnchainedSwapped(), 0, 0, nil)

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
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, _ := hex.DecodeString("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e")
	pk := new(bls.KyberG2)
	pk.UnmarshalBinary(pkb)
	network, err := fixed.NewNetwork("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493", pk, crypto.NewPedersenBLSUnchainedSwapped(), 0, 0, nil)

	tests := []struct {
		name    string
		data    []byte
		want    age.Recipient
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRecipient() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeRecipient(t *testing.T) {
	name, wanted, err := page.ParseRecipient("age1tlock1yrda2pkkaamwtuux7swx28wtszx9hj7h23cucn40506d77k5unzfxc9qhp32w5nlaca8xx7tty5q4d4t6ck4czmw5q7ufh0kvyhaljwsruqux92z2sthryp5wh43a3npt7xsmu9ckmww8pvpr4kulr97lwr4ne0xz63al5z5ey5fgpmxmxjmnku3uwmf0ewhp2t4rq0qqlu8ljj7lng8rlmrqvpvft27")
	require.NoError(t, err)
	require.Equal(t, "tlock", name)

	pkb, _ := hex.DecodeString("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e")
	chainhash, _ := hex.DecodeString("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493")

	if got := createRecipient(chainhash, pkb, 1677685200, 3, -1); !bytes.Equal(got, wanted) {
		t.Errorf("EncodeRecipient() = %v, want %v", got, wanted)
	}
}

func Test_intEncode(t *testing.T) {
	tests := []struct {
		input int64
		want  []byte
	}{
		{1677685200, []byte{252, 208, 113, 255, 99}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("test-%d", tt.input), func(t *testing.T) {
			if got := intEncode(tt.input); !bytes.Equal(got, tt.want) {
				t.Errorf("intEncode() = %v, want %v", got, tt.want)
			}
		})
	}
}
