package fixed

import (
	"reflect"
	"testing"
	"time"

	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/stretchr/testify/require"
)

func TestFromInfo(t *testing.T) {
	tests := []struct {
		name       string
		jsonStr    string
		wantHash   string
		wantScheme string
		wantErr    error
	}{
		{
			name:       "default",
			jsonStr:    `{"public_key":"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31","period":30,"genesis_time":1595431050,"genesis_seed":"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a","chain_hash":"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce","scheme":"pedersen-bls-chained","beacon_id":"default"}`,
			wantHash:   "",
			wantScheme: "",
			wantErr:    ErrNotUnchained,
		}, {
			name:       "evmnet",
			jsonStr:    `{"public_key":"07e1d1d335df83fa98462005690372c643340060d205306a9aa8106b6bd0b3820557ec32c2ad488e4d4f6008f89a346f18492092ccc0d594610de2732c8b808f0095685ae3a85ba243747b1b2f426049010f6b73a0cf1d389351d5aaaa1047f6297d3a4f9749b33eb2d904c9d9ebf17224150ddd7abd7567a9bec6c74480ee0b","period":3,"genesis_time":1727521075,"genesis_seed":"cd7ad2f0e0cce5d8c288f2dd016ffe7bc8dc88dbb229b3da2b6ad736490dfed6","chain_hash":"04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3","scheme":"bls-bn254-unchained-on-g1","beacon_id":"evmnet"}`,
			wantHash:   "04f1e9062b8a81f848fded9c12306733282b2727ecced50032187751166ec8c3",
			wantScheme: "bls-bn254-unchained-on-g1",
			wantErr:    nil,
		}, {
			name:       "quicknet",
			jsonStr:    `{"public_key":"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a","period":3,"genesis_time":1692803367,"genesis_seed":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","chain_hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","scheme":"bls-unchained-g1-rfc9380","beacon_id":"quicknet"}`,
			wantHash:   "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
			wantScheme: "bls-unchained-g1-rfc9380",
			wantErr:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromInfo(tt.jsonStr)
			require.ErrorIs(t, err, tt.wantErr)
			if err == nil {
				if got.ChainHash() != tt.wantHash {
					t.Errorf("FromInfo() got = %v, want %v", got.ChainHash(), tt.wantHash)
				}
				if got.Scheme().Name != tt.wantScheme {
					t.Errorf("FromInfo() got = %v, want %v", got.ChainHash(), tt.wantHash)
				}
				require.Equal(t, uint64(1), got.RoundNumber(time.Unix(got.genesis, 0)))
			}
		})
	}
}

func TestNetwork_ChainHash(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns configured chain hash",
			fields: fields{
				chainHash: "test-chain-hash",
			},
			want: "test-chain-hash",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if got := n.ChainHash(); got != tt.want {
				t.Errorf("ChainHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_Current(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	type args struct {
		date time.Time
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   uint64
	}{
		{
			name: "at genesis is round 1",
			fields: fields{
				period:  30 * time.Second,
				genesis: 1_600_000_000,
			},
			args: args{
				date: time.Unix(1_600_000_000, 0),
			},
			want: 1,
		},
		{
			name: "one period after genesis is round 2",
			fields: fields{
				period:  30 * time.Second,
				genesis: 1_600_000_000,
			},
			args: args{
				date: time.Unix(1_600_000_000+30, 0),
			},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if got := n.Current(tt.args.date); got != tt.want {
				t.Errorf("Current() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_PublicKey(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}

	sch, err := crypto.SchemeFromName(crypto.UnchainedSchemeID)
	require.NoError(t, err)
	pub := sch.KeyGroup.Point()

	tests := []struct {
		name   string
		fields fields
		want   kyber.Point
	}{
		{
			name: "returns configured public key",
			fields: fields{
				publicKey: pub,
			},
			want: pub,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if got := n.PublicKey(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_RoundNumber(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	type args struct {
		t time.Time
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   uint64
	}{
		{
			name: "at genesis is round 1",
			fields: fields{
				period:  10 * time.Second,
				genesis: 1_700_000_000,
			},
			args: args{
				t: time.Unix(1_700_000_000, 0),
			},
			want: 1,
		},
		{
			name: "two periods after genesis is round 3",
			fields: fields{
				period:  10 * time.Second,
				genesis: 1_700_000_000,
			},
			args: args{
				t: time.Unix(1_700_000_000+2*10, 0),
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if got := n.RoundNumber(tt.args.t); got != tt.want {
				t.Errorf("RoundNumber() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_Scheme(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.Scheme
	}{
		{
			name: "returns scheme value copy",
			fields: fields{
				scheme: &crypto.Scheme{},
			},
			want: crypto.Scheme{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if got := n.Scheme(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Scheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_SetSignature(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	type args struct {
		sig []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name:   "sets fixed signature used by Signature",
			fields: fields{},
			args: args{
				sig: []byte{0x01, 0x02, 0x03},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			n.SetSignature(tt.args.sig)

			got, err := n.Signature(0)
			require.NoError(t, err)
			require.Equal(t, tt.args.sig, got)
		})
	}
}

func TestNetwork_Signature(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	type args struct {
		in0 uint64
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "no signature set returns nil without error",
			fields: fields{
				fixedSig: nil,
			},
			args: args{
				in0: 0,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "returns fixed signature without error",
			fields: fields{
				fixedSig: []byte{0xaa, 0xbb},
			},
			args: args{
				in0: 42,
			},
			want:    []byte{0xaa, 0xbb},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			got, err := n.Signature(tt.args.in0)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signature() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetwork_SwitchChainHash(t *testing.T) {
	type fields struct {
		chainHash string
		publicKey kyber.Point
		scheme    *crypto.Scheme
		period    time.Duration
		genesis   int64
		fixedSig  []byte
	}
	type args struct {
		c string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "updates chain hash without error",
			fields: fields{
				chainHash: "old-hash",
			},
			args: args{
				c: "new-hash",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Network{
				chainHash: tt.fields.chainHash,
				publicKey: tt.fields.publicKey,
				scheme:    tt.fields.scheme,
				period:    tt.fields.period,
				genesis:   tt.fields.genesis,
				fixedSig:  tt.fields.fixedSig,
			}
			if err := n.SwitchChainHash(tt.args.c); (err != nil) != tt.wantErr {
				t.Errorf("SwitchChainHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && n.ChainHash() != tt.args.c {
				t.Errorf("SwitchChainHash() chainHash = %v, want %v", n.ChainHash(), tt.args.c)
			}
		})
	}
}

func TestNewNetwork(t *testing.T) {
	type args struct {
		chainHash string
		publicKey kyber.Point
		sch       *crypto.Scheme
		period    time.Duration
		genesis   int64
		sig       []byte
	}
	supportedScheme, err := crypto.SchemeFromName(crypto.UnchainedSchemeID)
	require.NoError(t, err)

	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrType error
	}{
		{
			name: "supported scheme succeeds",
			args: args{
				chainHash: "some-chain",
				sch:       supportedScheme,
				period:    30 * time.Second,
				genesis:   1_600_000_000,
			},
			wantErr:     false,
			wantErrType: nil,
		},
		{
			name: "unsupported scheme returns ErrNotUnchained",
			args: args{
				chainHash: "some-chain",
				sch: &crypto.Scheme{
					Name: "unsupported-scheme",
				},
				period:  30 * time.Second,
				genesis: 1_600_000_000,
			},
			wantErr:     true,
			wantErrType: ErrNotUnchained,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewNetwork(tt.args.chainHash, tt.args.publicKey, tt.args.sch, tt.args.period, tt.args.genesis, tt.args.sig)
			if tt.wantErr {
				require.ErrorIs(t, err, tt.wantErrType)
				require.Nil(t, got)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.args.chainHash, got.ChainHash())
			require.Equal(t, tt.args.period, got.period)
			require.Equal(t, tt.args.genesis, got.genesis)
		})
	}
}
