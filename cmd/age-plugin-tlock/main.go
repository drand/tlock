package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/tlock"
	"github.com/drand/tlock/cmd/tle/commands"
	"github.com/drand/tlock/networks/fixed"
	"github.com/drand/tlock/networks/http"
)

// using quicknet by default
var (
	DefaultChainhash       = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	DefaultPK              = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
	DefaultPeriod          = 3
	DefaultGenesis   int64 = 1692803367
	DefaultRemote          = "http://api.drand.sh/"
)

func main() {
	// we set up the flags we need
	fs := flag.NewFlagSet("age-plugin-tlock", flag.ExitOnError)
	isKeyGen := fs.Bool("keygen", false, "Generate a test keypair")

	//chainHash := fs.String("chainhash", DefaultChainhash, "The chainhash you want to encrypt towards. Default to the 'quicknet' one")
	//remote := fs.String("remote", DefaultRemote, "The remote endpoint you want to use for getting data. Default to 'https://api.drand.sh'. If using a chainhash, https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971 will override the default one as well")

	p, err := page.New("tlock")
	if err != nil {
		slog.Error("error creating plugin", "err", err)
		return
	}

	p.HandleRecipient(NewRecipient(p))
	p.HandleIdentity(NewIdentity(p))
	// we let age register its required flags
	p.RegisterFlags(fs)

	err = fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if *isKeyGen {
		data := []byte{}
		l := len(os.Args)
		switch {
		case l < 3:
			data = append([]byte{0x02}, []byte("interactive")...)
		case l == 3:
			host, err := url.Parse(os.Args[l-1])
			if err != nil {
				log.Fatal("invalid URL provided in keygen", err)
			}
			data = append([]byte{0x01}, []byte(host.String())...)
		case l == 4:
			pkb, err := hex.DecodeString(os.Args[2])
			if err != nil {
				log.Fatal("invalid public key hex provided in keygen")
			}
			chb, err := hex.DecodeString(os.Args[3])
			if err != nil {
				log.Fatal("invalid chainhash hex provided in keygen")
			}

			data = append([]byte{0x00}, pkb...)
			data = append(data, chb...)

			//case l == 5:
		default:
			Usage()
		}

		pub := page.EncodeRecipient(p.Name(), data)
		fmt.Println("recipient",pub)
		priv := page.EncodeIdentity(p.Name(), data)
		fmt.Println("identity", priv)

		return
	}

	p.Main()

}

func Usage() {
	log.Fatal("Usage of keygen:\n\t " +
		"- use age in interactive mode, getting prompted for all required data:\n\t\t\tage-plugin-tlock -keygen\n\t" +
		"- providing a http endpoint (works for both encryption and decryption, but require networking): \n\t\t\tage-plugin-tlock -keygen http://api.drand.sh/\n\t " +
		"- providing a public key and a chainhash (requires networking to fetch genesis and period, but is networkless afterwards): \n\t\t\tage-plugin-tlock -keygen <hexadecimal-public-key> <hexadecimal-chainhash> \n\t " +
		//"- providing a public key, a chainhash and the signature for the round you're interested in (networkless for decryption): \n\t\t\tage-plugin-tlock -keygen" +
		"\n")
}

// createRecipient creates data for recipients of the form:
// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD><ROUND(optional)>
func createRecipient(chainhash []byte, publicKey []byte, genesis int64, period uint, round int64) []byte {
	b := bytes.Buffer{}
	// we follow the tlock-ts encoding that uses https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md
	b.Write(append([]byte{byte(len(chainhash))}, chainhash...))
	b.Write(append([]byte{byte(len(publicKey))}, publicKey...))
	// varint encoding of genesis
	b.Write(intEncode(uint64(genesis)))
	b.Write(intEncode(uint64(period)))
	if round > 0 {
		b.Write(intEncode(uint64(round)))
	}
	return b.Bytes()
}

// intEncode re-implements the bincode format for uint64 values
func intEncode(u uint64) []byte {
	buf := make([]byte, 1, binary.MaxVarintLen64)
	switch {
	case u < 251:
		buf[0] = byte(u)
	case u < math.MaxInt16:
		buf[0] = byte(251)
		buf = binary.LittleEndian.AppendUint16(buf, uint16(u))
	case u < math.MaxInt32:
		buf[0] = byte(252)
		buf = binary.LittleEndian.AppendUint32(buf, uint32(u))
	case u < math.MaxInt64:
		buf[0] = byte(253)
		buf = binary.LittleEndian.AppendUint64(buf, u)
	default:
		// 254 is meant for u128, but we don't support 128 bit integers here.
		buf[0] = byte(254)
	}

	return buf
}

func intDecode(r io.Reader) (uint64, int) {
	buf := make([]byte, 1)
	i, err := r.Read(buf)
	if err != nil || i != 1 {
		slog.Error("intDecode error", "error", err, "read", i)
		return 0, -1
	}
	u := buf[0]
	switch {
	case int(u) < 251:
		return uint64(u), 1
	case u == byte(251):
		data := make([]byte, 2)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint16(data)), 1 + 2
	case u == byte(252):
		data := make([]byte, 4)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint32(data)), 1 + 4
	case u == byte(253):
		data := make([]byte, 8)
		i, err = r.Read(data)
		if err != nil || i <= 0 {
			slog.Error("read data error", "error", err, "read", i)
			return 0, -1
		}
		return uint64(binary.LittleEndian.Uint64(data)), 1 + 8
	case u == byte(254):
		slog.Error("u128 are unsupported")
		return 0, -1

	}
	return 0, -1
}

func decodePublicKey(pks string) (kyber.Point, *crypto.Scheme, error) {
	suite := bls.NewBLS12381Suite()
	data, err := hex.DecodeString(pks)
	if err != nil {
		return nil, nil, err
	}
	switch l := len(data); l {
	case suite.G1().PointLen():
		slog.Debug("detected public key on G1")
		var p bls.KyberG1
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, nil, fmt.Errorf("unmarshal kyber G1: %w", err)
		}
		sch := crypto.NewPedersenBLSUnchained()
		return &p, sch, nil
	case suite.G2().PointLen():
		slog.Debug("detected public key on G2")
		var p bls.KyberG2
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, nil, fmt.Errorf("unmarshal kyber G2: %w", err)
		}
		sch := crypto.NewPedersenBLSUnchainedG1()
		return &p, sch, nil
	default:
	}
	return nil, nil, errors.New("invalid public key len")
}

func NewIdentity(p *page.Plugin) func([]byte) (age.Identity, error) {
	return func(data []byte) (age.Identity, error) {
		if len(data) < 1 {
			return nil, errors.New("invalid identity")
		}
		var sig []byte
		var err error
		var network tlock.Network
		if data[0] == 0 {
			slog.Info("parsed data[0] == 0")
			sig = make([]byte, len(data[1:])/2)
			n, err := hex.Decode(sig, data[1:])
			if err != nil {
				return nil, err
			}
			if n != len(sig) {
				return nil, errors.New("error decoding signature from identity")
			}
			network, err = fixed.NewNetwork("", nil, nil, 0, 0, sig)
			if err != nil {
				return nil, err
			}
		} else if data[0] == 1 {
			slog.Info("parsed data[0] == 1")
			network, err = ParseNetwork(string(data[2:]))
		} else if data[0] == 2 {
			// interactive mode
			slog.Info("parsed data[0] == 2")
			return interactive{p: p}, nil
		} else {
			slog.Error("unknown tlock identity", "type", data[0])
			slog.Info("defaulting to interactive mode")
			return interactive{p: p}, nil
		}
		// we need to have tlock use the SwitchChainHash on the fixed network for it to work
		return tlock.NewIdentity(network, true), err
	}
}

type interactive struct {
	p *page.Plugin
}

type target struct {
	round     string
	chainhash string
}

func (i interactive) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	fmt.Fprintln(os.Stderr, "starting Unwrap in interactive mode", "#stanzas", len(stanzas))
	var targets []target
	for _, s := range stanzas {
		if s.Type != "tlock" {
			continue
		}

		if len(s.Args) != 2 {
			continue
		}

		target := target{
			round:     s.Args[0],
			chainhash: s.Args[1],
		}
		targets = append(targets, target)
	}

	if len(targets) != 1 {
		return nil, errors.New("tlock only supports a single stanza in interactive mode for now")
	}
	network, err := i.requestNetwork(targets[0].chainhash, targets[0].round)
	if err != nil {
		return nil, err
	}

	id := tlock.NewIdentity(network, true)

	return id.Unwrap(stanzas)
}

func (i interactive) requestRound() (uint64, error) {
	roundStr, err := i.p.RequestValue("please provide the round number you want to encrypt towards", false)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(roundStr, 10, 64)
}

func (i interactive) requestNetwork(chainhash, round string) (tlock.Network, error) {
	if chainhash == "" {
		var err error
		chainhash, err = i.p.RequestValue("please provide the chainhash of the network you want to work with (an empty value will use the default one)", false)
		if err != nil {
			return nil, err
		}
		if chainhash == "" {
			chainhash = DefaultChainhash
		}
	}
	usePK, err := i.p.Confirm("do you want to provide the group public key and round signature, or do you want to use a HTTP relay?", "use public key", "use HTTP relay")
	if err != nil {
		return nil, fmt.Errorf("confirmation error in Unwrap: %w", err)
	}
	if usePK {
		pks := DefaultPK
		if chainhash != DefaultChainhash {
			pks, err = i.p.RequestValue("Please provide the hex encoded public key for the chainhash "+chainhash, false)
			if err != nil {
				return nil, err
			}
		}
		pk, sch, err := decodePublicKey(pks)
		if err != nil {
			return nil, err
		}
		var sig []byte
		if round != "" {
			sigs, err := i.p.RequestValue("please provide the hex encoded signature of the round "+round, false)
			if err != nil {
				return nil, err
			}
			sig, err = hex.DecodeString(sigs)
			if err != nil {
				return nil, err
			}
		}
		return fixed.NewNetwork(chainhash, pk, sch, 0, 0, sig)
	}

	host, err := i.p.RequestValue("Please provide the http relay for chainhash (an empty value will use the default one)"+chainhash, false)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = DefaultRemote
	}
	return http.NewNetwork(host, chainhash)
}

func (p interactive) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	fmt.Fprintln(os.Stderr, "starting Wrap in interactive mode")
	net, err := p.requestNetwork("", "")
	if err != nil {
		return nil, err
	}
	round, err := p.requestRound()
	if err != nil {
		return nil, err
	}

	rec := tlock.NewRecipient(net, round)

	return rec.Wrap(fileKey)
}

// NewRecipient parses the recipient from the age1tlock1 recipient strings.
// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD><ROUND(optional)>
func NewRecipient(p *page.Plugin) func([]byte) (age.Recipient, error) {
	return func(data []byte) (age.Recipient, error) {
		// RAW mode
		var chainhash []byte
		var pk kyber.Point
		var scheme *crypto.Scheme
		offset := 0
		if length := len(data); length >= 32+48+8+8 {
			if data[0] != 32 {
				return nil, fmt.Errorf("invalid len %d for chainhash", data[0])
			}
			chainhash = data[1:1+32]
			if length >= 1+32+1+1+1+1 && length <= 1+32+1+48+8+8+8 {
				pk = new(bls.KyberG1)
				offset = 48
				scheme = crypto.NewPedersenBLSUnchained()
			} else if length >= 1+32+1+96+1+1+1 && length <= 1+32+1+96+8+8+8 {
				pk = new(bls.KyberG2)
				offset = 96
				scheme = crypto.NewPedersenBLSUnchainedG1()
			} else {
				return nil, fmt.Errorf("invalid len %d for tlock recipient", length)
			}
			if err := pk.UnmarshalBinary(data[1+32+1 : 1+32+1+offset]); err != nil {
				return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
			}

			// Careful, the following actually isn'at interoperable with the rust tlock plugin since it's using different encoding it seems.
			r := bytes.NewReader(data[1+32+1+offset:])
			genesis, err := binary.ReadVarint(r)
			if err != nil {
				return nil, fmt.Errorf("unable to read genesis: %w", err)
			}
			period, err := binary.ReadVarint(r)
			if err != nil {
				return nil, fmt.Errorf("unable to read period: %w", err)
			}
			scheme = crypto.NewPedersenBLSUnchained()
			round, i := intDecode(r)
			if i <= 0 {
				slog.Error("invalid round in recipient, aborting")
				return nil, fmt.Errorf("wrong round")
			}

			network, err := fixed.NewNetwork(hex.EncodeToString(chainhash), pk, scheme, time.Duration(period)*time.Second, genesis, nil)

			return tlock.NewRecipient(network, uint64(round)), err
		} else {
			slog.Error("invalid length for tlock recipient", "length", length)
			slog.Debug("using interactive mode", "data", data)
			return interactive{p: p}, nil
		}
	}
}

func ParseNetwork(u string) (tlock.Network, error) {
	s := strings.TrimRight(u, "/")
	urls := strings.Split(s, "/")
	chainhash := urls[len(urls)-1]
	if len(chainhash) == 64 {
		urls = urls[:len(urls)-1]
		fmt.Fprintln(os.Stderr, "using chainhash from endpoint", chainhash)
	} else {
		fmt.Fprintln(os.Stderr, "using default chainhash", chainhash)
		chainhash = commands.DefaultChain
	}
	return http.NewNetwork(strings.Join(urls, "/"), chainhash)

}
