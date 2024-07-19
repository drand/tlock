package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/drand/drand/crypto"
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
	// we setup the flags we need
	fs := flag.NewFlagSet("age-plugin-tlock", flag.ExitOnError)
	isKeyGen := fs.Bool("keygen", false, "Generate a test keypair")

	//chainHash := fs.String("chainhash", DefaultChainhash, "The chainhash you want to encrypt towards. Default to the 'quicknet' one")
	//remote := fs.String("remote", DefaultRemote, "The remote endpoint you want to use for getting data. Default to 'https://api.drand.sh'.")

	p, err := page.New("tlock")
	if err != nil {
		fmt.Println("error creating plugin", err)
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
		//if len(os.Args) < 1 {
		//	log.Fatal("Usage of keygen:\n\t " +
		//		"- providing a http endpoint: age-plugin-tlock -keygen http://api.drand.sh/\n\t " +
		//		//"- providing a public key and a chainhash \n\t " +
		//		//"- providing a public key, a chainhash and the signature for the round you're interested in"+
		//		"")
		//}
		//httpId := append([]byte{0x01}, []byte(os.Args[len(os.Args)-1])...)

		id := append([]byte{0x02}, []byte("interactive")...)

		pub := page.EncodeRecipient(p.Name(), id)
		fmt.Println("recipient:", pub)
		priv := page.EncodeIdentity(p.Name(), id)
		fmt.Println("identity:", priv)
	} else {
		p.Main()
	}
}

//
//{
//	log.Fatal(
//"Please specify the round number you want to encrypt towards as the last positional argument of the keygen. " +
//"By default this creates a recipient to encrypts towards the mainnet quicknet network and remote relays without using networking, " +
//"use the -remote and -chainhash flags to specify another one if needed, this will use HTTP to query the remote")
//}
//round, err := strconv.Atoi(os.Args[len(os.Args)-1])
//if err != nil || round < 0 {
//log.Fatalf("invalid integer for round %d:%v", round, err)
//}

// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD>
// age1tlock1yrda2pkkaamwtuux7swx28wtszx9hj7h23cucn40506d77k5unzfxc9qhp32w5nlaca8xx7tty5q4d4t6ck4czmw5q7ufh0kvyhaljwsruqux92z2sthryp5wh43a3npt7xsmu9ckmww8pvpr4kulr97lwr4ne0xz63al5z5ey5fgpmxmxjmnku3uwmf0ewhp2t4rq0qqlu8ljj7lng8rlmrqvpvft27
//
//var data []byte
//
//if *chainHash == commands.DefaultChain && *remote == commands.DefaultNetwork {
//pkb, err := hex.DecodeString("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
//if err != nil {
//log.Fatal(err)
//}
//
//hashb, err := hex.DecodeString(commands.DefaultChain)
//if err != nil {
//log.Fatal(err)
//}
//data = EncodeRecipient(hashb, pkb, int64(defaultGenesis), defaultPeriod, int64(round))
//}
//
//pub := page.EncodeRecipient(p.Name(), data)
//}

// createRecipient creates data for recipients of the form:
// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD><ROUND(optional)>
func createRecipient(chainhash []byte, publicKey []byte, genesis int64, period int, round int64) []byte {
	b := bytes.Buffer{}
	// we follow the tlock-ts encoding that uses https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md
	b.Write(append([]byte{byte(len(chainhash))}, chainhash...))
	b.Write(append([]byte{byte(len(publicKey))}, publicKey...))
	// varint encoding of genesis
	b.Write(intEncode(int64(genesis)))
	b.Write(intEncode(int64(period)))
	if round > 0 {
		b.Write(intEncode(int64(round)))
	}
	return b.Bytes()
}

func intEncode(val int64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(buf, val)

	fmt.Fprintln(os.Stderr, "Encoded int", val, "into", n, "bytes:", buf[:n])

	return buf[:n]
}

func decodePublicKey(pks string) (kyber.Point, *crypto.Scheme, error) {
	suite := bls.NewBLS12381Suite()
	data, err := hex.DecodeString(pks)
	if err != nil {
		return nil, nil, err
	}
	switch l := len(data); l {
	case suite.G1().PointLen():
		fmt.Fprintln(os.Stderr, "detected public key on G1")
		var p bls.KyberG1
		if err := p.UnmarshalBinary(data); err != nil {
			return nil, nil, fmt.Errorf("unmarshal kyber G1: %w", err)
		}
		sch := crypto.NewPedersenBLSUnchained()
		return &p, sch, nil
	case suite.G2().PointLen():
		fmt.Fprintln(os.Stderr, "detected public key on G2")
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
			s := strings.TrimRight(string(data[2:]), "/")
			urls := strings.Split(s, "/")
			chainhash := urls[len(urls)-1]
			if len(chainhash) == 64 {
				urls = urls[:len(urls)-1]
				fmt.Fprintln(os.Stderr, "using chainhash from endpoint", chainhash)
			} else {
				chainhash = commands.DefaultChain
			}
			network, err = http.NewNetwork(strings.Join(urls, "/"), chainhash)
		} else if data[0] == 2 {
			// interactive mode
			return interactive{p: p}, nil
		} else {
			fmt.Fprintln(os.Stderr, "unknown type:", data[0])
			return interactive{p: p}, nil
		}

		return &tlock.Identity{
			Network: network,
			// we need to have tlock use the SwitchChainHash on the fixed network for it to work
			TrustChainhash: true,
		}, err
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

	id := tlock.Identity{
		Network:        network,
		TrustChainhash: true,
	}
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
		chainhash, err = i.p.RequestValue("please provide the chainhash of the network you want to work with", false)
		if err != nil {
			return nil, err
		}
	}
	usePK, err := i.p.Confirm("do you want to provide the group public key and round signature, or do you want to use a HTTP relay?", "use public key", "use HTTP relay")
	if err != nil {
		return nil, fmt.Errorf("confirmation error in Unwrap: %w", err)
	}
	if usePK {
		pks, err := i.p.RequestValue("Please provide the hex encoded public key for the chainhash "+chainhash, false)
		if err != nil {
			return nil, err
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

	host, err := i.p.RequestValue("Please provide the http relay for chainhash "+chainhash, false)
	if err != nil {
		return nil, err
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

	rec := tlock.Recipient{
		Network:     net,
		RoundNumber: round,
	}

	return rec.Wrap(fileKey)
}

// NewRecipient parses the recipient from the age1tlock1 recipient strings.
// The beck32 data contains: <HASH><PUBLIC_KEY><GENESIS><PERIOD><ROUND>
func NewRecipient(p *page.Plugin) func([]byte) (age.Recipient, error) {
	return func(data []byte) (age.Recipient, error) {
		// RAW mode
		if data[0] == 0 {
			fmt.Fprintln(os.Stderr, "bech len", len(data))
			chainhash := data[:32]
			var pk kyber.Point
			var scheme *crypto.Scheme
			offset := 0
			if len(data) >= 1+32+1+1+1+1 && len(data) <= 1+32+1+48+8+8+8 {
				pk = new(bls.KyberG1)
				offset = 48
				scheme = crypto.NewPedersenBLSUnchained()
			} else if len(data) >= 1+32+1+96+1+1+1 && len(data) <= 1+32+1+96+8+8+8 {
				pk = new(bls.KyberG2)
				offset = 96
				scheme = crypto.NewPedersenBLSUnchainedG1()
			} else {
				return nil, fmt.Errorf("invalid len %d for tlock recipient", len(data))
			}
			if err := pk.UnmarshalBinary(data[1+32+1 : 1+32+1+offset]); err != nil {
				return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
			}

			r := bytes.NewReader(data[1+32+1+offset:])
			genesis, err := binary.ReadVarint(r)
			if err != nil {
				return nil, fmt.Errorf("unable to read genesis: %w", err)
			}
			period, err := binary.ReadVarint(r)
			if err != nil {
				return nil, fmt.Errorf("unable to read genesis: %w", err)
			}
			round, err := binary.ReadUvarint(r)
			if err != nil {
				return nil, fmt.Errorf("unable to read genesis: %w", err)
			}

			network, err := fixed.NewNetwork(hex.EncodeToString(chainhash), pk, scheme, time.Duration(period)*time.Second, genesis, nil)

			return &tlock.Recipient{
				Network:     network,
				RoundNumber: round,
			}, err
		}
		if data[0] == 1 {
			panic("unimplemented for now")
			//network := http.NewNetwork()
			//
			//return &tlock.Recipient{
			//	Network:     network,
			//	RoundNumber: round,
			//}, err
		}

		if data[0] == 2 && p != nil {
			return interactive{p: p}, nil
		}
		return nil, fmt.Errorf("unknown identity type: %x", data[0])
	}
}
