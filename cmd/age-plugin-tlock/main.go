package main

import (
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

func main() {
	fs := flag.NewFlagSet("age-plugin-tlock", flag.ExitOnError)
	isKeyGen := fs.Bool("keygen", false, "Generate a test keypair")
	chainHash := fs.String("chainhash", "", "The chainhash you want to encrypt towards. Default to the 'quicknet' one")
	p, err := page.New("tlock")
	if err != nil {
		fmt.Println("error creating plugin", err)
		return
	}

	p.HandleRecipient(NewRecipient)
	p.HandleIdentity(NewIdentity)
	p.RegisterFlags(fs)

	err = fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	if *isKeyGen {
		if len(os.Args) < 3 {
			log.Fatal("Please specify the round number you want to encrypt towards as the last positional argument of the keygen. By default this encrypts towards the mainnet quicknet network, use the -network and -chainhash flags to specify another one if needed")
		}
		round, err := strconv.Atoi(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatal("invalid integer for round:", err)
		}
		// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD>
		// age1tlock1yrda2pkkaamwtuux7swx28wtszx9hj7h23cucn40506d77k5unzfxc9qhp32w5nlaca8xx7tty5q4d4t6ck4czmw5q7ufh0kvyhaljwsruqux92z2sthryp5wh43a3npt7xsmu9ckmww8pvpr4kulr97lwr4ne0xz63al5z5ey5fgpmxmxjmnku3uwmf0ewhp2t4rq0qqlu8ljj7lng8rlmrqvpvft27

		pub := page.EncodeRecipient(p.Name(), []byte("thisisatest"+*chainHash))
		fmt.Println("recipient:", pub)
		fmt.Println("round:", round)
	} else {
		p.Main()
	}
}

// AGE-PLUGIN-TLOCK-<TYPE><IDENTITY>
func NewIdentity(data []byte) (age.Identity, error) {
	fmt.Fprintln(os.Stderr, "bech len", len(data))

	if len(data) < 1 {
		return nil, errors.New("invalid identity")
	}
	var pk kyber.Point
	var sch *crypto.Scheme
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
		suite := bls.NewBLS12381Suite()
		switch l := len(data[1:]); l {
		case suite.G1().PointLen():
			var p bls.KyberG1
			if err := p.UnmarshalBinary(data[1:]); err != nil {
				return nil, fmt.Errorf("unmarshal kyber G1: %w", err)
			}
			pk = &p
			sch = crypto.NewPedersenBLSUnchainedG1()
		case suite.G2().PointLen():
			var p bls.KyberG2
			if err := p.UnmarshalBinary(data[1:]); err != nil {
				return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
			}
			pk = &p
			sch = crypto.NewPedersenBLSUnchained()
		default:
			return nil, errors.New("invalid signature len in raw identity")
		}
		network, err = fixed.NewNetwork("", pk, sch, 0, 0, sig)
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
	} else {
		fmt.Fprintln(os.Stderr, "type:", data[0])
		return nil, errors.New("unknown identity type, neither raw nor http")
	}

	return &tlock.Identity{
		Network:        network,
		TrustChainhash: true,
	}, err
}

// NewRecipient parses the recipient from the age1tlock1 recipient strings.
// The beck32 data contains: <HASH><PUBLIC_KEY><GENESIS><PERIOD><ROUND>
func NewRecipient(data []byte) (age.Recipient, error) {
	fmt.Fprintln(os.Stderr, "bech len", len(data))
	chainhash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	var pk bls.KyberG2
	pks, err := hex.DecodeString("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
	if err != nil {
		return nil, err
	}
	if err := pk.UnmarshalBinary(pks); err != nil {
		return nil, fmt.Errorf("unmarshal kyber G2: %w", err)
	}
	network, err := fixed.NewNetwork(chainhash, &pk, crypto.NewPedersenBLSUnchainedG1(), 3*time.Second, int64(1692803367), nil)
	return &tlock.Recipient{
		Network:     network,
		RoundNumber: 8636452,
	}, err
}
