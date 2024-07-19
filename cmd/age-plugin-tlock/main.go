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
var DefaultChainhash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
var DefaultPK = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
var DefaultPeriod = 3
var DefaultGenesis int64 = 1692803367
var DefaultHost = "http://api.drand.sh/"

func main() {
	// we setup the flags we need
	fs := flag.NewFlagSet("age-plugin-tlock", flag.ExitOnError)
	isKeyGen := fs.Bool("keygen", false, "Generate a test keypair")
	//chainHash := fs.String("chainhash", "", "The chainhash you want to encrypt towards. Default to the 'quicknet' one")

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
		if len(os.Args) < 3 {
			log.Fatal("Usage of keygen:\n\t - providing a http endpoint: age-plugin-tlock -keygen http://api.drand.sh/\n\t - providing a public key and a chainhash \n\t - providing a public key, a chainhash and the signature for the round you're interested in")
		}

		httpId := append([]byte{0x01}, []byte(os.Args[len(os.Args)-1])...)
		pub := page.EncodeRecipient(p.Name(), httpId)
		fmt.Println("recipient:", pub)
		priv := page.EncodeIdentity(p.Name(), httpId)
		fmt.Println("identity:", priv)
	} else {
		p.Main()
	}
}

// createRecipient creates recipients of the form:
// age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD>
func createRecipient(chainhash, pk, genesis, period string) ([]byte, error) {
	return nil, nil
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
		return interactive{p: p}, nil
	}
}
