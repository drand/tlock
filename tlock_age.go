package tlock

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/drand/drand/chain"
)

var ErrWrongChainhash = errors.New("invalid chainhash")

// Recipient implements the age Recipient interface. This is used to encrypt
// data with the age Encrypt API.
type Recipient struct {
	Network     Network
	RoundNumber uint64
}

// Wrap is called by the age Encrypt API and is provided the DEK generated by
// age that is used for encrypting/decrypting data. Inside of Wrap we encrypt
// the DEK using time lock encryption.
func (t *Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	ciphertext, err := TimeLock(t.Network.Scheme(), t.Network.PublicKey(), t.RoundNumber, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	body, err := CiphertextToBytes(t.Network.Scheme(), ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}

	stanza := age.Stanza{
		Type: "tlock",
		Args: []string{strconv.FormatUint(t.RoundNumber, 10), t.Network.ChainHash()},
		Body: body,
	}

	return []*age.Stanza{&stanza}, nil
}

func (t *Recipient) String() string {
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("%d@", t.RoundNumber))
	sb.WriteString(t.Network.ChainHash())
	sb.WriteString("-" + t.Network.Scheme().Name)
	d, err := t.Network.PublicKey().MarshalBinary()
	if err != nil {
		d = []byte("error")
	}
	sb.WriteString("-" + hex.EncodeToString(d))

	return sb.String()
}

// =============================================================================

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
type Identity struct {
	Network        Network
	TrustChainhash bool
}

// Unwrap is called by the age Decrypt API and is provided the DEK that was time
// lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
// the DEK and provide back to age. If the ciphertext uses a chainhash different
// from the one we are current using, we will try switching to it.
func (t *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) < 1 {
		return nil, errors.New("check stanzas length: should be at least one")
	}

	invalid := ""
	for _, stanza := range stanzas {
		if stanza.Type != "tlock" {
			continue
		}

		if len(stanza.Args) != 2 {
			continue
		}

		roundNumber, err := strconv.ParseUint(stanza.Args[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse block round: %w", err)
		}

		if t.Network.ChainHash() != stanza.Args[1] {
			invalid = stanza.Args[1]
			if t.TrustChainhash {
				fmt.Fprintf(os.Stderr, "WARN: stanza using different chainhash '%s', trying to use it instead.\n", invalid)
				err = t.Network.SwitchChainHash(invalid)
				if err != nil {
					continue
				}
			} else {
				continue
			}
		}

		ciphertext, err := BytesToCiphertext(t.Network.Scheme(), stanza.Body)
		if err != nil {
			return nil, fmt.Errorf("parse cipher dek: %w", err)
		}

		signature, err := t.Network.Signature(roundNumber)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: expected round %d > %d current round",
				ErrTooEarly,
				roundNumber,
				t.Network.Current(time.Now()))
		}

		beacon := chain.Beacon{
			Round:     roundNumber,
			Signature: signature,
		}

		fileKey, err := TimeUnlock(t.Network.Scheme(), t.Network.PublicKey(), beacon, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt dek: %w", err)
		}

		return fileKey, nil
	}

	if len(invalid) > 0 {
		return nil, fmt.Errorf("%w: current network uses %s != %s the ciphertext requires.\n"+
			"Note that is might have been encrypted using our testnet instead", ErrWrongChainhash, t.Network.ChainHash(), invalid)
	}

	return nil, fmt.Errorf("check stanza type: wrong type: %w", age.ErrIncorrectIdentity)
}

func (t *Identity) String() string {
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("Trust:%v@", t.TrustChainhash))
	sb.WriteString(t.Network.ChainHash())
	sb.WriteString("-" + t.Network.Scheme().Name)
	sb.WriteString("-" + t.Network.PublicKey().String())

	return sb.String()
}
