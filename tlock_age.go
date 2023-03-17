package tlock

import (
	"errors"
	"fmt"
	"strconv"

	"filippo.io/age"
	"github.com/drand/drand/chain"
)

// tleRecipient implements the age Recipient interface. This is used to encrypt
// data with the age Encrypt API.
type tleRecipient struct {
	network     Network
	roundNumber uint64
}

// Wrap is called by the age Encrypt API and is provided the DEK generated by
// age that is used for encrypting/decrypting data. Inside of Wrap we encrypt
// the DEK using time lock encryption.
func (t *tleRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	ciphertext, err := TimeLock(t.network.Scheme(), t.network.PublicKey(), t.roundNumber, fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt dek: %w", err)
	}

	body, err := CiphertextToBytes(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("bytes: %w", err)
	}

	stanza := age.Stanza{
		Type: "tlock",
		Args: []string{strconv.FormatUint(t.roundNumber, 10), t.network.ChainHash()},
		Body: body,
	}

	return []*age.Stanza{&stanza}, nil
}

// =============================================================================

// tleIdentity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
type tleIdentity struct {
	network Network
}

// Unwrap is called by the age Decrypt API and is provided the DEK that was time
// lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
// the DEK and provide back to age.
func (t *tleIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) < 1 {
		return nil, errors.New("check stanzas length: should be at least one")
	}

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

		if t.network.ChainHash() != stanza.Args[1] {
			return nil, fmt.Errorf("wrong chainhash: current network uses %s != %s the ciphertext requires.\n"+
				"Note that is might have been encrypted using our testnet instead", t.network.ChainHash(), stanza.Args[1])
		}

		ciphertext, err := BytesToCiphertext(stanza.Body)
		if err != nil {
			return nil, fmt.Errorf("parse cipher dek: %w", err)
		}

		signature, err := t.network.Signature(roundNumber)
		if err != nil {
			return nil, fmt.Errorf("signature: %w", ErrTooEarly)
		}

		beacon := chain.Beacon{
			Round:     roundNumber,
			Signature: signature,
		}

		fileKey, err := TimeUnlock(t.network.Scheme(), t.network.PublicKey(), beacon, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decrypt dek: %w", err)
		}

		return fileKey, nil
	}

	return nil, fmt.Errorf("check stanza type: wrong type: %w", age.ErrIncorrectIdentity)
}
