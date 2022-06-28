package commands

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
	"github.com/drand/tlock/foundation/encrypters/aead"
	"github.com/drand/tlock/foundation/networks/http"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	var aead aead.AEAD
	network := http.New(flags.Network, flags.Chain)

	if flags.Round != 0 {
		client, err := network.Client(ctx)
		if err != nil {
			return fmt.Errorf("network client: %w", err)
		}

		// This will return the latest number for now.
		lastestRound := client.RoundAt(time.Now())

		// We have to make sure this round number is for the future.
		if flags.Round < lastestRound {
			return fmt.Errorf("round %d is not valid anymore", flags.Round)
		}

		return drnd.EncryptWithRound(ctx, out, in, network, aead, flags.Round, flags.Armor)
	}

	if flags.Duration != "" {
		duration, err := time.ParseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, out, in, network, aead, duration, flags.Armor)
	}

	return nil
}

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	var aead aead.AEAD
	network := http.New(flags.Network, flags.Chain)

	if err := drnd.Decrypt(ctx, out, in, network, aead); err != nil {
		return err
	}

	return nil
}
