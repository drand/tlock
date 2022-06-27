package commands

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
	"github.com/drand/tlock/foundation/networks/http"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	network := http.New(flags.Network, flags.Chain)

	if flags.Duration != "" {
		duration, err := time.ParseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, out, in, network, duration, flags.Armor)
	}

	return drnd.EncryptWithRound(ctx, out, in, network, flags.Round, flags.Armor)
}

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	network := http.New(flags.Network, flags.Chain)

	if err := drnd.Decrypt(ctx, out, in, network); err != nil {
		return err
	}

	return nil
}
