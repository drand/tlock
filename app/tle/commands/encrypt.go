package commands

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	if flags.Duration != "" {
		duration, err := time.ParseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, out, in, flags.Network, flags.Chain, duration, flags.Armor)
	}

	return drnd.EncryptWithRound(ctx, out, in, flags.Network, flags.Chain, flags.Round, flags.Armor)
}
