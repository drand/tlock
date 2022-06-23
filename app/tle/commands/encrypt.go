package commands

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, dst io.Writer, dataToEncrypt io.Reader) error {
	if flags.Duration != "" {
		duration, err := time.ParseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, dst, dataToEncrypt, flags.Network, flags.Chain, flags.Armor, duration)
	}

	return drnd.EncryptWithRound(ctx, dst, dataToEncrypt, flags.Network, flags.Chain, flags.Armor, flags.Round)
}
