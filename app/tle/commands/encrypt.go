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
	if flags.DurationFlag != "" {
		duration, err := time.ParseDuration(flags.DurationFlag)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		return drnd.EncryptWithDuration(ctx, dst, dataToEncrypt, flags.NetworkFlag, flags.ChainFlag, duration)
	}

	// Default to round
	return drnd.EncryptWithRound(ctx, dst, dataToEncrypt, flags.NetworkFlag, flags.ChainFlag, uint64(flags.RoundFlag))
}
