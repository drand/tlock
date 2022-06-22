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
	duration, err := time.ParseDuration(flags.DurationFlag)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}

	return drnd.Encrypt(ctx, dst, dataToEncrypt, flags.NetworkFlag, flags.ChainFlag, duration)
}
