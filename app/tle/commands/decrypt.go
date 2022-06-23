package commands

import (
	"context"
	"io"

	"github.com/drand/tlock/foundation/drnd"
)

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	if err := drnd.Decrypt(ctx, out, in, flags.Network); err != nil {
		return err
	}

	return nil
}
