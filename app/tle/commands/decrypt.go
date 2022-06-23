package commands

import (
	"context"
	"io"

	"github.com/drand/tlock/foundation/drnd"
)

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, dst io.Writer, dataToDecrypt io.Reader) error {
	if err := drnd.Decrypt(ctx, dst, flags.Network, dataToDecrypt); err != nil {
		return err
	}

	return nil
}
