package commands

import (
	"context"
	"fmt"
	"io"

	"github.com/drand/tlock/foundation/drnd"
)

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, dataToDecrypt io.Reader) error {
	data, err := drnd.Decrypt(ctx, dataToDecrypt)
	if err != nil {
		return err
	}

	// Printing data to stdout for now
	fmt.Println(string(data))

	return nil
}
