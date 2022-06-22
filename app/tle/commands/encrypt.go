package commands

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
)

// Encrypt performs the encryption operation.
func Encrypt(flags Flags, dst io.Writer, dataToEncrypt io.Reader) error {

	dur, err := time.ParseDuration(flags.DurationFlag)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}

	config := drnd.Config{
		Network:   flags.NetworkFlag[0],
		ChainHash: flags.ChainFlag,
		Duration:  dur,
	}

	return drnd.Encrypt(context.Background(), config, dst, dataToEncrypt)
}
