package commands

import (
	"io"
	"time"

	"github.com/drand/tlock/foundation/drnd"
)

// Encrypt performs the encryption operation.
func Encrypt(d *drnd.Drnd, w io.Writer, r io.Reader, duration time.Duration, armor bool) error {

	// Ignoring the armor parameter for now
	return d.Encrypt(w, r, duration)
}
