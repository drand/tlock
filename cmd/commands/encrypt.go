package commands

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"filippo.io/age/armor"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

// Encrypt performs the encryption operation. This requires the implementation
// of an encoder for reading/writing to disk, a network for making calls to the
// drand network, and an encrypter for encrypting/decrypting the data.
func Encrypt(flags Flags, dst io.Writer, src io.Reader, network *http.Network) error {
	tlock := tlock.NewEncrypter(network)

	if flags.Armor {
		a := armor.NewWriter(dst)
		defer func() {
			if err := a.Close(); err != nil {
				fmt.Printf("Error while closing: %v", err)
			}
		}()
		dst = a
	}

	switch {
	case flags.Round != 0:
		lastestAvailableRound, err := network.RoundNumber(time.Now())
		if err != nil {
			return fmt.Errorf("round numer: %w", err)
		}

		if flags.Round < lastestAvailableRound {
			return fmt.Errorf("round %d is in the past", flags.Round)
		}

		return tlock.Encrypt(dst, src, flags.Round)

	case flags.Duration != "":
		duration, err := parseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		roundNumber, err := network.RoundNumber(time.Now().Add(duration))
		if err != nil {
			return fmt.Errorf("round number: %w", err)
		}

		return tlock.Encrypt(dst, src, roundNumber)
	}

	return nil
}

// parseDuration parses the duration and can handle days, months, and years.
func parseDuration(duration string) (time.Duration, error) {
	d, err := time.ParseDuration(duration)
	if err == nil {
		return d, nil
	}

	// M has to be capitalised to avoid conflict with minutes.
	if !strings.ContainsAny(duration, "dMy") {
		return time.Second, fmt.Errorf("unknown unit")
	}

	now := time.Now()

	pieces := strings.Split(duration, "d")
	if len(pieces) == 2 {
		days, err := strconv.Atoi(pieces[0])
		if err != nil {
			return time.Second, fmt.Errorf("parse day duration: %w", err)
		}
		diff := now.AddDate(0, 0, days).Sub(now)
		return diff, nil
	}

	pieces = strings.Split(duration, "M")
	if len(pieces) == 2 {
		months, err := strconv.Atoi(pieces[0])
		if err != nil {
			return time.Second, fmt.Errorf("parse month duration: %w", err)
		}
		diff := now.AddDate(0, months, 0).Sub(now)
		return diff, nil
	}

	pieces = strings.Split(duration, "y")
	if len(pieces) == 2 {
		years, err := strconv.Atoi(pieces[0])
		if err != nil {
			return time.Second, fmt.Errorf("parse year duration: %w", err)
		}
		diff := now.AddDate(years, 0, 0).Sub(now)
		return diff, nil
	}

	return time.Second, fmt.Errorf("parse duration: %w", err)
}
