package commands

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/drand/tlock"
)

// Encrypt performs the encryption operation. This requires the implementation
// of an encoder for reading/writing to disk, a network for making calls to the
// drand network, and an encrypter for encrypting/decrypting the data.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader, encoder tlock.Encoder, network tlock.Network, dataEncrypter tlock.DataEncrypter) error {
	tlock := tlock.NewEncrypter(network, dataEncrypter, encoder)

	switch {
	case flags.Round != 0:
		lastestAvailableRound, err := network.RoundNumber(ctx, time.Now())
		if err != nil {
			return fmt.Errorf("round numer: %w", err)
		}

		if flags.Round < lastestAvailableRound {
			return fmt.Errorf("round %d is in the past", flags.Round)
		}

		return tlock.Encrypt(ctx, out, in, flags.Round, flags.Armor)

	case flags.Duration != "":
		duration, err := parseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}

		roundNumber, err := network.RoundNumber(ctx, time.Now().Add(duration))
		if err != nil {
			return fmt.Errorf("round number: %w", err)
		}

		return tlock.Encrypt(ctx, out, in, roundNumber, flags.Armor)
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

	if number, _, found := strings.Cut(duration, "d"); found {
		days, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse day duration: %w", err)
		}
		diff := now.AddDate(0, 0, days).Sub(now)
		return diff, nil
	}

	if number, _, found := strings.Cut(duration, "M"); found {
		months, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse month duration: %w", err)
		}
		diff := now.AddDate(0, months, 0).Sub(now)
		return diff, nil
	}

	if number, _, found := strings.Cut(duration, "y"); found {
		years, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse year duration: %w", err)
		}
		diff := now.AddDate(years, 0, 0).Sub(now)
		return diff, nil
	}

	return time.Second, fmt.Errorf("parse duration: %w", err)
}
