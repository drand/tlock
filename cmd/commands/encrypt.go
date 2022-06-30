// Package commands implements the Encrypt function for the CLI.
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

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader, encoder tlock.Encoder, network tlock.Network, encrypter tlock.Encrypter) error {
	if flags.Round != 0 {
		client, err := network.Client(ctx)
		if err != nil {
			return fmt.Errorf("network client: %w", err)
		}

		// This will return the latest number for now.
		lastestRound := client.RoundAt(time.Now())

		// We have to make sure this round number is for the future.
		if flags.Round < lastestRound {
			return fmt.Errorf("round %d is not valid anymore", flags.Round)
		}

		return tlock.EncryptWithRound(ctx, out, in, encoder, network, encrypter, flags.Round, flags.Armor)
	}

	if flags.Duration != "" {
		duration, err := parseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}
		return tlock.EncryptWithDuration(ctx, out, in, encoder, network, encrypter, duration, flags.Armor)
	}

	return nil
}

// parseDuration tries to parse the duration, also considering days, months and
// years.
func parseDuration(duration string) (time.Duration, error) {
	d, err := time.ParseDuration(duration)
	if err == nil {
		return d, nil
	}

	// We only accept d, M or y units. M has to be capitalised to avoid conflict
	// with minutes.
	if !strings.ContainsAny(duration, "dMy") {
		return time.Second, fmt.Errorf("unknown unit")
	}

	currentTime := time.Now()

	// Check if there are days to parse.
	number, _, found := strings.Cut(duration, "d")
	if found {
		i, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse day duration: %w", err)
		}
		diff := currentTime.AddDate(0, 0, i).Sub(currentTime)
		return diff, nil
	}

	// Check if there are months to parse.
	number, _, found = strings.Cut(duration, "M")
	if found {
		i, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse month duration: %w", err)
		}
		diff := currentTime.AddDate(0, i, 0).Sub(currentTime)
		return diff, nil
	}

	// Check if there are years to parse.
	number, _, found = strings.Cut(duration, "y")
	if found {
		i, err := strconv.Atoi(number)
		if err != nil {
			return time.Second, fmt.Errorf("parse year duration: %w", err)
		}
		diff := currentTime.AddDate(i, 0, 0).Sub(currentTime)
		return diff, nil
	}

	return time.Second, fmt.Errorf("parse duration: %w", err)
}
