package commands

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/drand/tlock"
	"github.com/drand/tlock/encrypters/aead"
	"github.com/drand/tlock/networks/http"
)

// Encrypt performs the encryption operation.
func Encrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	var aead aead.AEAD
	network := http.New(flags.Network, flags.Chain)

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

		return tlock.EncryptWithRound(ctx, out, in, network, aead, flags.Round, flags.Armor)
	}

	if flags.Duration != "" {
		duration, err := parseDuration(flags.Duration)
		if err != nil {
			return fmt.Errorf("parse duration: %w", err)
		}
		fmt.Println("duration", duration)
		return tlock.EncryptWithDuration(ctx, out, in, network, aead, duration, flags.Armor)
	}

	return nil
}

// calculateDurationInHours parses the number and return the duration calculation
// in hours.
func calculateDurationInHours(number string, calc int) (time.Duration, error) {
	i, err := strconv.Atoi(number)
	if err != nil {
		return time.Second, fmt.Errorf("calculate duration: %w", err)
	}

	return time.Duration(i*calc) * time.Hour, nil
}

// parseDuration tries to parse the duration, also considering days, years and
// months
func parseDuration(duration string) (time.Duration, error) {
	d, err := time.ParseDuration(duration)
	if err != nil {

		// Check for a unit convertion error and try to parse.
		if strings.Contains(err.Error(), "unknown unit") {

			// We only accept d, m or y units.
			if !strings.ContainsAny(duration, "dMy") {
				return time.Second, fmt.Errorf("unknown unit")
			}

			// Days
			number, _, found := strings.Cut(duration, "d")
			if found {
				return calculateDurationInHours(number, 24)
			}

			// Months
			// Considering a month with 30 days
			number, _, found = strings.Cut(duration, "M")
			if found {
				return calculateDurationInHours(number, 24*30)

			}

			// Years
			// Considering a year with 365 days
			number, _, found = strings.Cut(duration, "y")
			if found {
				return calculateDurationInHours(number, 24*365)
			}
		}

		return time.Second, fmt.Errorf("parse duration: %w", err)
	}

	return d, nil
}

// Decrypt performs the decryption operation.
func Decrypt(ctx context.Context, flags Flags, out io.Writer, in io.Reader) error {
	var aead aead.AEAD
	network := http.New(flags.Network, flags.Chain)

	if err := tlock.Decrypt(ctx, out, in, network, aead); err != nil {
		return err
	}

	return nil
}
