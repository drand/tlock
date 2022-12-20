package commands

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"time"

	"filippo.io/age/armor"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

var ErrInvalidDuration = errors.New("unsupported duration type - note: drand can only support as long as seconds")
var ErrInvalidDurationMultiplier = errors.New("errors must contain a multiplier, e.g. 1d not just d")

// Encrypt performs the encryption operation. This requires the implementation
// of an encoder for reading/writing to disk, a network for making calls to the
// drand network, and an encrypter for encrypting/decrypting the data.
func Encrypt(flags Flags, dst io.Writer, src io.Reader, network *http.Network) error {
	tlock := tlock.New(network)

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
		lastestAvailableRound := network.RoundNumber(time.Now())
		if flags.Round < lastestAvailableRound {
			return fmt.Errorf("round %d is in the past", flags.Round)
		}

		return tlock.Encrypt(dst, src, flags.Round)

	case flags.Duration != "":
		durations, err := parseDurations(flags.Duration)
		if err != nil {
			return err
		}
		decryptionTime := durations.from(time.Now())
		roundNumber := network.RoundNumber(decryptionTime)
		return tlock.Encrypt(dst, src, roundNumber)
	}

	return nil
}

type combinedDuration struct {
	seconds int
	minutes int
	hours   int
	weeks   int
	days    int
	months  int
	years   int
}

func (c *combinedDuration) apply(value int, multiplier DurationMultiplier) {
	switch multiplier {
	case Second:
		c.seconds = c.seconds + value
	case Minute:
		c.minutes = c.minutes + value
	case Hour:
		c.hours = c.hours + value
	case Day:
		c.days = c.days + value
	case Week:
		c.weeks = c.weeks + value
	case Month:
		c.months = c.months + value
	case Year:
		c.years = c.years + value
	}
}

func (c *combinedDuration) from(someTime time.Time) time.Time {
	return someTime.AddDate(
		c.years, c.months, c.days+(c.weeks*7),
	).Add(
		time.Duration(int64(c.minutes)) * time.Minute,
	).Add(
		time.Duration(int64(c.seconds)) * time.Second,
	)
}

func parseDurations(input string) (combinedDuration, error) {
	out := combinedDuration{}
	i := input
	for {
		if i == "" {
			return out, nil
		}

		ints, remainingInput, err := parsePrecedingInt(i)
		if ints == 0 || err != nil {
			return combinedDuration{}, ErrInvalidDurationMultiplier
		}

		duration, err := parseNextDuration(remainingInput)
		if err != nil {
			return combinedDuration{}, err
		}

		i = remainingInput[1:]
		out.apply(ints, duration)
	}
}

func parsePrecedingInt(input string) (int, string, error) {
	preceding := 0
	for i := 0; i < len(input); i++ {
		if input[i] < '0' || input[i] > '9' {
			return preceding, input[i:], nil
		}

		mantissa, err := strconv.Atoi(string(input[i]))
		if err != nil {
			return 0, input, err
		}
		exponent := int(math.Pow(float64(10), float64(i)))
		preceding = preceding + mantissa*exponent
	}
	return preceding, "", nil
}

type DurationMultiplier = int8

const (
	Second DurationMultiplier = iota
	Minute
	Hour
	Day
	Week
	Month
	Year
)

func parseNextDuration(input string) (DurationMultiplier, error) {
	if input == "" {
		return 0, ErrInvalidDuration
	}

	switch input[0] {
	case 'y':
		return Year, nil
	case 'M':
		return Month, nil
	case 'w':
		return Week, nil
	case 'd':
		return Day, nil
	case 'h':
		return Hour, nil
	case 'm':
		return Minute, nil
	case 's':
		return Second, nil
	default:
		return 0, ErrInvalidDuration
	}
}
