package commands

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"filippo.io/age/armor"
	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

var ErrInvalidDurationFormat = errors.New("unsupported duration type or malformed duration - note: drand can only support as short as seconds")
var ErrInvalidDurationValue = errors.New("the duration you entered is either in the past or was too large and would cause an overflow")

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
		if !flags.Force && flags.Round < lastestAvailableRound {
			return fmt.Errorf("round %d is in the past", flags.Round)
		}

		return tlock.Encrypt(dst, src, flags.Round)

	case flags.Duration != "":
		start := time.Now()
		totalDuration, err := parseDurationsAsSeconds(start, flags.Duration)
		if err != nil {
			return err
		}

		decryptionTime := start.Add(totalDuration)
		if decryptionTime.Before(start) || decryptionTime.Equal(start) {
			return ErrInvalidDurationValue
		}

		roundNumber := network.RoundNumber(decryptionTime)
		return tlock.Encrypt(dst, src, roundNumber)
	default:
		return errors.New("you must provide either duration or a round flag to encrypt")
	}
}

var ErrDuplicateDuration = errors.New("you cannot use the same duration unit specifier twice in one duration")

func parseDurationsAsSeconds(start time.Time, input string) (time.Duration, error) {
	timeUnits := "smhMdwy"

	// first we check that there are no extra characters or malformed groups
	valid, err := regexp.Compile(fmt.Sprintf("^([0-9]+[%s]{1})+$", timeUnits))
	if err != nil {
		return 0, err
	}
	if len(valid.FindAll([]byte(input), -1)) != 1 {
		return 0, ErrInvalidDurationFormat
	}

	// then we iterate through each duration unit and combine them into one
	totalDuration := time.Duration(0)
	for _, timeUnit := range timeUnits {
		r, err := regexp.Compile(fmt.Sprintf("[0-9]+%c", timeUnit))
		if err != nil {
			return 0, err
		}
		matches := r.FindAll([]byte(input), -1)
		if len(matches) > 1 {
			return 0, ErrDuplicateDuration
		}
		if len(matches) == 0 {
			continue
		}

		match := matches[0]
		durationLength, err := strconv.Atoi(string(match[0 : len(match)-1]))
		if err != nil {
			return 0, err
		}

		totalDuration += durationFrom(start, durationLength, timeUnit)
	}

	return totalDuration, nil
}

func durationFrom(start time.Time, value int, duration rune) time.Duration {
	switch duration {
	case 's':
		return time.Duration(value) * time.Second
	case 'm':
		return time.Duration(value) * time.Minute
	case 'h':
		return time.Duration(value) * time.Hour
	case 'd':
		return start.AddDate(0, 0, value).Sub(start)
	case 'w':
		return start.AddDate(0, 0, value*7).Sub(start)
	case 'M':
		return start.AddDate(0, value, 0).Sub(start)
	case 'y':
		return start.AddDate(value, 0, 0).Sub(start)
	}
	return 0
}

func timestampToDuration(timestamp string) (string, error) {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return "", fmt.Errorf("time format must be RFC3339 (\"2006-01-02T15:04:05Z07:00\")")
	}
	duration := time.Until(t)
	if duration <= 0 {
		return "", fmt.Errorf("must specify a future time")
	}
	return fmt.Sprintf("%ds", uint64(duration.Seconds())), nil
}
