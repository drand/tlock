package commands

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseDuration(t *testing.T) {
	type test struct {
		name     string
		duration string
		date     time.Time
		expected time.Duration
		err      error
	}

	tests := []test{
		{
			name:     "seconds are parsed correctly",
			duration: "1s",
			date:     time.Now(),
			expected: 1 * time.Second,
		},
		{
			name:     "hours are parsed correctly",
			duration: "1h",
			date:     time.Now(),
			expected: 1 * time.Hour,
		},
		{
			name:     "days are parsed correctly",
			duration: "1d",
			date:     time.Now(),
			expected: 24 * time.Hour,
		},
		{
			name:     "months are parsed correctly",
			duration: "1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: 31 * 24 * time.Hour,
		},
		{
			name:     "years are parsed correctly",
			duration: "1y",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: 365 * 24 * time.Hour,
		},
		{
			name:     "a mix of timespans parse successfully",
			duration: "1y1M1s",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: 365*24*time.Hour + 31*24*time.Hour + 1*time.Second,
		},
		{
			name:     "a mix of timespans in a funny order parse successfully",
			duration: "2s1y1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: 365*24*time.Hour + 31*24*time.Hour + 2*time.Second,
		},
		{
			name:     "times with multiple digits parse successfully",
			duration: "203m",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: 203 * time.Minute,
		},
		{
			name:     "parsing an invalid timespan character fails",
			duration: "1C",
			date:     time.Now(),
			err:      ErrInvalidDurationFormat,
		},
		{
			name:     "missing multipliers fails",
			duration: "DM",
			date:     time.Now(),
			err:      ErrInvalidDurationFormat,
		},
		{
			name:     "0 values are in the middle are allowed",
			duration: "4y0M1m",
			date:     time.Now(),
			// note that this will fail in 2096-2099 since 2100 is not a leap year
			expected: (4*365+1)*24*time.Hour + 1*time.Minute,
		},
		{
			name:     "total of 0 should also be fine",
			duration: "0s",
			date:     time.Now(),
			expected: 0 * time.Second,
		},
		{
			name:     "if characters are repeated, an error is returned",
			duration: "3s2s1d1s",
			date:     time.Now(),
			err:      ErrDuplicateDuration,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seconds, err := parseDurationsAsSeconds(tc.date, tc.duration)
			if tc.err == nil && err != nil {
				t.Fatalf("unexpected parse error: %s", err)
			}

			if tc.err != nil && tc.err != err {
				t.Fatalf("expecting parsing error '%s'; got %v", ErrInvalidDurationFormat, err)
			}

			expected := tc.date.Add(tc.expected)
			result := tc.date.Add(seconds)

			if !result.Equal(tc.date.Add(tc.expected)) {
				t.Fatalf("expecting end time %s; got %s", expected, result)
			}

		})
	}
}

func TestEncryptionWithDurationOverflow(t *testing.T) {
	flags := Flags{
		Encrypt:  true,
		Decrypt:  false,
		Network:  DefaultNetwork,
		Chain:    DefaultChain,
		Round:    0,
		Duration: "292277042628y",
		Armor:    false,
	}
	err := Encrypt(flags, os.Stdout, bytes.NewBufferString("very nice"), nil)
	require.ErrorIs(t, err, ErrInvalidDurationValue)
}

func TestEncryptionWithDurationOverflowUsingOtherUnits(t *testing.T) {
	flags := Flags{
		Encrypt:  true,
		Decrypt:  false,
		Network:  DefaultNetwork,
		Chain:    DefaultChain,
		Duration: "292277042627y12m1d",
		Armor:    false,
	}
	err := Encrypt(flags, os.Stdout, bytes.NewBufferString("very nice"), nil)
	require.ErrorIs(t, err, ErrInvalidDurationValue)
}
