package commands

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func Test_ParseDuration(t *testing.T) {
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
			name:     "days are parsed correctly",
			duration: "1d",
			date:     time.Now(),
			expected: 24 * time.Hour,
		},
		{
			name:     "months are parsed correctly",
			duration: "1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(31*24) * time.Hour,
		},
		{
			name:     "years are parsed correctly",
			duration: "1y",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24) * time.Hour,
		},
		{
			name:     "a mix of timespans parse successfuly",
			duration: "1y1M1s",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24)*time.Hour + time.Duration(31*24)*time.Hour + time.Duration(1)*time.Second,
		},
		{
			name:     "a mix of timespans in a funny order parse successfully",
			duration: "2s1y1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24)*time.Hour + time.Duration(31*24)*time.Hour + time.Duration(2)*time.Second,
		},
		{
			name:     "times with multiple digits parse successfully",
			duration: "203m",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(203) * time.Minute,
		},
		{
			name:     "parsing an invalid timespan character fails",
			duration: "1C",
			date:     time.Now(),
			err:      ErrInvalidDurationType,
		},
		{
			name:     "missing multipliers fails",
			duration: "DM",
			date:     time.Now(),
			err:      ErrInvalidDurationMultiplier,
		},
		{
			name:     "0 values are in the middle are allowed",
			duration: "1y0M1m",
			date:     time.Now(),
			expected: time.Duration(365*24)*time.Hour + time.Duration(1)*time.Minute,
		},
		{
			name:     "total of 0 should also be fine",
			duration: "0s",
			date:     time.Now(),
			expected: 0 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			durations, err := parseDurations(tc.duration)
			if tc.err == nil && err != nil {
				t.Fatalf("unexpected parse error: %s", err)
			}

			if tc.err != nil && tc.err != err {
				t.Fatalf("expecting parsing error '%s'; got %v", ErrInvalidDurationType, err)
			}

			expected := tc.date.Add(tc.expected)
			result := durations.from(tc.date)

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
		Network:  defaultNetwork,
		Chain:    defaultChain,
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
		Network:  defaultNetwork,
		Chain:    defaultChain,
		Duration: "292277042627y12m1d",
		Armor:    false,
	}
	err := Encrypt(flags, os.Stdout, bytes.NewBufferString("very nice"), nil)
	require.ErrorIs(t, err, ErrInvalidDurationValue)
}
