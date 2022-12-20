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
			name:     "parseDay",
			duration: "1d",
			date:     time.Now(),
			expected: 24 * time.Hour,
			err:      nil,
		},
		{
			name:     "parseMonth",
			duration: "1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(31*24) * time.Hour,
			err:      nil,
		},
		{
			name:     "parseYear",
			duration: "1y",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24) * time.Hour,
			err:      nil,
		},
		{
			name:     "parseMixed",
			duration: "1y1M1s",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24)*time.Hour + time.Duration(31*24)*time.Hour + time.Duration(1)*time.Second,
			err:      nil,
		},
		{
			name:     "parseMixedInAFunnyOrder",
			duration: "2s1y1M",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(365*24)*time.Hour + time.Duration(31*24)*time.Hour + time.Duration(2)*time.Second,
			err:      nil,
		},
		{
			name:     "multiDigitParsesCorrectly",
			duration: "203m",
			date:     time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC),
			expected: time.Duration(203) * time.Minute,
			err:      nil,
		},
		{
			name:     "parseInvalid",
			duration: "1C",
			date:     time.Now(),
			err:      ErrInvalidDuration,
		},
		{
			name:     "parseMissingMultiplier",
			duration: "DM",
			date:     time.Now(),
			err:      ErrInvalidDurationMultiplier,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			durations, err := parseDurations(tc.duration)
			if tc.err == nil && err != nil {
				t.Fatalf("unexpected parse error: %s", err)
			}

			if tc.err != nil && tc.err != err {
				t.Fatalf("expecting parsing error '%s'; got %v", ErrInvalidDuration, err)
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
	require.ErrorIs(t, err, ErrDurationOverflow)
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
	require.ErrorIs(t, err, ErrDurationOverflow)
}
