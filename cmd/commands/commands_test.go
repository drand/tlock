package commands

import (
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
		{name: "parseDay", duration: "1d", date: time.Now(), expected: 24 * time.Hour, err: nil},
		{name: "parseMonth", duration: "1M", date: time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC), expected: time.Duration(31*24) * time.Hour, err: nil},
		{name: "parseYear", duration: "1y", date: time.Date(2022, 01, 01, 0, 0, 0, 0, time.UTC), expected: time.Duration(365*24) * time.Hour, err: nil},
		{name: "parseInvalid", duration: "1C", date: time.Now(), expected: time.Second, err: ErrInvalidDuration},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			duration, err := parseDuration(tc.date, tc.duration)
			if tc.err == nil && err != nil {
				t.Fatalf("unexpected parse error: %s", err)
			}

			if tc.err != nil && tc.err != err {
				t.Fatalf("expecting parsing error '%s'; got %v", ErrInvalidDuration, err)
			}

			if duration != tc.expected {
				t.Fatalf("expecting duration %s; go %s", tc.expected, duration)
			}

		})
	}
}
