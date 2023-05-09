package commands

import (
	"flag"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

type KV struct {
	key   string
	value string
}

func Test(t *testing.T) {
	tests := []struct {
		name        string
		flags       []KV
		shouldError bool
	}{
		{
			name: "parsing encrypt fails without duration or round",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing encrypt with both duration and round fails",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
				{
					key:   "TLE_DURATION",
					value: "1d",
				},
				{
					key:   "TLE_ROUND",
					value: "1",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing encrypt with round passes",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
				{
					key:   "TLE_ROUND",
					value: "1",
				},
			},
			shouldError: false,
		},
		{
			name: "parsing encrypt with just duration passes",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
				{
					key:   "TLE_DURATION",
					value: "1d",
				},
			},
			shouldError: false,
		},
		{
			name: "parsing encrypt with duration and armor passes",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
				{
					key:   "TLE_DURATION",
					value: "1d",
				},
				{
					key:   "TLE_ARMOR",
					value: "true",
				},
			},
			shouldError: false,
		},
		{
			name: "parsing encrypt fails with decrypt",
			flags: []KV{
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
				{
					key:   "TLE_DURATION",
					value: "1d",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing decrypt fails with duration",
			flags: []KV{
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
				{
					key:   "TLE_DURATION",
					value: "1d",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing decrypt with round fails",
			flags: []KV{
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
				{
					key:   "TLE_ROUND",
					value: "1",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing decrypt with armor fails",
			flags: []KV{
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
				{
					key:   "TLE_ARMOR",
					value: "true",
				},
			},
			shouldError: true,
		},
		{
			name: "parsing decrypt alone passes",
			flags: []KV{
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
			},
			shouldError: false,
		},
		{
			name: "passing metadata flag",
			flags: []KV{
				{
					key:   "TLE_METADATA",
					value: "true",
				},
			},
			shouldError: false,
		},
		{
			name: "passing metadata flag along with encrypt",
			flags: []KV{
				{
					key:   "TLE_METADATA",
					value: "true",
				},
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
			},
			shouldError: true,
		},
		{
			name: "passing metadata flag along with decrypt",
			flags: []KV{
				{
					key:   "TLE_METADATA",
					value: "true",
				},
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
			},
			shouldError: true,
		},
		{
			name: "passing metadata flag along with decrypt and encrypt",
			flags: []KV{
				{
					key:   "TLE_METADATA",
					value: "true",
				},
				{
					key:   "TLE_DECRYPT",
					value: "true",
				},
				{
					key:   "TLE_ENCRYPT",
					value: "true",
				},
			},
			shouldError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, flag := range test.flags {
				f := flag
				require.NoError(t, os.Setenv(f.key, f.value))
			}

			_, err := Parse()
			if test.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			for _, flag := range test.flags {
				f := flag
				require.NoError(t, os.Unsetenv(f.key))
			}

			flag.CommandLine = flag.NewFlagSet("this seems to work with nonsense in it", 0)
		})
	}
}
