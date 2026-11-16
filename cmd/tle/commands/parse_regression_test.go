package commands

import (
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func TestParseModes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		mode string
		err  string
	}{
		{name: "default duration", args: []string{"-D", "30s"}, mode: "default"},
		{name: "default round", args: []string{"-r", "123456"}, mode: "default"},
		{name: "default armored", args: []string{"-a", "-D", "30s"}, mode: "default"},
		{name: "explicit encrypt", args: []string{"-e", "-D", "30s"}, mode: "encrypt"},
		{name: "explicit decrypt", args: []string{"-d"}, mode: "decrypt"},
		{name: "explicit metadata", args: []string{"-m"}, mode: "metadata"},
		{name: "missing time", err: "-D/--duration or -r/--round must be specified"},
		{name: "both times", args: []string{"-D", "30s", "-r", "123456"}, err: "-D/--duration can't be used with -r/--round"},
		{name: "encrypt and decrypt", args: []string{"-e", "-d"}, err: "only one of"},
		{name: "encrypt and metadata", args: []string{"-e", "-m"}, err: "only one of"},
		{name: "decrypt and metadata", args: []string{"-d", "-m"}, err: "only one of"},
		{name: "all modes", args: []string{"-e", "-d", "-m"}, err: "only one of"},
		{name: "decrypt with duration", args: []string{"-d", "-D", "30s"}, err: "-D/--duration can't be used with -d/--decrypt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse owns the process-global flag set and reads TLE_* variables.
			// Keep these cases serial and restore both globals after each case.
			oldArgs, oldFlags := os.Args, flag.CommandLine
			t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
			os.Args = append([]string{"tle"}, tt.args...)
			flag.CommandLine = flag.NewFlagSet("tle", flag.ContinueOnError)
			flag.CommandLine.SetOutput(io.Discard)
			for key, value := range map[string]string{
				"TLE_ENCRYPT": "false", "TLE_DECRYPT": "false", "TLE_METADATA": "false",
				"TLE_FORCE": "false", "TLE_ARMOR": "false", "TLE_ROUND": "0",
				"TLE_DURATION": "", "TLE_OUTPUT": "", "TLE_NETWORK": DefaultNetwork, "TLE_CHAIN": DefaultChain,
			} {
				t.Setenv(key, value)
			}
			got, err := Parse()
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Parse(%v) error = %v, want %q", tt.args, err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%v): %v", tt.args, err)
			}
			if got.Encrypt != (tt.mode == "encrypt") || got.Decrypt != (tt.mode == "decrypt") || got.Metadata != (tt.mode == "metadata") {
				t.Fatalf("Parse(%v) modes = encrypt:%v decrypt:%v metadata:%v", tt.args, got.Encrypt, got.Decrypt, got.Metadata)
			}
		})
	}
}
