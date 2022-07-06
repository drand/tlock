// Package commands implements the processing of the command line flags and
// processing of the encryption operation.
package commands

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kelseyhightower/envconfig"
)

// Default settings.
const (
	defaultNetwork  = "http://pl-us.testnet.drand.sh/"
	defaultChain    = "7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf"
	defaultDuration = "120d"
)

// =============================================================================

const usage = `
Usage:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]
	tle --decrypt [-o OUTPUT] [INPUT]

Options:
	-e, --encrypt  Encrypt the input to the output. Default if omitted.
	-d, --decrypt  Decrypt the input to the output.
	-n, --network  The drand API endpoint to use.
	-c, --chain    The chain to use. Can use either beacon ID name or beacon hash. Use beacon hash in order to ensure public key integrity.
	-r, --round    The specific round to use to encrypt the message. Cannot be used with --duration.
	-D, --duration How long to wait before the message can be decrypted. Defaults to 120d (120 days).
	-o, --output   Write the result to the file at path OUTPUT.
	-a, --armor    Encrypt using the PEM encoded format.

If the OUTPUT exists, it will be overwritten.

NETWORK defaults to the Drand test network http://pl-us.testnet.drand.sh/.

CHAIN defaults to the "unchained" hash in the default test network:
7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf

DURATION has a default value of 120d. When it is specified, it expects a number
followed by one of these units: "ns", "us" (or "µs"), "ms", "s", "m", "h", "d", "M", "y").

Example:
    $ ./tle -D 10d -o encrypted_file data_to_encrypt

After the specified duration:
    $ ./tle -d -o dencrypted_file.txt encrypted_file`

// PrintUsage displays the usage information.
func PrintUsage(log *log.Logger) {
	log.Println(usage)
}

// =============================================================================

// Flags represent the values from the command line.
type Flags struct {
	Encrypt  bool
	Decrypt  bool
	Network  string
	Chain    string
	Round    uint64
	Duration string
	Output   string
	Armor    bool
}

// Parse will parse the environment variables and command line flags. The command
// line flags will overwrite environment variables. Validation takes place.
func Parse() (Flags, error) {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	f := Flags{
		Network:  defaultNetwork,
		Chain:    defaultChain,
		Duration: defaultDuration,
	}

	envconfig.Process("tle", &f)
	parseCmdline(&f)

	if err := validateFlags(f); err != nil {
		return Flags{}, err
	}

	return f, nil
}

// parseCmdline will parse all the command line flags.
// The default value is set to the values parsed by the environment variables.
func parseCmdline(f *Flags) *Flags {
	flag.BoolVar(&f.Encrypt, "e", f.Encrypt, "encrypt the input to the output")
	flag.BoolVar(&f.Encrypt, "encrypt", f.Encrypt, "encrypt the input to the output")

	flag.BoolVar(&f.Decrypt, "d", f.Decrypt, "decrypt the input to the output")
	flag.BoolVar(&f.Decrypt, "decrypt", f.Decrypt, "decrypt the input to the output")

	flag.StringVar(&f.Network, "n", f.Network, "the drand API endpoint")
	flag.StringVar(&f.Network, "network", f.Network, "the drand API endpoint")

	flag.StringVar(&f.Chain, "c", f.Chain, "chain to use")
	flag.StringVar(&f.Chain, "chain", f.Chain, "chain to use")

	flag.Uint64Var(&f.Round, "r", f.Round, "the specific round to use; cannot be used with --duration")
	flag.Uint64Var(&f.Round, "round", f.Round, "the specific round to use; cannot be used with --duration")

	flag.StringVar(&f.Duration, "D", f.Duration, "how long to wait before being able to decrypt")
	flag.StringVar(&f.Duration, "duration", f.Duration, "how long to wait before being able to decrypt")

	flag.StringVar(&f.Output, "o", f.Output, "the path to the output file")
	flag.StringVar(&f.Output, "output", f.Output, "the path to the output file")

	flag.BoolVar(&f.Armor, "a", f.Armor, "encrypt to a PEM encoded format")
	flag.BoolVar(&f.Armor, "armor", f.Armor, "encrypt to a PEM encoded format")

	flag.Parse()

	return f
}

// validateFlags performs a sanity check of the provided flag information.
func validateFlags(f Flags) error {
	switch {
	case f.Decrypt:
		if f.Encrypt {
			return fmt.Errorf("-e/--encrypt can't be used with -d/--decrypt")
		}
		if f.Duration != defaultDuration {
			return fmt.Errorf("-D/--duration can't be used with -d/--decrypt")
		}
		if f.Armor {
			return fmt.Errorf("-a/--armor can't be used with -d/--decrypt")
		}

	default:
		if f.Chain == "" {
			return fmt.Errorf("-c/--chain can't be empty")
		}
		if f.Duration != defaultDuration && f.Round != 0 {
			return fmt.Errorf("-D/--duration can't be used with -r/--round")
		}
		if f.Duration == "" && f.Round == 0 {
			return fmt.Errorf("-D/--duration or -r/--round must be specified")
		}
	}

	return nil
}
