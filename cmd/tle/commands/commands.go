// Package commands implements the processing of the command line flags and
// processing of the encryption operation.
package commands

import (
	"flag"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	"log"
	"os"
)

// Default settings.
const (
	defaultNetwork = "https://api.drand.sh/"
	defaultChain   = "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
)

// =============================================================================

const usage = `tlock v1.0.0 -- github.com/drand/tlock

Usage:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]
If input is a string (not a file) 
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [--input INPUT]

	tle --decrypt [-o OUTPUT] [INPUT]

Options:
	-e, --encrypt    Encrypt the input to the output. Default if omitted.
	-d, --decrypt    Decrypt the input to the output.
	-n, --network    The drand API endpoint to use.
	-c, --chain      The chain to use. Can use either beacon ID name or beacon hash. Use beacon hash in order to ensure public key integrity.
	-r, --round      The specific round to use to encrypt the message. Cannot be used with --duration.
	-f, --force      Forces to encrypt against past rounds.
	-D, --duration   How long to wait before the message can be decrypted.
	-t, --time       Exact time (UTC) when the message can be decrypted
	-o, --output     Write the result to the file at path OUTPUT.
	-a, --armor      Encrypt to a PEM encoded format.
	-I, --input      Encrypt the input string to the output

If the OUTPUT exists, it will be overwritten.

NETWORK defaults to the drand mainnet endpoint https://api.drand.sh/.

CHAIN defaults to the chainhash of the fastnet network:
dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493

You can also use the drand test network:
https://pl-us.testnet.drand.sh/
and its unchained network with chain hash 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf
Note that if you encrypted something prior to March 2023, this was the only available network and used to be the default.

DURATION, when specified, expects a number followed by one of these units:
"ns", "us" (or "µs"), "ms", "s", "m", "h", "d", "M", "y".

Example:
    $ tle -D 10d -o encrypted_file data_to_encrypt

After the specified duration:
    $ tle -d -o dencrypted_file.txt encrypted_file`

// PrintUsage displays the usage information.
func PrintUsage(log *log.Logger) {
	log.Println(usage)
}

// =============================================================================

// Flags represent the values from the command line.
type Flags struct {
	Encrypt  bool
	Decrypt  bool
	Force    bool
	Network  string
	Chain    string
	Round    uint64
	Time     string
	Duration string
	Output   string
	RawInput string
	Armor    bool
}

// Parse will parse the environment variables and command line flags. The command
// line flags will overwrite environment variables. Validation takes place.
func Parse() (Flags, error) {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	f := Flags{
		Network: defaultNetwork,
		Chain:   defaultChain,
	}

	err := envconfig.Process("tle", &f)
	if err != nil {
		return f, err
	}
	parseCmdline(&f)

	if err := validateFlags(&f); err != nil {
		return Flags{}, err
	}

	return f, nil
}

// parseCmdline will parse all the command line flags.
// The default value is set to the values parsed by the environment variables.
func parseCmdline(f *Flags) {
	flag.BoolVar(&f.Encrypt, "e", f.Encrypt, "encrypt the input to the output")
	flag.BoolVar(&f.Encrypt, "encrypt", f.Encrypt, "encrypt the input to the output")

	flag.BoolVar(&f.Decrypt, "d", f.Decrypt, "decrypt the input to the output")
	flag.BoolVar(&f.Decrypt, "decrypt", f.Decrypt, "decrypt the input to the output")

	flag.BoolVar(&f.Force, "f", f.Force, "Forces to encrypt against past rounds")
	flag.BoolVar(&f.Force, "force", f.Force, "Forces to encrypt against past rounds.")

	flag.StringVar(&f.Network, "n", f.Network, "the drand API endpoint")
	flag.StringVar(&f.Network, "network", f.Network, "the drand API endpoint")

	flag.StringVar(&f.Chain, "c", f.Chain, "chain to use")
	flag.StringVar(&f.Chain, "chain", f.Chain, "chain to use")

	flag.Uint64Var(&f.Round, "r", f.Round, "the specific round to use; cannot be used with --duration")
	flag.Uint64Var(&f.Round, "round", f.Round, "the specific round to use; cannot be used with --duration")

	flag.StringVar(&f.Duration, "D", f.Duration, "how long to wait before being able to decrypt")
	flag.StringVar(&f.Duration, "duration", f.Duration, "how long to wait before being able to decrypt")

	flag.StringVar(&f.Time, "T", f.Time, "a UTC time value in RFC3339 format")
	flag.StringVar(&f.Time, "time", f.Time, "a UTC time value in RFC3339 format")

	flag.StringVar(&f.Output, "o", f.Output, "the path to the output file")
	flag.StringVar(&f.Output, "output", f.Output, "the path to the output file")

	flag.StringVar(&f.RawInput, "I", f.RawInput, "raw input to be encrypted")
	flag.StringVar(&f.RawInput, "input", f.RawInput, "raw input to be encrypted")

	flag.BoolVar(&f.Armor, "a", f.Armor, "encrypt to a PEM encoded format")
	flag.BoolVar(&f.Armor, "armor", f.Armor, "encrypt to a PEM encoded format")

	flag.Parse()
}

// validateFlags performs a sanity check of the provided flag information.
func validateFlags(f *Flags) error {
	switch {
	case f.Decrypt:
		if f.Encrypt {
			return fmt.Errorf("-e/--encrypt can't be used with -d/--decrypt")
		}
		if f.Duration != "" {
			return fmt.Errorf("-D/--duration can't be used with -d/--decrypt")
		}
		if f.Time != "" {
			return fmt.Errorf("-T/--time can't be used with -d/--decrypt")
		}
		if f.Round != 0 {
			return fmt.Errorf("-r/--round can't be used with -d/--decrypt")
		}
		if f.Armor {
			return fmt.Errorf("-a/--armor can't be used with -d/--decrypt")
		}
		if f.Network != defaultNetwork {
			if f.Chain == defaultChain {
				fmt.Fprintf(os.Stderr,
					"You've specified a non-default network endpoint but still use the default chain hash.\n"+
						"You might want to also specify a custom chainhash with the -c/--chain flag.\n\n")
			}
		}

	default:
		if f.Chain == "" {
			return fmt.Errorf("-c/--chain can't be empty")
		}
		if f.Duration == "" && f.Round == 0 && f.Time == "" {
			return fmt.Errorf("one of -D/--duration, -r/--round or -T/--time must be specified")
		}
		if f.Duration != "" && f.Round != 0 {
			return fmt.Errorf("-D/--duration can't be used with -r/--round")
		}
		if f.Duration != "" && f.Time != "" {
			return fmt.Errorf("-D/--duration can't be used with -T/--time")
		}
		if f.Time != "" && f.Round != 0 {
			return fmt.Errorf("-T/--time can't be used with -r/--round")
		}
		if f.Time != "" {
			duration, err := timestampToDuration(f.Time)
			if err != nil {
				return err
			}
			f.Duration = duration
		}
	}

	return nil
}
