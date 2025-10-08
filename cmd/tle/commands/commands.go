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
	// DefaultNetwork is set to the HTTPs relay from drand, you can also use Cloudflare relay or any other relay.
	DefaultNetwork = "https://api.drand.sh/"
	// DefaultChain is set to the League of Entropy quicknet chainhash.
	DefaultChain = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
)

// =============================================================================

const usage = `tlock v1.4.0 -- github.com/drand/tlock

Usage:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]
	tle --decrypt [-o OUTPUT] [INPUT]
	tle --metadata
	tle --status [INPUT]
	tle --batch-encrypt [--input-dir DIR] [--output-dir DIR] [--pattern PATTERN]
	tle --batch-decrypt [--input-dir DIR] [--output-dir DIR] [--pattern PATTERN]

Options:
	-m, --metadata Displays the metadata of drand network in yaml format.
	-e, --encrypt  Encrypt the input to the output. Default if omitted.
	-d, --decrypt  Decrypt the input to the output.
	-s, --status   Check the encryption status and remaining time for a file.
	-n, --network  The drand API endpoint to use.
	-c, --chain    The chain to use. Can use either beacon ID name or beacon hash. Use beacon hash in order to ensure public key integrity.
	-r, --round    The specific round to use to encrypt the message. Cannot be used with --duration.
	-f, --force    Forces to encrypt against past rounds.
	-D, --duration How long to wait before the message can be decrypted.
	-o, --output   Write the result to the file at path OUTPUT.
	-a, --armor    Encrypt to a PEM encoded format.
	-v, --verbose  Enable verbose output with detailed progress information.
	-q, --quiet    Suppress all output except errors.
	--batch-encrypt Encrypt multiple files in a directory.
	--batch-decrypt Decrypt multiple files in a directory.
	--input-dir    Directory containing files to process (for batch operations).
	--output-dir   Directory to write processed files (for batch operations).
	--pattern      File pattern to match (e.g., "*.txt", "*.tle").

If the OUTPUT exists, it will be overwritten.

NETWORK defaults to the drand mainnet endpoint https://api.drand.sh/.

CHAIN defaults to the chainhash of quicknet:
52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971

You can also use the drand test network:
https://pl-us.testnet.drand.sh/
and its unchained network on G2 with chainhash 7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf
Note that if you encrypted something prior to March 2023, this was the only available network and used to be the default.

DURATION, when specified, expects a number followed by one of these units:
"ns", "us" (or "µs"), "ms", "s", "m", "h", "d", "M", "y".

Example:
    $ tle -D 10d -o encrypted_file data_to_encrypt

After the specified duration:
    $ tle -d -o decrypted_file.txt encrypted_file`

// PrintUsage displays the usage information.
func PrintUsage(log *log.Logger) {
	log.Println(usage)
}

// =============================================================================

// Flags represent the values from the command line.
type Flags struct {
	Encrypt      bool
	Decrypt      bool
	Status       bool
	BatchEncrypt bool
	BatchDecrypt bool
	Force        bool
	Network      string
	Chain        string
	Round        uint64
	Duration     string
	Output       string
	Armor        bool
	Metadata     bool
	Verbose      bool
	Quiet        bool
	InputDir     string
	OutputDir    string
	Pattern      string
}

// Parse will parse the environment variables and command line flags. The command
// line flags will overwrite environment variables. Validation takes place.
func Parse() (Flags, error) {
	f := Flags{
		Network: DefaultNetwork,
		Chain:   DefaultChain,
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
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	flag.BoolVar(&f.Encrypt, "e", f.Encrypt, "encrypt the input to the output")
	flag.BoolVar(&f.Encrypt, "encrypt", f.Encrypt, "encrypt the input to the output")

	flag.BoolVar(&f.Decrypt, "d", f.Decrypt, "decrypt the input to the output")
	flag.BoolVar(&f.Decrypt, "decrypt", f.Decrypt, "decrypt the input to the output")

	flag.BoolVar(&f.Status, "s", f.Status, "check the encryption status and remaining time")
	flag.BoolVar(&f.Status, "status", f.Status, "check the encryption status and remaining time")

	flag.BoolVar(&f.BatchEncrypt, "batch-encrypt", f.BatchEncrypt, "encrypt multiple files in a directory")
	flag.BoolVar(&f.BatchDecrypt, "batch-decrypt", f.BatchDecrypt, "decrypt multiple files in a directory")

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

	flag.StringVar(&f.Output, "o", f.Output, "the path to the output file")
	flag.StringVar(&f.Output, "output", f.Output, "the path to the output file")

	flag.BoolVar(&f.Armor, "a", f.Armor, "encrypt to a PEM encoded format")
	flag.BoolVar(&f.Armor, "armor", f.Armor, "encrypt to a PEM encoded format")

	flag.BoolVar(&f.Metadata, "m", f.Metadata, "get metadata about the drand network")
	flag.BoolVar(&f.Metadata, "metadata", f.Metadata, "get metadata about the drand network")

	flag.BoolVar(&f.Verbose, "v", f.Verbose, "enable verbose output with detailed progress information")
	flag.BoolVar(&f.Verbose, "verbose", f.Verbose, "enable verbose output with detailed progress information")

	flag.BoolVar(&f.Quiet, "q", f.Quiet, "suppress all output except errors")
	flag.BoolVar(&f.Quiet, "quiet", f.Quiet, "suppress all output except errors")

	flag.StringVar(&f.InputDir, "input-dir", f.InputDir, "directory containing files to process (for batch operations)")
	flag.StringVar(&f.OutputDir, "output-dir", f.OutputDir, "directory to write processed files (for batch operations)")
	flag.StringVar(&f.Pattern, "pattern", f.Pattern, "file pattern to match (e.g., *.txt, *.tle)")

	flag.Parse()
}

// validateFlags performs a sanity check of the provided flag information.
func validateFlags(f *Flags) error {
	// only one of the main operations must be true
	count := 0
	if f.Metadata {
		count++
	}
	if f.Encrypt {
		count++
	}
	if f.Decrypt {
		count++
	}
	if f.Status {
		count++
	}
	if f.BatchEncrypt {
		count++
	}
	if f.BatchDecrypt {
		count++
	}
	if count != 1 {
		return fmt.Errorf("only one of -m/--metadata, -d/--decrypt, -e/--encrypt, -s/--status, --batch-encrypt, or --batch-decrypt must be passed")
	}

	// Validate verbose and quiet are mutually exclusive
	if f.Verbose && f.Quiet {
		return fmt.Errorf("-v/--verbose and -q/--quiet cannot be used together")
	}
	switch {
	case f.Metadata:
		if f.Chain == "" {
			return fmt.Errorf("-c/--chain can't be the empty string")
		}
		if f.Network == "" {
			return fmt.Errorf("-n/--network can't be the empty string")
		}
	case f.Decrypt:
		if f.Duration != "" {
			return fmt.Errorf("-D/--duration can't be used with -d/--decrypt")
		}
		if f.Round != 0 {
			return fmt.Errorf("-r/--round can't be used with -d/--decrypt")
		}
		if f.Armor {
			return fmt.Errorf("-a/--armor can't be used with -d/--decrypt")
		}
		if f.Network != DefaultNetwork {
			if f.Chain == DefaultChain {
				fmt.Fprintf(os.Stderr,
					"You've specified a non-default network endpoint but still use the default chain hash.\n"+
						"You might want to also specify a custom chainhash with the -c/--chain flag.\n\n")
			}
		}
	case f.Status:
		if f.Duration != "" {
			return fmt.Errorf("-D/--duration can't be used with -s/--status")
		}
		if f.Round != 0 {
			return fmt.Errorf("-r/--round can't be used with -s/--status")
		}
		if f.Armor {
			return fmt.Errorf("-a/--armor can't be used with -s/--status")
		}
	case f.BatchEncrypt, f.BatchDecrypt:
		if f.InputDir == "" {
			return fmt.Errorf("--input-dir must be specified for batch operations")
		}
		if f.OutputDir == "" {
			return fmt.Errorf("--output-dir must be specified for batch operations")
		}
		if f.Duration == "" && f.Round == 0 && f.BatchEncrypt {
			return fmt.Errorf("-D/--duration or -r/--round must be specified for batch encryption")
		}
		if f.Duration != "" && f.Round != 0 && f.BatchEncrypt {
			return fmt.Errorf("-D/--duration can't be used with -r/--round")
		}
	default:
		if f.Chain == "" {
			fmt.Fprintf(os.Stderr, "-c/--chain is empty, will default to quicknet chainhash (%s).\n", DefaultChain)
		}
		if f.Duration != "" && f.Round != 0 {
			return fmt.Errorf("-D/--duration can't be used with -r/--round")
		}
		if f.Duration == "" && f.Round == 0 {
			return fmt.Errorf("-D/--duration or -r/--round must be specified")
		}
		if f.Network != DefaultNetwork {
			if f.Chain == DefaultChain {
				fmt.Fprintf(os.Stderr,
					"You've specified a non-default network endpoint but still use the default chain hash.\n"+
						"You might want to also specify a custom chainhash with the -c/--chain flag.\n\n")
			}
		}
	}

	return nil
}
