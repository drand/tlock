package commands

import (
	"flag"
	"fmt"
	"log"
	"os"
)

const usage = `USAGE:
	tle [--encrypt] (-r round)... [--armor] [-o OUTPUT] [INPUT]

OPTIONS:
	-e, --encrypt Encrypt the input to the output. Default if omitted.
	-d, --decrypt Decrypt the input to the output, using the required drand rounds.
	-n, --network The drand API endpoint(s) to use. Default to https://mainnet1-api.drand.cloudflare.com/ and https://api.drand.sh/
	-c, --chain The chain to use. Can use either beacon ID name or beacon hash. Default to the chain hash of the "unchained" network. Use beacon hash in order to ensure public key integrity.
	-r, --round The specific round to use to encrypt the message. Cannot be used with --duration.
	-D, --duration How long to wait before the msg can be decrypted. Default to "120d", i.e. 120 days. Cannot be used with --round.
	-o, --output OUTPUT write the result to the file at path OUTPUT.
	-a, --armor Encrypt to a PEM encoded format.`

// PrintUsage displays the usage information.
func PrintUsage(log *log.Logger) {
	log.Println(usage)
}

// =============================================================================

// flags represent the values from the command line.
type Flags struct {
	EncryptFlag  bool
	DecryptFlag  bool
	NetworkFlag  string
	ChainFlag    string
	RoundFlag    int
	DurationFlag string
	OutputFlag   string
	ArmorFlag    bool
}

// ParseFlags will parse all the command line flags. If any parse fails, the
// default behavior is to terminate the program.
func ParseFlags() Flags {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var f Flags

	flag.BoolVar(&f.EncryptFlag, "e", false, "encrypt the input to the output")
	flag.BoolVar(&f.EncryptFlag, "encrypt", false, "encrypt the input to the output")

	flag.BoolVar(&f.DecryptFlag, "d", false, "decrypt the input to the output")
	flag.BoolVar(&f.DecryptFlag, "decrypt", false, "decrypt the input to the output")

	flag.StringVar(&f.NetworkFlag, "n", "", "the drand API endpoint")
	flag.StringVar(&f.NetworkFlag, "network", "", "the drand API endpoint")

	flag.StringVar(&f.ChainFlag, "c", "", "chain to use")
	flag.StringVar(&f.ChainFlag, "chain", "", "chain to use")

	flag.IntVar(&f.RoundFlag, "r", 0, "the specific round to use; cannot be used with --duration")
	flag.IntVar(&f.RoundFlag, "round", 0, "the specific round to use; cannot be used with --duration")

	flag.StringVar(&f.DurationFlag, "D", "", "how long to wait before being able to decrypt")
	flag.StringVar(&f.DurationFlag, "duration", "", "how long to wait before being able to decrypt")

	flag.StringVar(&f.OutputFlag, "o", "", "the path to the output file")
	flag.StringVar(&f.OutputFlag, "output", "", "the path to the output file")

	flag.BoolVar(&f.ArmorFlag, "a", false, "encrypt to a PEM encoded format")
	flag.BoolVar(&f.ArmorFlag, "armor", false, "encrypt to a PEM encoded format")

	flag.Parse()

	if f.NetworkFlag == "" {
		f.NetworkFlag = "https://mainnet1-api.drand.cloudflare.com/"
	}

	return f
}

// ValidateFlags performs a sanity check of the provided flag information.
func ValidateFlags(f Flags) error {
	switch {
	case f.DecryptFlag:
		if f.EncryptFlag {
			return fmt.Errorf("-e/--encrypt can't be used with -d/--decrypt")
		}
		if f.ArmorFlag {
			return fmt.Errorf("-a/--armor can't be used with -d/--decrypt")
		}
		if f.DurationFlag != "" {
			return fmt.Errorf("-D/--duration can't be used with -d/--decrypt")
		}
	}

	if f.RoundFlag < 0 {
		return fmt.Errorf("-r/--round should be a positive integer")
	}

	return nil
}
