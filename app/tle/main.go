package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/drand/tlock/app/tle/commands"
)

/*
	- Hardcoding default network values in parseFlag.

	* Integrate that code into main cli tooling.
		* Write encrypt and decrypt function.
		* Better flag validation.
	* Write basic unit tests and figure out best way to test.
*/

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

// =============================================================================

// multiFlag provides multi-flag value support.
type multiFlag []string

// String implements the flag.Value interface.
func (f *multiFlag) String() string {
	return fmt.Sprint(*f)
}

// Set implements the flag.Value interface. Pointer semantics are being
// used to support the mutation of the slice since length is unknown.
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// flags represent the values from the command line.
type flags struct {
	encryptFlag  bool
	decryptFlag  bool
	networkFlag  multiFlag
	chainFlag    string
	roundFlag    int
	durationFlag int
	outputFlag   string
	armorFlag    bool
}

// =============================================================================

func main() {
	log := log.New(os.Stderr, "", 0)

	if len(os.Args) == 1 {
		log.Println(usage)
		return
	}

	if err := run(log); err != nil {
		log.Fatal(err)
	}
}

func run(log *log.Logger) error {
	flags := parseFlags()
	if err := validateFlags(flags); err != nil {
		return err
	}

	var in io.Reader = os.Stdin
	var out io.Writer = os.Stdout

	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	}

	if name := flags.outputFlag; name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", name, err)
		}
		out = f
	}

	switch {
	case flags.decryptFlag:
		commands.Decrypt(in, out)
	default:
		commands.Encrypt(in, out, flags.armorFlag)
	}

	return nil
}

// parseFlags will parse all the command line flags. If any parse fails, the
// default behavior is to terminate the program.
func parseFlags() flags {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var f flags

	flag.BoolVar(&f.encryptFlag, "e", false, "encrypt the input to the output")
	flag.BoolVar(&f.encryptFlag, "encrypt", false, "encrypt the input to the output")

	flag.BoolVar(&f.decryptFlag, "d", false, "decrypt the input to the output")
	flag.BoolVar(&f.decryptFlag, "decrypt", false, "decrypt the input to the output")

	flag.Var(&f.networkFlag, "n", "the drand API endpoint(s)")
	flag.Var(&f.networkFlag, "network", "the drand API endpoint(s)")

	flag.StringVar(&f.chainFlag, "c", "", "chain to use")
	flag.StringVar(&f.chainFlag, "chain", "", "chain to use")

	flag.IntVar(&f.roundFlag, "r", 0, "the specific round to use; cannot be used with --duration")
	flag.IntVar(&f.roundFlag, "round", 0, "the specific round to use; cannot be used with --duration")

	flag.IntVar(&f.durationFlag, "D", 120, "how long to wait before being able to decrypt")
	flag.IntVar(&f.durationFlag, "duration", 120, "how long to wait before being able to decrypt")

	flag.StringVar(&f.outputFlag, "o", "", "the path to the output file")
	flag.StringVar(&f.outputFlag, "output", "", "the path to the output file")

	flag.BoolVar(&f.armorFlag, "a", false, "encrypt to a PEM encoded format")
	flag.BoolVar(&f.armorFlag, "armor", false, "encrypt to a PEM encoded format")

	flag.Parse()

	if len(f.networkFlag) == 0 {
		f.networkFlag.Set("https://mainnet1-api.drand.cloudflare.com/")
		f.networkFlag.Set("https://api.drand.sh/")
	}

	return f
}

// validateFlags performs a sanity check of the provided flag information.
func validateFlags(f flags) error {
	switch {
	case f.decryptFlag:
		if f.encryptFlag {
			return fmt.Errorf("-e/--encrypt can't be used with -d/--decrypt")
		}
		if f.armorFlag {
			return fmt.Errorf("-a/--armor can't be used with -d/--decrypt")
		}
		if f.durationFlag > 0 {
			return fmt.Errorf("-D/--duration can't be used with -d/--decrypt")
		}

	default:
		if f.durationFlag <= 0 {
			return fmt.Errorf("-D/--duration should be a number of days to allow decryption")
		}
	}

	if f.roundFlag < 0 {
		return fmt.Errorf("-r/--round should be a positive integer")
	}

	return nil
}
