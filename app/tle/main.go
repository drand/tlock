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
	- Implement all the flags except armor.
	- Write network and chain hash to output.
	- Allow network override with flags
	- Add support for environment variables (kelsey envconfig)
	- Change output format to github.com/C2SP/C2SP/blob/main/age.md#encrypted-file-format

	- Write unit tests with container running network.
	- Write unit tests with some form of mocking for negative path.
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
	if err := commands.ValidateFlags(flags); err != nil {
		return err
	}

	var dataToEncrypt io.Reader = os.Stdin
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_RDONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		dataToEncrypt = f
	}

	var dst io.Writer = os.Stdout
	if name := flags.OutputFlag; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", name, err)
		}
		dst = f
	}

	switch {
	case flags.DecryptFlag:
		return commands.Decrypt(flags, dst, dataToEncrypt)
	default:
		return commands.Encrypt(flags, dst, dataToEncrypt)
	}
}

// parseFlags will parse all the command line flags. If any parse fails, the
// default behavior is to terminate the program.
func parseFlags() commands.Flags {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }

	var f commands.Flags

	flag.BoolVar(&f.EncryptFlag, "e", false, "encrypt the input to the output")
	flag.BoolVar(&f.EncryptFlag, "encrypt", false, "encrypt the input to the output")

	flag.BoolVar(&f.DecryptFlag, "d", false, "decrypt the input to the output")
	flag.BoolVar(&f.DecryptFlag, "decrypt", false, "decrypt the input to the output")

	flag.Var(&f.NetworkFlag, "n", "the drand API endpoint(s)")
	flag.Var(&f.NetworkFlag, "network", "the drand API endpoint(s)")

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

	if len(f.NetworkFlag) == 0 {
		f.NetworkFlag.Set("https://mainnet1-api.drand.cloudflare.com/")
		f.NetworkFlag.Set("https://api.drand.sh/")
	}

	return f
}
