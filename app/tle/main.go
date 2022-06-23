package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/drand/tlock/app/tle/commands"
)

/*
	- pair suite configuration
	- All the flags working in combinations
	- Add support for environment variables (kelsey envconfig)

	- Write unit tests with container running network.
	- Write unit tests with some form of mocking for negative path.
*/

// =============================================================================

func main() {
	log := log.New(os.Stderr, "", 0)

	if len(os.Args) == 1 {
		commands.PrintUsage(log)
		return
	}

	if err := run(log); err != nil {
		log.Fatal(err)
	}
}

func run(log *log.Logger) error {
	flags, err := commands.Parse()
	if err != nil {
		return err
	}
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
	if name := flags.Output; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		dst = f
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	switch {
	case flags.Decrypt:
		return commands.Decrypt(ctx, flags, dataToEncrypt)
	default:
		return commands.Encrypt(ctx, flags, dst, dataToEncrypt)
	}
}
