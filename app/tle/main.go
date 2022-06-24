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

	var in io.Reader = os.Stdin
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_RDONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		in = f
	}

	var out io.Writer = os.Stdout
	if name := flags.Output; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", name, err)
		}
		defer f.Close()
		out = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch {
	case flags.Decrypt:
		return commands.Decrypt(ctx, flags, out, in)
	default:
		return commands.Encrypt(ctx, flags, out, in)
	}
}
