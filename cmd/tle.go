package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/drand/tlock"
	"github.com/drand/tlock/cmd/commands"
	"github.com/drand/tlock/encoders/base"
	"github.com/drand/tlock/encrypters/aead"
	"github.com/drand/tlock/networks/http"
)

/*
	- Write unit tests with test network.
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
		return fmt.Errorf("parse commands: %v", err)
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

	var encoder base.Encoder
	var encrypter aead.AEAD
	network := http.New(flags.Network, flags.Chain)

	switch {
	case flags.Decrypt:
		return tlock.Decrypt(ctx, out, in, encoder, network, encrypter)
	default:
		return commands.Encrypt(ctx, flags, out, in, encoder, network, encrypter)
	}
}
