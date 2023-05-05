package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/drand/tlock"
	"github.com/drand/tlock/cmd/tle/commands"
	"github.com/drand/tlock/networks/http"
)

func main() {
	log := log.New(os.Stderr, "", 0)

	if len(os.Args) == 1 {
		commands.PrintUsage(log)
		return
	}

	if err := run(); err != nil {
		switch {
		case errors.Is(err, tlock.ErrTooEarly):
			log.Fatal(errors.Unwrap(err))
		case errors.Is(err, http.ErrNotUnchained):
			log.Fatal(http.ErrNotUnchained)
		default:
			log.Fatal(err)
		}
	}
}

func run() error {
	var err error

	flags, err := commands.Parse()
	if err != nil {
		return fmt.Errorf("parse commands: %v", err)
	}

	var src io.Reader = os.Stdin
	if rawInput := flags.RawInput; rawInput != "" && rawInput != "-" {
		src = strings.NewReader(rawInput)
	} else {
		if name := flag.Arg(0); name != "" && name != "-" {
			f, err := os.OpenFile(name, os.O_RDONLY, 0600)
			if err != nil {
				return fmt.Errorf("failed to open input file %q: %v", name, err)
			}
			defer func(f *os.File) {
				err = f.Close()
			}(f)
			src = f
		}
	}

	var dst io.Writer = os.Stdout
	if name := flags.Output; name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", name, err)
		}
		defer func(f *os.File) {
			err = f.Close()
		}(f)
		dst = f
	}

	network, err := http.NewNetwork(flags.Network, flags.Chain)
	if err != nil {
		return err
	}

	switch {
	case flags.Decrypt:
		err = tlock.New(network).Decrypt(dst, src)
	default:
		err = commands.Encrypt(flags, dst, src, network)
	}

	return err
}
