package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/drand/tlock"
	"github.com/drand/tlock/cmd/commands"
	"github.com/drand/tlock/networks/http"
)

func main() {
	log := log.New(os.Stderr, "", 0)

	if len(os.Args) == 1 {
		commands.PrintUsage(log)
		return
	}

	if err := run(log); err != nil {
		switch {
		case errors.Is(err, tlock.ErrTooEarly):
			log.Fatal(tlock.ErrTooEarly)
		case errors.Is(err, http.ErrNotUnchained):
			log.Fatal(http.ErrNotUnchained)
		default:
			log.Fatal(err)
		}
	}
}

func run(log *log.Logger) error {
	flags, err := commands.Parse()
	if err != nil {
		return fmt.Errorf("parse commands: %v", err)
	}

	if len(flag.Args()) != 1 {
		return fmt.Errorf("expecing only one input but got %s", flag.Args())
	}

	var src io.Reader = os.Stdin
	if name := flag.Arg(0); name != "" && name != "-" {
		f, err := os.OpenFile(name, os.O_RDONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open input file %q: %v", name, err)
		}
		defer f.Close()
		src = f
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

	network, err := http.NewNetwork(flags.Network, flags.Chain)
	if err != nil {
		return err
	}

	switch {
	case flags.Decrypt:
		return tlock.NewDecrypter(network).Decrypt(dst, src)
	default:
		return commands.Encrypt(flags, dst, src, network)
	}
}
