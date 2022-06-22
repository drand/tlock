package commands

import "fmt"

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
