package commands

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"

	"github.com/drand/tlock/networks/http"
)

type CiphertextMetadata struct {
	Round     uint64    `yaml:"round"`
	ChainHash string    `yaml:"chain_hash"`
	Time      time.Time `yaml:"time"`
}

// Metadata reads INPUT from src and, if it contains a tlock stanza, outputs YAML with round, chainhash and estimated time.
func Metadata(dst io.Writer, src io.Reader, network *http.Network) error {
	rr := bufio.NewReader(src)

	// Use armor.NewReader to handle armor decoding automatically
	// Only support armored input for metadata extraction in this change.
	armorReader := armor.NewReader(rr)

	// Read from the de-armored content to find the tlock stanza
	scanner := bufio.NewScanner(armorReader)
	var round uint64
	var chainHash string
	found := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-> ") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[1] == "tlock" {
				r, err := strconv.ParseUint(fields[2], 10, 64)
				if err != nil {
					return fmt.Errorf("parse round: %w", err)
				}
				round = r
				chainHash = fields[3]
				found = true
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read armored content: %w", err)
	}

	if !found {
		return fmt.Errorf("no tlock stanza found in armored age header")
	}

	// Estimate time for the given round
	now := time.Now()
	current := network.Current(now)
	var low, high time.Time
	if round <= current {
		high = now
		low = now.Add(-365 * 24 * time.Hour)
	} else {
		low = now
		high = now.Add(365 * 24 * time.Hour)
	}

	t, err := roundToTimeBinarySearch(network, round, low, high)
	if err != nil {
		return fmt.Errorf("estimate time: %w", err)
	}

	out := CiphertextMetadata{Round: round, ChainHash: chainHash, Time: t}
	b, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("yaml marshal: %w", err)
	}
	if _, err := dst.Write(b); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// roundToTimeBinarySearch searches for a time whose round is the target.
func roundToTimeBinarySearch(network *http.Network, target uint64, low, high time.Time) (time.Time, error) {
	// If bounds are inverted, fix.
	if high.Before(low) {
		low, high = high, low
	}
	// Binary search with tolerance of 1 round.
	for i := 0; i < 64; i++ {
		mid := low.Add(high.Sub(low) / 2)
		r := network.RoundNumber(mid)
		if r == target {
			return mid, nil
		}
		if r < target {
			low = mid.Add(time.Second)
		} else {
			high = mid.Add(-time.Second)
		}
		if !high.After(low) {
			break
		}
	}
	// Best effort: return low as approximation.
	return low, nil
}

// parseArgs tries to extract round and chain from a tlock stanza arguments slice.
// (no other helpers)
