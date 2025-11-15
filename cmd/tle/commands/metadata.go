package commands

import (
	"bufio"
	"encoding/base64"
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
	// Only support armored input for metadata extraction in this change.
	if start, _ := rr.Peek(len(armor.Header)); string(start) != armor.Header {
		return fmt.Errorf("metadata from INPUT currently supports only armored age files")
	}
	// Read base64-encoded header block: try decoding each line until we find the tlock stanza.
	if _, err := rr.ReadString('\n'); err != nil { // BEGIN line
		return fmt.Errorf("read begin line: %w", err)
	}
	var round uint64
	var chainHash string
	found := false
	for {
		line, err := rr.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read armored content: %w", err)
		}
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "-----END ") {
			break
		}
		// Try to decode this line as base64
		dec, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			continue
		}
		decoded := string(dec)
		// Look for tlock stanza in this decoded line
		for _, line := range strings.Split(decoded, "\n") {
			line = strings.TrimSpace(line)
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
		if found {
			break
		}
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
