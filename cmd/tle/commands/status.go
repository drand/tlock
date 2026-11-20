package commands

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age/armor"
	"github.com/drand/tlock/networks/http"
)

// StatusInfo contains information about an encrypted file
type StatusInfo struct {
	File          string
	RoundNumber   uint64
	ChainHash     string
	EncryptedAt   time.Time
	CanDecrypt    bool
	TimeRemaining time.Duration
	Error         error
}

// CheckStatus checks the encryption status of a file
func CheckStatus(flags Flags, network *http.Network) error {
	var inputFile string
	if len(os.Args) > 1 {
		inputFile = os.Args[len(os.Args)-1]
	} else {
		return fmt.Errorf("no input file specified")
	}

	status, err := getFileStatus(inputFile, network)
	if err != nil {
		return fmt.Errorf("failed to check status: %w", err)
	}

	if flags.Quiet {
		// In quiet mode, only output if there's an error
		if status.Error != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", status.Error)
			return status.Error
		}
		return nil
	}

	// Print status information
	fmt.Printf("File: %s\n", status.File)
	fmt.Printf("Round Number: %d\n", status.RoundNumber)
	fmt.Printf("Chain Hash: %s\n", status.ChainHash)
	fmt.Printf("Encrypted At: %s\n", status.EncryptedAt.Format(time.RFC3339))

	if status.CanDecrypt {
		fmt.Printf("Status: ✓ Ready to decrypt\n")
		if status.TimeRemaining > 0 {
			fmt.Printf("Time Remaining: %s\n", formatDuration(status.TimeRemaining))
		}
	} else {
		fmt.Printf("Status: ⏳ Not yet ready to decrypt\n")
		if status.TimeRemaining > 0 {
			fmt.Printf("Time Remaining: %s\n", formatDuration(status.TimeRemaining))
		}
	}

	if status.Error != nil {
		fmt.Printf("Error: %v\n", status.Error)
	}

	return status.Error
}

// getFileStatus extracts status information from an encrypted file
func getFileStatus(filename string, network *http.Network) (*StatusInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	status := &StatusInfo{
		File: filename,
	}

	// Check if file is armored
	reader := bufio.NewReader(file)
	header, err := reader.Peek(len(armor.Header))
	if err != nil {
		return nil, fmt.Errorf("failed to read file header: %w", err)
	}

	var src io.Reader
	if string(header) == armor.Header {
		src = armor.NewReader(reader)
	} else {
		src = reader
	}

	// Parse the age file to extract tlock stanzas
	// We need to manually parse the age file format since age.Parse doesn't exist
	// This is a simplified parser that looks for tlock stanzas

	// Read the file content to parse stanzas
	content, err := io.ReadAll(src)
	if err != nil {
		status.Error = fmt.Errorf("failed to read file content: %w", err)
		return status, nil
	}

	// Look for tlock stanzas in the content
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "-> tlock ") {
			// Parse the tlock stanza
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// Extract round number
				roundNumber, err := strconv.ParseUint(parts[1], 10, 64)
				if err != nil {
					status.Error = fmt.Errorf("failed to parse round number: %w", err)
					continue
				}

				status.RoundNumber = roundNumber
				status.ChainHash = parts[2]

				// Check if we can decrypt now
				currentRound := network.Current(time.Now())
				status.CanDecrypt = roundNumber <= currentRound

				// Calculate time remaining
				if !status.CanDecrypt {
					// Estimate time remaining based on network frequency
					// This is a rough estimate - actual time depends on network timing
					roundsRemaining := roundNumber - currentRound
					// Assuming 3 second intervals (this should be configurable)
					status.TimeRemaining = time.Duration(roundsRemaining) * 3 * time.Second
				}

				// Try to get more accurate timing from the network
				if roundNumber > currentRound {
					// Get the actual round time from the network
					if roundTime, err := getRoundTime(network, roundNumber); err == nil {
						now := time.Now()
						if roundTime.After(now) {
							status.TimeRemaining = roundTime.Sub(now)
						}
					}
				}

				// Set encrypted time (rough estimate)
				status.EncryptedAt = time.Now().Add(-status.TimeRemaining)

				return status, nil
			}
		}
	}

	status.Error = fmt.Errorf("no tlock stanzas found in file")
	return status, nil
}

// getRoundTime attempts to get the actual time for a round from the network
func getRoundTime(network *http.Network, roundNumber uint64) (time.Time, error) {
	// This is a simplified implementation
	// In practice, you'd need to query the network for round timing information
	currentRound := network.Current(time.Now())
	if roundNumber <= currentRound {
		// Round has already passed
		return time.Now(), nil
	}

	// Estimate based on network frequency
	// This should be replaced with actual network round timing
	roundsRemaining := roundNumber - currentRound
	estimatedTime := time.Now().Add(time.Duration(roundsRemaining) * 3 * time.Second)
	return estimatedTime, nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	} else if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%d minutes %d seconds", minutes, seconds)
	} else if d < 24*time.Hour {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%d hours %d minutes", hours, minutes)
	} else {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%d days %d hours", days, hours)
	}
}
