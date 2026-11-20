package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drand/tlock"
	"github.com/drand/tlock/networks/http"
)

// BatchResult represents the result of a batch operation
type BatchResult struct {
	File     string
	Success  bool
	Error    error
	Duration time.Duration
}

// BatchEncrypt encrypts multiple files in a directory
func BatchEncrypt(flags Flags, network *http.Network) error {
	LogMessage(flags.Quiet, flags.Verbose, "Starting batch encryption in directory: %s", flags.InputDir)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(flags.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Find files matching the pattern
	files, err := findMatchingFiles(flags.InputDir, flags.Pattern)
	if err != nil {
		return fmt.Errorf("failed to find files: %w", err)
	}

	if len(files) == 0 {
		LogMessage(flags.Quiet, flags.Verbose, "No files found matching the pattern")
		return nil
	}

	LogMessage(flags.Quiet, flags.Verbose, "Found %d files to encrypt", len(files))

	// Process files
	results := make([]BatchResult, 0, len(files))
	successCount := 0

	// Create progress bar
	progressBar := NewProgressBar(len(files), flags.Quiet, flags.Verbose)

	for i, file := range files {
		start := time.Now()

		LogMessage(flags.Quiet, flags.Verbose, "Encrypting %d/%d: %s", i+1, len(files), file)

		result := BatchResult{File: file}

		// Determine output file path
		relPath, err := filepath.Rel(flags.InputDir, file)
		if err != nil {
			result.Error = fmt.Errorf("failed to get relative path: %w", err)
			results = append(results, result)
			continue
		}

		outputFile := filepath.Join(flags.OutputDir, relPath)

		// Add .tle extension if not present
		if !strings.HasSuffix(outputFile, ".tle") {
			outputFile += ".tle"
		}

		// Create output directory for this file
		if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
			result.Error = fmt.Errorf("failed to create output directory: %w", err)
			results = append(results, result)
			continue
		}

		// Encrypt the file
		if err := encryptFile(file, outputFile, flags, network); err != nil {
			result.Error = err
		} else {
			result.Success = true
			successCount++
		}

		result.Duration = time.Since(start)
		results = append(results, result)

		if result.Success {
			LogMessage(flags.Quiet, flags.Verbose, "✓ Encrypted %s in %v", file, result.Duration)
		} else {
			LogError(flags.Quiet, "Failed to encrypt %s: %v", file, result.Error)
		}

		// Update progress bar
		progressBar.Increment()
	}

	// Finish progress bar
	progressBar.Finish()

	// Print summary
	LogMessage(flags.Quiet, flags.Verbose, "Batch encryption completed: %d/%d files successful", successCount, len(files))

	if successCount < len(files) {
		LogMessage(flags.Quiet, flags.Verbose, "Failed files:")
		for _, result := range results {
			if !result.Success {
				LogError(flags.Quiet, "  %s: %v", result.File, result.Error)
			}
		}
	}

	return nil
}

// BatchDecrypt decrypts multiple files in a directory
func BatchDecrypt(flags Flags, network *http.Network) error {
	LogMessage(flags.Quiet, flags.Verbose, "Starting batch decryption in directory: %s", flags.InputDir)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(flags.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Find files matching the pattern
	files, err := findMatchingFiles(flags.InputDir, flags.Pattern)
	if err != nil {
		return fmt.Errorf("failed to find files: %w", err)
	}

	if len(files) == 0 {
		LogMessage(flags.Quiet, flags.Verbose, "No files found matching the pattern")
		return nil
	}

	LogMessage(flags.Quiet, flags.Verbose, "Found %d files to decrypt", len(files))

	// Process files
	results := make([]BatchResult, 0, len(files))
	successCount := 0

	// Create progress bar
	progressBar := NewProgressBar(len(files), flags.Quiet, flags.Verbose)

	for i, file := range files {
		start := time.Now()

		LogMessage(flags.Quiet, flags.Verbose, "Decrypting %d/%d: %s", i+1, len(files), file)

		result := BatchResult{File: file}

		// Determine output file path
		relPath, err := filepath.Rel(flags.InputDir, file)
		if err != nil {
			result.Error = fmt.Errorf("failed to get relative path: %w", err)
			results = append(results, result)
			continue
		}

		outputFile := filepath.Join(flags.OutputDir, relPath)

		// Remove .tle extension if present
		outputFile = strings.TrimSuffix(outputFile, ".tle")

		// Create output directory for this file
		if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
			result.Error = fmt.Errorf("failed to create output directory: %w", err)
			results = append(results, result)
			continue
		}

		// Decrypt the file
		if err := decryptFile(file, outputFile, network); err != nil {
			result.Error = err
		} else {
			result.Success = true
			successCount++
		}

		result.Duration = time.Since(start)
		results = append(results, result)

		if result.Success {
			LogMessage(flags.Quiet, flags.Verbose, "✓ Decrypted %s in %v", file, result.Duration)
		} else {
			LogError(flags.Quiet, "Failed to decrypt %s: %v", file, result.Error)
		}

		// Update progress bar
		progressBar.Increment()
	}

	// Finish progress bar
	progressBar.Finish()

	// Print summary
	LogMessage(flags.Quiet, flags.Verbose, "Batch decryption completed: %d/%d files successful", successCount, len(files))

	if successCount < len(files) {
		LogMessage(flags.Quiet, flags.Verbose, "Failed files:")
		for _, result := range results {
			if !result.Success {
				LogError(flags.Quiet, "  %s: %v", result.File, result.Error)
			}
		}
	}

	return nil
}

// findMatchingFiles finds files matching the given pattern in the directory
func findMatchingFiles(dir, pattern string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// If no pattern specified, include all files
		if pattern == "" {
			files = append(files, path)
			return nil
		}

		// Simple pattern matching (supports * wildcard)
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err != nil {
			return err
		}

		if matched {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// encryptFile encrypts a single file
func encryptFile(inputFile, outputFile string, flags Flags, network *http.Network) error {
	// Open input file
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer input.Close()

	// Create output file
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer output.Close()

	// Create tlock instance
	tlock := tlock.New(network)

	// Determine round number
	var roundNumber uint64
	if flags.Round != 0 {
		roundNumber = flags.Round
	} else if flags.Duration != "" {
		start := time.Now()
		totalDuration, err := parseDurationsAsSeconds(start, flags.Duration)
		if err != nil {
			return fmt.Errorf("failed to parse duration: %w", err)
		}
		decryptionTime := start.Add(totalDuration)
		roundNumber = network.RoundNumber(decryptionTime)
	} else {
		return fmt.Errorf("no round or duration specified")
	}

	// Encrypt the file
	return tlock.Encrypt(output, input, roundNumber)
}

// decryptFile decrypts a single file
func decryptFile(inputFile, outputFile string, network *http.Network) error {
	// Open input file
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer input.Close()

	// Create output file
	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer output.Close()

	// Create tlock instance
	tlock := tlock.New(network)

	// Decrypt the file
	return tlock.Decrypt(output, input)
}
