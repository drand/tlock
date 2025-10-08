package commands

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ProgressWriter wraps an io.Writer to show progress for long operations
type ProgressWriter struct {
	writer    io.Writer
	total     int64
	written   int64
	lastPrint time.Time
	quiet     bool
	verbose   bool
}

// NewProgressWriter creates a new progress writer
func NewProgressWriter(writer io.Writer, total int64, quiet, verbose bool) *ProgressWriter {
	return &ProgressWriter{
		writer:    writer,
		total:     total,
		lastPrint: time.Now(),
		quiet:     quiet,
		verbose:   verbose,
	}
}

// Write implements io.Writer interface
func (pw *ProgressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.writer.Write(p)
	pw.written += int64(n)

	// Update progress display
	if !pw.quiet && time.Since(pw.lastPrint) > 500*time.Millisecond {
		pw.updateProgress()
		pw.lastPrint = time.Now()
	}

	return n, err
}

// updateProgress updates the progress display
func (pw *ProgressWriter) updateProgress() {
	if pw.total <= 0 {
		return
	}

	percentage := float64(pw.written) / float64(pw.total) * 100
	barWidth := 50
	filled := int(percentage / 100 * float64(barWidth))

	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)

	fmt.Fprintf(os.Stderr, "\r[%s] %.1f%% (%d/%d bytes)",
		bar, percentage, pw.written, pw.total)
}

// Finish completes the progress display
func (pw *ProgressWriter) Finish() {
	if !pw.quiet {
		fmt.Fprintf(os.Stderr, "\n")
	}
}

// ProgressBar represents a simple progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	quiet     bool
	verbose   bool
	startTime time.Time
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, quiet, verbose bool) *ProgressBar {
	return &ProgressBar{
		total:     total,
		width:     50,
		quiet:     quiet,
		verbose:   verbose,
		startTime: time.Now(),
	}
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
	pb.current = current
	if !pb.quiet {
		pb.display()
	}
}

// Increment increments the progress bar
func (pb *ProgressBar) Increment() {
	pb.current++
	if !pb.quiet {
		pb.display()
	}
}

// display shows the current progress
func (pb *ProgressBar) display() {
	if pb.total <= 0 {
		return
	}

	percentage := float64(pb.current) / float64(pb.total) * 100
	filled := int(percentage / 100 * float64(pb.width))

	bar := strings.Repeat("=", filled) + strings.Repeat("-", pb.width-filled)
	elapsed := time.Since(pb.startTime)

	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d (%.1f%%) - %v",
		bar, pb.current, pb.total, percentage, elapsed.Round(time.Second))
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	if !pb.quiet {
		elapsed := time.Since(pb.startTime)
		fmt.Fprintf(os.Stderr, "\nCompleted %d items in %v\n", pb.total, elapsed.Round(time.Second))
	}
}

// LogMessage logs a message with appropriate verbosity
func LogMessage(quiet, verbose bool, format string, args ...interface{}) {
	if quiet {
		return
	}

	if verbose {
		fmt.Printf("[VERBOSE] "+format+"\n", args...)
	} else {
		fmt.Printf(format+"\n", args...)
	}
}

// LogError logs an error message
func LogError(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	}
}

// LogWarning logs a warning message
func LogWarning(quiet bool, format string, args ...interface{}) {
	if !quiet {
		fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
	}
}
