package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProgressWriter(t *testing.T) {
	var buf bytes.Buffer

	// Test with total size
	pw := NewProgressWriter(&buf, 100, false, false)
	assert.Equal(t, int64(100), pw.total)
	assert.Equal(t, int64(0), pw.written)
	assert.False(t, pw.quiet)
	assert.False(t, pw.verbose)

	// Test writing
	n, err := pw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, int64(4), pw.written)

	// Test finish
	pw.Finish()
}

func TestProgressWriterQuiet(t *testing.T) {
	var buf bytes.Buffer

	// Test quiet mode
	pw := NewProgressWriter(&buf, 100, true, false)
	assert.True(t, pw.quiet)

	// Write some data
	n, err := pw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	// Finish should not output anything in quiet mode
	pw.Finish()
}

func TestProgressWriterVerbose(t *testing.T) {
	var buf bytes.Buffer

	// Test verbose mode
	pw := NewProgressWriter(&buf, 100, false, true)
	assert.True(t, pw.verbose)

	// Write some data
	n, err := pw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	// Finish
	pw.Finish()
}

func TestProgressBarCreation(t *testing.T) {
	// Test creation
	pb := NewProgressBar(10, false, false)
	assert.Equal(t, 0, pb.current)
	assert.Equal(t, 10, pb.total)
	assert.Equal(t, 50, pb.width)
	assert.False(t, pb.quiet)
	assert.False(t, pb.verbose)
	assert.NotZero(t, pb.startTime)

	// Test increment
	pb.Increment()
	assert.Equal(t, 1, pb.current)

	// Test update
	pb.Update(5)
	assert.Equal(t, 5, pb.current)

	// Test finish
	pb.Finish()
}

func TestProgressBarQuiet(t *testing.T) {
	// Test quiet mode
	pb := NewProgressBar(10, true, false)
	assert.True(t, pb.quiet)

	// Operations should not output anything in quiet mode
	pb.Increment()
	pb.Update(5)
	pb.Finish()
}

func TestProgressBarVerbose(t *testing.T) {
	// Test verbose mode
	pb := NewProgressBar(10, false, true)
	assert.True(t, pb.verbose)

	// Operations should work normally
	pb.Increment()
	pb.Update(5)
	pb.Finish()
}

func TestProgressBarEdgeCases(t *testing.T) {
	// Test with zero total
	pb := NewProgressBar(0, false, false)
	assert.Equal(t, 0, pb.total)

	// Test with negative current (should not happen in practice)
	pb.current = -1
	pb.Update(0)
	assert.Equal(t, 0, pb.current)

	// Test with current greater than total
	pb.Update(15)
	assert.Equal(t, 15, pb.current)
}

func TestLogMessageFunctions(t *testing.T) {
	// Test quiet mode - should not output anything
	LogMessage(true, false, "This should not appear")
	LogMessage(true, true, "This should not appear either")

	// Test verbose mode
	LogMessage(false, true, "This should appear with [VERBOSE] prefix")

	// Test normal mode
	LogMessage(false, false, "This should appear normally")
}

func TestLogErrorFunctions(t *testing.T) {
	// Test quiet mode - should not output anything
	LogError(true, "This error should not appear")

	// Test normal mode
	LogError(false, "This error should appear")
}

func TestLogWarningFunctions(t *testing.T) {
	// Test quiet mode - should not output anything
	LogWarning(true, "This warning should not appear")

	// Test normal mode
	LogWarning(false, "This warning should appear")
}

func TestProgressWriterWithZeroTotal(t *testing.T) {
	var buf bytes.Buffer

	// Test with zero total
	pw := NewProgressWriter(&buf, 0, false, false)

	// Write some data
	n, err := pw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	// Finish
	pw.Finish()
}

func TestProgressWriterWithLargeData(t *testing.T) {
	var buf bytes.Buffer

	// Test with large data
	pw := NewProgressWriter(&buf, 1000, false, false)

	// Write large data
	largeData := make([]byte, 500)
	n, err := pw.Write(largeData)
	assert.NoError(t, err)
	assert.Equal(t, 500, n)
	assert.Equal(t, int64(500), pw.written)

	// Finish
	pw.Finish()
}

func TestProgressBarWithZeroTotal(t *testing.T) {
	// Test with zero total
	pb := NewProgressBar(0, false, false)

	// Operations should work without panicking
	pb.Increment()
	pb.Update(0)
	pb.Finish()
}

func TestProgressBarWithOneItem(t *testing.T) {
	// Test with single item
	pb := NewProgressBar(1, false, false)

	// Increment to complete
	pb.Increment()
	assert.Equal(t, 1, pb.current)

	// Finish
	pb.Finish()
}
