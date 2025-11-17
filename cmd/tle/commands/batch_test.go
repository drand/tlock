package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindMatchingFiles(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create test files
	files := []string{
		"test1.txt",
		"test2.txt",
		"test3.pdf",
		"subdir/test4.txt",
		"subdir/test5.doc",
	}

	for _, file := range files {
		filePath := filepath.Join(tempDir, file)
		// Create directory if needed
		dir := filepath.Dir(filePath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)

		// Create file
		f, err := os.Create(filePath)
		require.NoError(t, err)
		f.Close()
	}

	tests := []struct {
		name     string
		pattern  string
		expected int
	}{
		{
			name:     "no pattern - all files",
			pattern:  "",
			expected: 5,
		},
		{
			name:     "txt files only",
			pattern:  "*.txt",
			expected: 3,
		},
		{
			name:     "pdf files only",
			pattern:  "*.pdf",
			expected: 1,
		},
		{
			name:     "doc files only",
			pattern:  "*.doc",
			expected: 1,
		},
		{
			name:     "non-existent pattern",
			pattern:  "*.xyz",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := findMatchingFiles(tempDir, tt.pattern)
			require.NoError(t, err)
			assert.Len(t, files, tt.expected)
		})
	}
}

func TestBatchResult(t *testing.T) {
	result := BatchResult{
		File:     "test.txt",
		Success:  true,
		Error:    nil,
		Duration: 100 * time.Millisecond,
	}

	assert.Equal(t, "test.txt", result.File)
	assert.True(t, result.Success)
	assert.NoError(t, result.Error)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
}

func TestBatchFlagsValidation(t *testing.T) {
	tests := []struct {
		name        string
		flags       Flags
		expectError bool
	}{
		{
			name: "valid batch encrypt flags",
			flags: Flags{
				BatchEncrypt: true,
				InputDir:     "/input",
				OutputDir:    "/output",
				Duration:     "1h",
			},
			expectError: false,
		},
		{
			name: "valid batch decrypt flags",
			flags: Flags{
				BatchDecrypt: true,
				InputDir:     "/input",
				OutputDir:    "/output",
			},
			expectError: false,
		},
		{
			name: "missing input dir",
			flags: Flags{
				BatchEncrypt: true,
				OutputDir:    "/output",
				Duration:     "1h",
			},
			expectError: true,
		},
		{
			name: "missing output dir",
			flags: Flags{
				BatchEncrypt: true,
				InputDir:     "/input",
				Duration:     "1h",
			},
			expectError: true,
		},
		{
			name: "batch encrypt without duration or round",
			flags: Flags{
				BatchEncrypt: true,
				InputDir:     "/input",
				OutputDir:    "/output",
			},
			expectError: true,
		},
		{
			name: "verbose and quiet together",
			flags: Flags{
				Encrypt: true,
				Verbose: true,
				Quiet:   true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlags(&tt.flags)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
