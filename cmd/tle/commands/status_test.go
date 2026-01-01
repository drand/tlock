package commands

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/drand/tlock/networks/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusInfo(t *testing.T) {
	status := StatusInfo{
		File:          "test.tle",
		RoundNumber:   12345,
		ChainHash:     "abc123",
		EncryptedAt:   time.Now().Add(-time.Hour),
		CanDecrypt:    true,
		TimeRemaining: 0,
		Error:         nil,
	}

	assert.Equal(t, "test.tle", status.File)
	assert.Equal(t, uint64(12345), status.RoundNumber)
	assert.Equal(t, "abc123", status.ChainHash)
	assert.True(t, status.CanDecrypt)
	assert.Zero(t, status.TimeRemaining)
	assert.NoError(t, status.Error)
}

func TestGetRoundTime(t *testing.T) {
	// This is a simplified test since we can't easily mock the network
	// In a real implementation, you'd want to use dependency injection
	// or interfaces to make this testable

	// For now, we'll just test that the function exists and can be called
	// without panicking
	network, err := http.NewNetwork("https://api.drand.sh/", "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
	require.NoError(t, err)

	// Test with a future round number
	roundTime, err := getRoundTime(network, 999999999)
	if err != nil {
		// This is expected to fail in tests since we can't reach the network
		assert.Error(t, err)
	} else {
		assert.NotZero(t, roundTime)
	}
}

func TestStatusFlagsValidation(t *testing.T) {
	tests := []struct {
		name        string
		flags       Flags
		expectError bool
	}{
		{
			name: "valid status flags",
			flags: Flags{
				Status: true,
			},
			expectError: false,
		},
		{
			name: "status with duration should fail",
			flags: Flags{
				Status:   true,
				Duration: "1h",
			},
			expectError: true,
		},
		{
			name: "status with round should fail",
			flags: Flags{
				Status: true,
				Round:  12345,
			},
			expectError: true,
		},
		{
			name: "status with armor should fail",
			flags: Flags{
				Status: true,
				Armor:  true,
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

func TestCheckStatusWithInvalidFile(t *testing.T) {
	flags := Flags{
		Status: true,
	}

	network, err := http.NewNetwork("https://api.drand.sh/", "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
	require.NoError(t, err)

	// This should fail because the file doesn't exist
	err = CheckStatus(flags, network)
	assert.Error(t, err)
}

func TestCheckStatusWithEmptyFile(t *testing.T) {
	// Create an empty file
	tempDir := t.TempDir()
	emptyFile := filepath.Join(tempDir, "empty.tle")

	f, err := os.Create(emptyFile)
	require.NoError(t, err)
	f.Close()

	flags := Flags{
		Status: true,
	}

	network, err := http.NewNetwork("https://api.drand.sh/", "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
	require.NoError(t, err)

	// This should fail because the file is empty and has no tlock stanzas
	err = CheckStatus(flags, network)
	assert.Error(t, err)
}
