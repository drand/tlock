package drnd_test

import (
	_ "embed" // Calls init function.
	"testing"
)

var (
	//go:embed test_artifacts/decryptedFile.bin
	decryptedFile []byte

	//go:embed test_artifacts/encryptedFile.bin
	encryptedFile []byte
)

func Test_Decryption(t *testing.T) {
	// GIVEN encryptedFile GET decryptedFile
}
