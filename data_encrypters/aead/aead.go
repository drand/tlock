// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package aead implements the Encrypter/Decrypter interfaces for the tlock package.
package aead

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// DataEncrypter provides the ability to encrypt data using the chacha20poly1305 algorithm.
type DataEncrypter struct{}

// Encrypt will encrypt the plain data using the specified key with the
// chacha20poly1305 algorithm.
func (DataEncrypter) Encrypt(key []byte, plainData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Having a null nonce is fine beause we're generating a new random
	// key for each encryption.
	nonce := make([]byte, chacha20poly1305.NonceSize)

	return aead.Seal(nil, nonce, plainData, nil), nil
}

// DataEncrypter provides the ability to decrypt data using the chacha20poly1305 algorithm.
type DataDecrypter struct{}

// Decrypt will decrypt the cipher data using the specified key with the
// chacha20poly1305 algorithm. Having a null nonce is fine beause we're
// generating a new random key for each encryption.
func (DataDecrypter) Decrypt(key []byte, cipherData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Having a null nonce is fine beause we're generating a new random
	// key for each encryption.
	nonce := make([]byte, chacha20poly1305.NonceSize)

	return aead.Open(nil, nonce, cipherData, nil)
}
