// Copyright 2019 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package aead implements the Encrypter and Decrypter interfaces for the
// drnd package.
package aead

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD provides an implementation of the aead.
type AEAD struct{}

// Encrypt will encrypt the plain data using the specified key with the
// chacha20poly1305 algorithm.
func (AEAD) Encrypt(key []byte, plainData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Seal(nil, nonce, plainData, nil), nil
}

// Decrypt will decrypt the cipher data using the specified key with the
// chacha20poly1305 algorithm.
func (AEAD) Decrypt(key []byte, cipherData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	return aead.Open(nil, nonce, cipherData, nil)
}
