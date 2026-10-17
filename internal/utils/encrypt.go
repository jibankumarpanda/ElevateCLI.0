// Package util provides small, dependency-free helpers shared across packages.
package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var errEncrypt = errors.New("encryption failed")
var errDecrypt = errors.New("decryption failed")

// EncryptAESGCM encrypts plaintext using AES-256-GCM with the provided 32-byte key.
// It returns ciphertext prefixed with the 12-byte nonce (nonce||ciphertext).
func EncryptAESGCM(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes", errEncrypt)
	}
	if len(plaintext) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errEncrypt, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errEncrypt, err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", errEncrypt, err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	return out, nil
}

// DecryptAESGCM decrypts ciphertext produced by EncryptAESGCM (nonce||ciphertext)
// using the provided 32-byte key.
func DecryptAESGCM(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes", errDecrypt)
	}
	if len(ciphertext) == 0 {
		return nil, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecrypt, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecrypt, err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("%w: ciphertext too short", errDecrypt)
	}
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecrypt, err)
	}
	return plain, nil
}
