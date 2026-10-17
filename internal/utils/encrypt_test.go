package util

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x2a}, 32)
	plain := []byte("super secret report body avec unicode → ✓")

	ct, err := EncryptAESGCM(key, plain)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := DecryptAESGCM(key, ct)
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plain)
	}
}

func TestEncryptNonceIsRandom(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	plain := []byte("same input")
	a, err := EncryptAESGCM(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptAESGCM(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("expected distinct nonces to produce distinct ciphertext")
	}
}

func TestEncryptRejectsBadKey(t *testing.T) {
	if _, err := EncryptAESGCM([]byte("short"), []byte("data")); err == nil {
		t.Fatal("expected error for key that is not 32 bytes")
	}
	if _, err := DecryptAESGCM([]byte("short"), []byte("data")); err == nil {
		t.Fatal("expected error for key that is not 32 bytes")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	ct, err := EncryptAESGCM(key, []byte("authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := DecryptAESGCM(key, ct); err == nil {
		t.Fatal("expected authentication failure for tampered ciphertext")
	}
}

func TestEncryptEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, 32)
	ct, err := EncryptAESGCM(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != 0 {
		t.Fatalf("expected empty ciphertext for empty input, got %d bytes", len(ct))
	}
}
