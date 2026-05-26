package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateToken generates a cryptographically secure random token.
// entropyBytes controls the number of random bytes (use 32 for 256-bit entropy).
// Returns the URL-safe base64-encoded token (no padding) and its SHA-256 hex hash.
func GenerateToken(entropyBytes int) (token, tokenHash string, err error) {
	if entropyBytes <= 0 {
		return "", "", fmt.Errorf("entropyBytes must be positive, got %d", entropyBytes)
	}

	tokenBytes := make([]byte, entropyBytes)
	if _, err = rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	token = base64.RawURLEncoding.EncodeToString(tokenBytes)

	sum := sha256.Sum256(tokenBytes)
	tokenHash = hex.EncodeToString(sum[:])

	return token, tokenHash, nil
}
