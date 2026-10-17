package hash

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

const defaultCost = 12

// Hasher provides password hashing and verification.
type Hasher struct {
	cost int
}

// NewHasher creates a new Hasher with the given cost. If cost <= 0, uses default.
func NewHasher(cost int) *Hasher {
	if cost <= 0 {
		cost = defaultCost
	}
	return &Hasher{cost: cost}
}

// HashPassword hashes a plaintext password using bcrypt.
func (h *Hasher) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword compares a plaintext password against a bcrypt hash.
func (h *Hasher) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// SHA256Hash returns a hex-encoded SHA-256 hash of the input.
// Used for hashing refresh tokens for storage.
func SHA256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
