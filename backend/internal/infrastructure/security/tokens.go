package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// Tokens implements usecase.TokenService with crypto/rand.
type Tokens struct{}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error()) // never continue with weak randomness
	}
	return b
}

func (Tokens) NewID() string { return hex.EncodeToString(randBytes(16)) }

// NewToken returns a 256-bit URL-safe secret and the digest that is stored instead of it.
func (t Tokens) NewToken() (string, string) {
	raw := base64.RawURLEncoding.EncodeToString(randBytes(32))
	return raw, t.Hash(raw)
}

func (Tokens) Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // 32 symbols, no 0/O/1/I

// NewRecoveryCode returns XXXXX-XXXXX (50 bits).
func (Tokens) NewRecoveryCode() string {
	b := randBytes(10)
	out := make([]byte, 0, 11)
	for i, x := range b {
		if i == 5 {
			out = append(out, '-')
		}
		out = append(out, recoveryAlphabet[int(x)&31])
	}
	return string(out)
}
