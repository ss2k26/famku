// Package security contains the cryptographic building blocks (password hashing, tokens, TOTP).
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params follow the OWASP Password Storage Cheat Sheet (Argon2id).
type Argon2Params struct {
	MemoryKiB   uint32 // m
	Iterations  uint32 // t
	Parallelism uint8  // p
	SaltLen     uint32
	KeyLen      uint32
	MaxParallel int // concurrent hashes: each one holds MemoryKiB of RAM
}

func DefaultArgon2() Argon2Params {
	return Argon2Params{MemoryKiB: 46 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32, MaxParallel: 2}
}

// Argon2Hasher implements usecase.PasswordHasher. An optional pepper (kept outside the database) is mixed
// in with HMAC-SHA256 before hashing, so a leaked database alone cannot be cracked offline.
type Argon2Hasher struct {
	p      Argon2Params
	pepper []byte
	sem    chan struct{}
	dummy  string
}

func NewArgon2Hasher(p Argon2Params, pepper string) *Argon2Hasher {
	if p.MaxParallel < 1 {
		p.MaxParallel = 1
	}
	h := &Argon2Hasher{p: p, pepper: []byte(pepper), sem: make(chan struct{}, p.MaxParallel)}
	h.dummy, _ = h.Hash("dummy-password-for-timing")
	return h
}

func (h *Argon2Hasher) prepare(password string) []byte {
	if len(h.pepper) == 0 {
		return []byte(password)
	}
	m := hmac.New(sha256.New, h.pepper)
	m.Write([]byte(password))
	return []byte(base64.RawStdEncoding.EncodeToString(m.Sum(nil)))
}

func (h *Argon2Hasher) key(pw, salt []byte, m, t uint32, par uint8, keyLen uint32) []byte {
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	return argon2.IDKey(pw, salt, t, m, par, keyLen)
}

func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := h.key(h.prepare(password), salt, h.p.MemoryKiB, h.p.Iterations, h.p.Parallelism, h.p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.p.MemoryKiB, h.p.Iterations, h.p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

func (h *Argon2Hasher) Verify(password, encoded string) (ok bool, needsRehash bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false
	}
	var version int
	var m, t uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &par); err != nil {
		return false, false
	}
	// refuse absurd parameters from a tampered row (memory/CPU exhaustion)
	if m < 8 || m > 1024*1024 || t < 1 || t > 10 || par < 1 || par > 16 {
		return false, false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) < 16 {
		return false, false
	}
	got := h.key(h.prepare(password), salt, m, t, par, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, m != h.p.MemoryKiB || t != h.p.Iterations || par != h.p.Parallelism
}

func (h *Argon2Hasher) Dummy(password string) { h.Verify(password, h.dummy) }
