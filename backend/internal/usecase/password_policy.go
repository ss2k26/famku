package usecase

import (
	"strings"
	"unicode/utf8"

	"famku/internal/domain"
)

const (
	MinPasswordLen = 12
	MaxPasswordLen = 128 // upper bound protects the hasher from huge inputs
)

// Common passwords that satisfy the length rule (NIST SP 800-63B: check against known-bad lists).
var commonPasswords = map[string]struct{}{}

func init() {
	for _, p := range strings.Fields(`
		123456789012 1234567890123 password1234 passwordpassword qwertyuiop12 qwertyuiopasdf 1q2w3e4r5t6y
		iloveyou1234 administrator letmein12345 welcome12345 changeme1234 abcdefghijkl abcd12345678
		111111111111 000000000000 123123123123 password12345 password123456 qwerty123456 asdfghjkl123
		zxcvbnm12345 trustno1trustno1 monkey123456 dragon123456 football1234 baseball1234 superman1234
		123456789abc a1b2c3d4e5f6 master123456 sunshine1234 princess1234 whatever1234 starwars1234
	`) {
		commonPasswords[p] = struct{}{}
	}
}

// ValidatePassword applies the policy: length, not a known-bad password, not derived from the account.
func ValidatePassword(password, email, name string) error {
	msg := ""
	n := utf8.RuneCountInString(password)
	lower := strings.ToLower(password)
	local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
	switch {
	case n < MinPasswordLen:
		msg = "use at least 12 characters (a few random words make a good passphrase)"
	case n > MaxPasswordLen:
		msg = "use at most 128 characters"
	case isCommon(lower):
		msg = "this password is too common"
	case len(local) >= 4 && strings.Contains(lower, local):
		msg = "do not use your email address in the password"
	case sameRune(password):
		msg = "do not repeat a single character"
	case strings.ContainsRune(password, 0):
		msg = "password contains invalid characters"
	}
	if msg != "" {
		return &domain.ValidationError{Fields: map[string]string{"password": msg}}
	}
	return nil
}

func isCommon(lower string) bool {
	_, ok := commonPasswords[lower]
	return ok
}

func sameRune(s string) bool {
	var first rune
	for i, r := range s {
		if i == 0 {
			first = r
		} else if r != first {
			return false
		}
	}
	return true
}
