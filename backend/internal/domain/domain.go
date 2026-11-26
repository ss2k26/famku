// Package domain holds the enterprise rules: entities, value objects and domain errors.
// It imports nothing from the other layers (dependencies point inwards only).
package domain

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- errors ------------------------------------------------------------------------------------

var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account temporarily locked")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrCaptchaRequired    = errors.New("captcha required")
	ErrCaptchaFailed      = errors.New("captcha verification failed")
	ErrTwoFactorRequired  = errors.New("two-factor code required")
	ErrInvalidTwoFactor   = errors.New("invalid two-factor code")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrRegistrationClosed = errors.New("registration is closed")
	ErrRateLimited        = errors.New("too many requests")
)

// ValidationError carries user-facing, field-level messages.
type ValidationError struct{ Fields map[string]string }

func (e *ValidationError) Error() string { return "validation failed" }

// ---- entities ----------------------------------------------------------------------------------

type User struct {
	ID              string
	Email           string // normalised (lower-case, trimmed)
	Name            string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	TOTPSecret      string // base32, empty = 2FA off
	TOTPEnabled     bool
	TOTPLastStep    int64 // last accepted 30s step: a code can be used once
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }

// Session is a server-side login. Only the SHA-256 of the cookie token is stored.
type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	CSRFToken  string
	UserAgent  string
	IP         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time // absolute lifetime
}

type TokenPurpose string

const (
	PurposePasswordReset TokenPurpose = "password_reset"
	PurposeVerifyEmail   TokenPurpose = "verify_email"
)

// OneTimeToken is a single-use emailed token (stored hashed).
type OneTimeToken struct {
	ID        string
	UserID    string
	Purpose   TokenPurpose
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// RecoveryCode is a single-use 2FA backup code (stored hashed).
type RecoveryCode struct {
	ID       string
	UserID   string
	CodeHash string
	UsedAt   *time.Time
}

type AuditEvent struct {
	ID        string
	UserID    string // may be empty (failed login for unknown user)
	Action    string
	IP        string
	UserAgent string
	Detail    string
	CreatedAt time.Time
}

// ---- value objects -----------------------------------------------------------------------------

// NormalizeEmail lower-cases and trims; it returns an error for anything that is not a plain address.
func NormalizeEmail(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || len(s) > 254 {
		return "", errors.New("enter a valid email address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", errors.New("enter a valid email address")
	}
	return s, nil
}

func ValidateName(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if n := utf8.RuneCountInString(s); n < 1 || n > 80 {
		return "", errors.New("name must be 1-80 characters")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("name contains invalid characters")
		}
	}
	return s, nil
}

// LockedError is returned while an account is in a login lock-out; it matches ErrAccountLocked.
type LockedError struct{ RetryAfter time.Duration }

func (e *LockedError) Error() string        { return ErrAccountLocked.Error() }
func (e *LockedError) Is(target error) bool { return target == ErrAccountLocked }
