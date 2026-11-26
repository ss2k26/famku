// Package usecase holds the application rules. It depends only on the domain and on the small
// interfaces ("ports") declared here; databases, mailers, captcha services... implement them.
package usecase

import (
	"context"
	"time"

	"famku/internal/domain"
)

// ---- persistence ports -------------------------------------------------------------------------

type UserRepository interface {
	Create(ctx context.Context, u *domain.User) error // domain.ErrConflict when the email exists
	ByID(ctx context.Context, id string) (*domain.User, error)
	ByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, u *domain.User) error
}

type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	ByTokenHash(ctx context.Context, hash string) (*domain.Session, error)
	Touch(ctx context.Context, id string, seen time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, userID, exceptID string) error
	ListByUser(ctx context.Context, userID string) ([]*domain.Session, error)
	DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int64, error)
}

type TokenRepository interface {
	Create(ctx context.Context, t *domain.OneTimeToken) error
	ByHash(ctx context.Context, purpose domain.TokenPurpose, hash string) (*domain.OneTimeToken, error)
	// MarkUsed must succeed for exactly one caller (atomic); false = already used.
	MarkUsed(ctx context.Context, id string, at time.Time) (bool, error)
	DeleteByUser(ctx context.Context, userID string, purpose domain.TokenPurpose) error
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)
}

type RecoveryCodeRepository interface {
	Replace(ctx context.Context, userID string, codes []*domain.RecoveryCode) error
	// Consume marks the code used; false when unknown or already used (atomic).
	Consume(ctx context.Context, userID, codeHash string, at time.Time) (bool, error)
	CountUnused(ctx context.Context, userID string) (int, error)
}

type AuditRepository interface {
	Add(ctx context.Context, e *domain.AuditEvent) error
}

// ---- service ports -----------------------------------------------------------------------------

type PasswordHasher interface {
	Hash(password string) (string, error)
	// Verify reports a match and whether the stored hash uses outdated parameters.
	Verify(password, encoded string) (ok bool, needsRehash bool)
	// Dummy burns the same time as Verify (used for unknown accounts to hide their absence).
	Dummy(password string)
}

type TokenService interface {
	NewID() string
	NewToken() (token, hash string) // random secret + its stored digest
	Hash(token string) string
	NewRecoveryCode() string // e.g. ABCDE-FGHJK
}

type TOTP interface {
	NewSecret() (string, error)
	URI(issuer, account, secret string) string
	// Verify returns the matched time step (to refuse replays) and whether the code is valid.
	Verify(secret, code string, now time.Time) (step int64, ok bool)
}

type Mailer interface {
	SendPasswordReset(ctx context.Context, to, name, link string) error
	SendVerifyEmail(ctx context.Context, to, name, link string) error
}

type Captcha interface {
	Enabled() bool
	Verify(ctx context.Context, token, ip string) error // nil = human
}

// AttemptCounter counts failures per key inside a fixed window (in-memory or shared store).
type AttemptCounter interface {
	Failures(key string) (count int, resetIn time.Duration)
	Fail(key string, window time.Duration)
	Clear(key string)
}

type Clock interface{ Now() time.Time }

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// ClientMeta is what the delivery layer knows about the caller.
type ClientMeta struct{ IP, UserAgent string }
