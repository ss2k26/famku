package mysql

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"famku/internal/domain"
)

// Store groups the repositories; every method takes the request context so cancelled requests stop their queries.
type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Users() Users                   { return Users{s.db} }
func (s *Store) Sessions() Sessions             { return Sessions{s.db} }
func (s *Store) Tokens() Tokens                 { return Tokens{s.db} }
func (s *Store) Recovery() Recovery             { return Recovery{s.db} }
func (s *Store) AuditLog() Audit                { return Audit{s.db} }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func isDuplicate(err error) bool { // MySQL/MariaDB error 1062, without importing the driver here
	return err != nil && strings.Contains(err.Error(), "Error 1062")
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

// ---- users -------------------------------------------------------------------------------------

type Users struct{ db *sql.DB }

const userCols = "id, email, username, name, password_hash, email_verified_at, totp_secret, totp_enabled, totp_last_step, created_at, updated_at"

func scanUser(row interface{ Scan(...any) error }) (*domain.User, error) {
	var u domain.User
	var verified sql.NullTime
	if err := row.Scan(&u.ID, &u.Email, &u.Username, &u.Name, &u.PasswordHash, &verified, &u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastStep, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	if verified.Valid {
		t := verified.Time
		u.EmailVerifiedAt = &t
	}
	return &u, nil
}

func (r Users) Create(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Email, u.Username, u.Name, u.PasswordHash, nullTime(u.EmailVerifiedAt), u.TOTPSecret, u.TOTPEnabled, u.TOTPLastStep, u.CreatedAt.UTC(), u.UpdatedAt.UTC())
	if isDuplicate(err) {
		return domain.ErrConflict
	}
	return err
}

func (r Users) ByID(ctx context.Context, id string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (r Users) ByEmail(ctx context.Context, email string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, email))
}

func (r Users) ByUsername(ctx context.Context, username string) (*domain.User, error) {
	return scanUser(r.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
}

func (r Users) Update(ctx context.Context, u *domain.User) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET username=?, name=?, password_hash=?, email_verified_at=?, totp_secret=?, totp_enabled=?, totp_last_step=?, updated_at=? WHERE id=?`,
		u.Username, u.Name, u.PasswordHash, nullTime(u.EmailVerifiedAt), u.TOTPSecret, u.TOTPEnabled, u.TOTPLastStep, u.UpdatedAt.UTC(), u.ID)
	if isDuplicate(err) {
		return domain.ErrConflict
	}
	return err
}

// ---- sessions ----------------------------------------------------------------------------------

type Sessions struct{ db *sql.DB }

const sessCols = "id, user_id, token_hash, csrf_token, user_agent, ip, created_at, last_seen_at, expires_at"

func scanSession(row interface{ Scan(...any) error }) (*domain.Session, error) {
	var s domain.Session
	if err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &s.UserAgent, &s.IP, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &s, nil
}

func (r Sessions) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO sessions (`+sessCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		s.ID, s.UserID, s.TokenHash, s.CSRFToken, s.UserAgent, s.IP, s.CreatedAt.UTC(), s.LastSeenAt.UTC(), s.ExpiresAt.UTC())
	return err
}

func (r Sessions) ByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	return scanSession(r.db.QueryRowContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE token_hash = ?`, hash))
}

func (r Sessions) Touch(ctx context.Context, id string, seen time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, seen.UTC(), id)
	return err
}

func (r Sessions) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (r Sessions) DeleteByUser(ctx context.Context, userID, except string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id <> ?`, userID, except)
	return err
}

func (r Sessions) ListByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+sessCols+` FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r Sessions) DeleteExpired(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR last_seen_at < ?`, now.UTC(), now.Add(-idle).UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- one-time tokens ---------------------------------------------------------------------------

type Tokens struct{ db *sql.DB }

func (r Tokens) Create(ctx context.Context, t *domain.OneTimeToken) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO one_time_tokens (id, user_id, purpose, token_hash, expires_at, used_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		t.ID, t.UserID, string(t.Purpose), t.TokenHash, t.ExpiresAt.UTC(), nullTime(t.UsedAt), t.CreatedAt.UTC())
	return err
}

func (r Tokens) ByHash(ctx context.Context, p domain.TokenPurpose, hash string) (*domain.OneTimeToken, error) {
	var t domain.OneTimeToken
	var used sql.NullTime
	var purpose string
	err := r.db.QueryRowContext(ctx, `SELECT id, user_id, purpose, token_hash, expires_at, used_at, created_at FROM one_time_tokens WHERE purpose = ? AND token_hash = ?`,
		string(p), hash).Scan(&t.ID, &t.UserID, &purpose, &t.TokenHash, &t.ExpiresAt, &used, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Purpose = domain.TokenPurpose(purpose)
	if used.Valid {
		u := used.Time
		t.UsedAt = &u
	}
	return &t, nil
}

// MarkUsed is atomic: of two concurrent requests with the same token exactly one gets true.
func (r Tokens) MarkUsed(ctx context.Context, id string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE one_time_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`, at.UTC(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (r Tokens) DeleteByUser(ctx context.Context, userID string, p domain.TokenPurpose) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM one_time_tokens WHERE user_id = ? AND purpose = ?`, userID, string(p))
	return err
}

func (r Tokens) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM one_time_tokens WHERE expires_at < ?`, now.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- recovery codes ----------------------------------------------------------------------------

type Recovery struct{ db *sql.DB }

func (r Recovery) Replace(ctx context.Context, userID string, codes []*domain.RecoveryCode) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_codes (id, user_id, code_hash, used_at) VALUES (?,?,?,NULL)`, c.ID, c.UserID, c.CodeHash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r Recovery) Consume(ctx context.Context, userID, hash string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1`, at.UTC(), userID, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (r Recovery) CountUnused(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ---- audit -------------------------------------------------------------------------------------

type Audit struct{ db *sql.DB }

func (r Audit) Add(ctx context.Context, e *domain.AuditEvent) error {
	var uid any
	if e.UserID != "" {
		uid = e.UserID
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO audit_events (id, user_id, action, ip, user_agent, detail, created_at) VALUES (?,?,?,?,?,?,?)`,
		e.ID, uid, e.Action, e.IP, e.UserAgent, e.Detail, e.CreatedAt.UTC())
	return err
}
