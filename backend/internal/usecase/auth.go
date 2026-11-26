package usecase

import (
	"context"
	"errors"
	"strings"
	"time"

	"famku/internal/domain"
)

// Audit actions.
const (
	ActRegister      = "register"
	ActLoginOK       = "login_ok"
	ActLoginFail     = "login_failed"
	ActLogout        = "logout"
	ActPasswordSet   = "password_changed"
	ActPasswordReset = "password_reset"
	ActEmailVerified = "email_verified"
	Act2FAEnabled    = "2fa_enabled"
	Act2FADisabled   = "2fa_disabled"
	ActSessionRevoke = "session_revoked"
)

type AuthConfig struct {
	BaseURL              string // public URL used in emails, e.g. https://famku.example.com
	Issuer               string // shown in authenticator apps
	RegistrationOpen     bool
	RequireVerifiedEmail bool
	CaptchaMode          string // off | adaptive | always
	CaptchaAfterFailures int    // adaptive: show captcha after this many failures
	LockAfterFailures    int    // hard lock of one account
	LockDuration         time.Duration
	SessionIdle          time.Duration
	SessionAbsolute      time.Duration
	ResetTTL             time.Duration
	VerifyTTL            time.Duration
}

type Deps struct {
	Users    UserRepository
	Sessions SessionRepository
	OneTime  TokenRepository
	Recovery RecoveryCodeRepository
	Audit    AuditRepository
	Hasher   PasswordHasher
	Crypto   TokenService
	TOTP     TOTP
	Mailer   Mailer
	Captcha  Captcha
	Attempts AttemptCounter
	Clock    Clock
}

type Auth struct {
	Deps
	Cfg AuthConfig
	// Async runs fire-and-forget work (sending mail) so response time does not reveal whether an account exists.
	Async func(func())
}

func NewAuth(d Deps, cfg AuthConfig) *Auth {
	if d.Clock == nil {
		d.Clock = SystemClock{}
	}
	return &Auth{Deps: d, Cfg: cfg, Async: func(f func()) { go f() }}
}

// ---- inputs / results --------------------------------------------------------------------------

type RegisterInput struct {
	Name, Email, Password, CaptchaToken string
	Meta                                ClientMeta
}

type LoginInput struct {
	Email, Password, CaptchaToken string
	TOTPCode, RecoveryCode        string
	Meta                          ClientMeta
}

type LoginResult struct {
	User    *domain.User
	Session *domain.Session
	Token   string // raw session token: goes into the cookie, never stored
}

// ---- registration ------------------------------------------------------------------------------

// Register creates an account. With RequireVerifiedEmail an existing address is answered exactly like a new one
// (nil user, nil error) and the owner is told by email, so the form cannot be used to discover accounts.
func (s *Auth) Register(ctx context.Context, in RegisterInput) (*domain.User, error) {
	if !s.Cfg.RegistrationOpen {
		return nil, domain.ErrRegistrationClosed
	}
	if err := s.checkCaptcha(ctx, s.Cfg.CaptchaMode != "off", in.CaptchaToken, in.Meta.IP); err != nil {
		return nil, err
	}
	fields := map[string]string{}
	name, err := domain.ValidateName(in.Name)
	if err != nil {
		fields["name"] = err.Error()
	}
	email, err := domain.NormalizeEmail(in.Email)
	if err != nil {
		fields["email"] = err.Error()
	}
	if len(fields) == 0 {
		if perr := ValidatePassword(in.Password, email, name); perr != nil {
			var ve *domain.ValidationError
			if errors.As(perr, &ve) {
				fields = ve.Fields
			}
		}
	}
	if len(fields) > 0 {
		return nil, &domain.ValidationError{Fields: fields}
	}
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now()
	u := &domain.User{ID: s.Crypto.NewID(), Email: email, Name: name, PasswordHash: hash, CreatedAt: now, UpdatedAt: now}
	if err := s.Users.Create(ctx, u); err != nil {
		if errors.Is(err, domain.ErrConflict) && s.Cfg.RequireVerifiedEmail {
			return nil, nil // same answer as success
		}
		return nil, err
	}
	s.audit(ctx, u.ID, ActRegister, in.Meta, "")
	if s.Cfg.RequireVerifiedEmail {
		s.sendVerification(ctx, u)
	}
	return u, nil
}

// ---- login -------------------------------------------------------------------------------------

func (s *Auth) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	email, emailErr := domain.NormalizeEmail(in.Email)
	acctKey, ipKey := "login:acct:"+email, "login:ip:"+in.Meta.IP
	if emailErr != nil {
		acctKey = "login:acct:invalid"
	}
	fa, resetA := s.Attempts.Failures(acctKey)
	fi, _ := s.Attempts.Failures(ipKey)

	if fa >= s.Cfg.LockAfterFailures || fi >= s.Cfg.LockAfterFailures*3 {
		return nil, &domain.LockedError{RetryAfter: resetA}
	}
	if s.Cfg.CaptchaMode == "always" || (s.Cfg.CaptchaMode == "adaptive" && (fa >= s.Cfg.CaptchaAfterFailures || fi >= s.Cfg.CaptchaAfterFailures)) {
		if err := s.checkCaptcha(ctx, true, in.CaptchaToken, in.Meta.IP); err != nil {
			return nil, err
		}
	}

	fail := func(userID, detail string) {
		s.Attempts.Fail(acctKey, s.Cfg.LockDuration)
		s.Attempts.Fail(ipKey, s.Cfg.LockDuration)
		s.audit(ctx, userID, ActLoginFail, in.Meta, detail)
	}

	var u *domain.User
	if emailErr == nil {
		var err error
		u, err = s.Users.ByEmail(ctx, email)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, err
		}
	}
	if u == nil {
		s.Hasher.Dummy(in.Password) // same cost as a real check: no timing oracle
		fail("", "unknown account")
		return nil, domain.ErrInvalidCredentials
	}
	ok, rehash := s.Hasher.Verify(in.Password, u.PasswordHash)
	if !ok {
		fail(u.ID, "bad password")
		return nil, domain.ErrInvalidCredentials
	}
	if s.Cfg.RequireVerifiedEmail && !u.EmailVerified() {
		return nil, domain.ErrEmailNotVerified
	}

	now := s.Clock.Now()
	if u.TOTPEnabled {
		switch {
		case in.TOTPCode != "":
			step, valid := s.TOTP.Verify(u.TOTPSecret, in.TOTPCode, now)
			if !valid || step <= u.TOTPLastStep {
				fail(u.ID, "bad 2fa code")
				return nil, domain.ErrInvalidTwoFactor
			}
			u.TOTPLastStep = step
		case in.RecoveryCode != "":
			used, err := s.Recovery.Consume(ctx, u.ID, s.Crypto.Hash(normalizeRecovery(in.RecoveryCode)), now)
			if err != nil {
				return nil, err
			}
			if !used {
				fail(u.ID, "bad recovery code")
				return nil, domain.ErrInvalidTwoFactor
			}
		default:
			return nil, domain.ErrTwoFactorRequired
		}
	}

	s.Attempts.Clear(acctKey) // not the IP key: one login must not wipe a guessing counter shared with other accounts
	if rehash {
		if h, err := s.Hasher.Hash(in.Password); err == nil {
			u.PasswordHash = h
		}
	}
	if rehash || u.TOTPEnabled {
		u.UpdatedAt = now
		if err := s.Users.Update(ctx, u); err != nil {
			return nil, err
		}
	}

	token, tokenHash := s.Crypto.NewToken()
	csrf, _ := s.Crypto.NewToken()
	sess := &domain.Session{
		ID: s.Crypto.NewID(), UserID: u.ID, TokenHash: tokenHash, CSRFToken: csrf,
		UserAgent: clip(in.Meta.UserAgent, 255), IP: in.Meta.IP,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.Cfg.SessionAbsolute),
	}
	if err := s.Sessions.Create(ctx, sess); err != nil {
		return nil, err
	}
	s.audit(ctx, u.ID, ActLoginOK, in.Meta, "")
	return &LoginResult{User: u, Session: sess, Token: token}, nil
}

// Authenticate resolves a session cookie. Idle and absolute timeouts are enforced here.
func (s *Auth) Authenticate(ctx context.Context, rawToken string) (*domain.User, *domain.Session, error) {
	if rawToken == "" {
		return nil, nil, domain.ErrUnauthenticated
	}
	sess, err := s.Sessions.ByTokenHash(ctx, s.Crypto.Hash(rawToken))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, domain.ErrUnauthenticated
		}
		return nil, nil, err
	}
	now := s.Clock.Now()
	if now.After(sess.ExpiresAt) || now.After(sess.LastSeenAt.Add(s.Cfg.SessionIdle)) {
		_ = s.Sessions.Delete(ctx, sess.ID)
		return nil, nil, domain.ErrUnauthenticated
	}
	u, err := s.Users.ByID(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil, domain.ErrUnauthenticated
		}
		return nil, nil, err
	}
	if now.Sub(sess.LastSeenAt) > time.Minute {
		_ = s.Sessions.Touch(ctx, sess.ID, now)
		sess.LastSeenAt = now
	}
	return u, sess, nil
}

func (s *Auth) Logout(ctx context.Context, sess *domain.Session, meta ClientMeta) error {
	s.audit(ctx, sess.UserID, ActLogout, meta, "")
	return s.Sessions.Delete(ctx, sess.ID)
}

func (s *Auth) ListSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.Sessions.ListByUser(ctx, userID)
}

// RevokeSession ends one of the caller's own sessions (ownership is checked).
func (s *Auth) RevokeSession(ctx context.Context, userID, sessionID string, meta ClientMeta) error {
	list, err := s.Sessions.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, x := range list {
		if x.ID == sessionID {
			s.audit(ctx, userID, ActSessionRevoke, meta, "")
			return s.Sessions.Delete(ctx, sessionID)
		}
	}
	return domain.ErrNotFound
}

// LogoutOthers ends every session except the current one.
func (s *Auth) LogoutOthers(ctx context.Context, userID, keepID string) error {
	return s.Sessions.DeleteByUser(ctx, userID, keepID)
}

// ---- account -----------------------------------------------------------------------------------

func (s *Auth) UpdateProfile(ctx context.Context, userID, rawName string) (*domain.User, error) {
	name, err := domain.ValidateName(rawName)
	if err != nil {
		return nil, &domain.ValidationError{Fields: map[string]string{"name": err.Error()}}
	}
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	u.Name, u.UpdatedAt = name, s.Clock.Now()
	return u, s.Users.Update(ctx, u)
}

func (s *Auth) ChangePassword(ctx context.Context, userID, keepSessionID, current, next string, meta ClientMeta) error {
	key := "chpw:" + userID
	if n, reset := s.Attempts.Failures(key); n >= 5 {
		return &domain.LockedError{RetryAfter: reset}
	}
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return err
	}
	if ok, _ := s.Hasher.Verify(current, u.PasswordHash); !ok {
		s.Attempts.Fail(key, 15*time.Minute)
		return &domain.ValidationError{Fields: map[string]string{"current_password": "current password is incorrect"}}
	}
	if err := ValidatePassword(next, u.Email, u.Name); err != nil {
		return err
	}
	if next == current {
		return &domain.ValidationError{Fields: map[string]string{"password": "choose a different password"}}
	}
	if u.PasswordHash, err = s.Hasher.Hash(next); err != nil {
		return err
	}
	u.UpdatedAt = s.Clock.Now()
	if err := s.Users.Update(ctx, u); err != nil {
		return err
	}
	s.Attempts.Clear(key)
	s.audit(ctx, u.ID, ActPasswordSet, meta, "")
	return s.Sessions.DeleteByUser(ctx, u.ID, keepSessionID) // everyone else is logged out
}

// ---- password reset / email verification -------------------------------------------------------

// RequestPasswordReset never reveals whether the address exists; mail is sent in the background.
func (s *Auth) RequestPasswordReset(ctx context.Context, rawEmail, captchaToken string, meta ClientMeta) error {
	if err := s.checkCaptcha(ctx, s.Cfg.CaptchaMode != "off", captchaToken, meta.IP); err != nil {
		return err
	}
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		return nil
	}
	key := "reset:" + email
	if n, _ := s.Attempts.Failures(key); n >= 3 { // at most 3 mails / hour / address
		return nil
	}
	s.Attempts.Fail(key, time.Hour)
	u, err := s.Users.ByEmail(ctx, email)
	if err != nil {
		return nil
	}
	raw, hash := s.Crypto.NewToken()
	now := s.Clock.Now()
	_ = s.OneTime.DeleteByUser(ctx, u.ID, domain.PurposePasswordReset)
	if err := s.OneTime.Create(ctx, &domain.OneTimeToken{ID: s.Crypto.NewID(), UserID: u.ID, Purpose: domain.PurposePasswordReset,
		TokenHash: hash, ExpiresAt: now.Add(s.Cfg.ResetTTL), CreatedAt: now}); err != nil {
		return err
	}
	link := strings.TrimRight(s.Cfg.BaseURL, "/") + "/reset-password#token=" + raw
	s.Async(func() {
		s.mail(func(c context.Context) error { return s.Mailer.SendPasswordReset(c, u.Email, u.Name, link) })
	})
	return nil
}

func (s *Auth) ResetPassword(ctx context.Context, rawToken, newPassword string, meta ClientMeta) error {
	t, err := s.loadToken(ctx, domain.PurposePasswordReset, rawToken)
	if err != nil {
		return err
	}
	u, err := s.Users.ByID(ctx, t.UserID)
	if err != nil {
		return domain.ErrInvalidToken
	}
	if err := ValidatePassword(newPassword, u.Email, u.Name); err != nil {
		return err // token not consumed: the user can try again
	}
	if used, err := s.OneTime.MarkUsed(ctx, t.ID, s.Clock.Now()); err != nil {
		return err
	} else if !used {
		return domain.ErrInvalidToken
	}
	if u.PasswordHash, err = s.Hasher.Hash(newPassword); err != nil {
		return err
	}
	now := s.Clock.Now()
	if u.EmailVerifiedAt == nil { // the mail reached them, so the address is theirs
		u.EmailVerifiedAt = &now
	}
	u.UpdatedAt = now
	if err := s.Users.Update(ctx, u); err != nil {
		return err
	}
	s.Attempts.Clear("login:acct:" + u.Email)
	s.audit(ctx, u.ID, ActPasswordReset, meta, "")
	return s.Sessions.DeleteByUser(ctx, u.ID, "")
}

func (s *Auth) VerifyEmail(ctx context.Context, rawToken string, meta ClientMeta) error {
	t, err := s.loadToken(ctx, domain.PurposeVerifyEmail, rawToken)
	if err != nil {
		return err
	}
	if used, err := s.OneTime.MarkUsed(ctx, t.ID, s.Clock.Now()); err != nil {
		return err
	} else if !used {
		return domain.ErrInvalidToken
	}
	u, err := s.Users.ByID(ctx, t.UserID)
	if err != nil {
		return domain.ErrInvalidToken
	}
	now := s.Clock.Now()
	u.EmailVerifiedAt, u.UpdatedAt = &now, now
	s.audit(ctx, u.ID, ActEmailVerified, meta, "")
	return s.Users.Update(ctx, u)
}

func (s *Auth) ResendVerification(ctx context.Context, rawEmail, captchaToken string, meta ClientMeta) error {
	if err := s.checkCaptcha(ctx, s.Cfg.CaptchaMode != "off", captchaToken, meta.IP); err != nil {
		return err
	}
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		return nil
	}
	key := "verify:" + email
	if n, _ := s.Attempts.Failures(key); n >= 3 {
		return nil
	}
	s.Attempts.Fail(key, time.Hour)
	if u, err := s.Users.ByEmail(ctx, email); err == nil && !u.EmailVerified() {
		s.sendVerification(ctx, u)
	}
	return nil
}

// ---- two-factor (TOTP) -------------------------------------------------------------------------

type TwoFactorSetup struct{ Secret, URI string }

func (s *Auth) BeginTwoFactor(ctx context.Context, userID string) (*TwoFactorSetup, error) {
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.TOTPEnabled {
		return nil, domain.ErrConflict
	}
	secret, err := s.TOTP.NewSecret()
	if err != nil {
		return nil, err
	}
	u.TOTPSecret, u.UpdatedAt = secret, s.Clock.Now()
	if err := s.Users.Update(ctx, u); err != nil {
		return nil, err
	}
	return &TwoFactorSetup{Secret: secret, URI: s.TOTP.URI(s.Cfg.Issuer, u.Email, secret)}, nil
}

// EnableTwoFactor confirms the first code and returns the one-time recovery codes (shown once).
func (s *Auth) EnableTwoFactor(ctx context.Context, userID, code string, meta ClientMeta) ([]string, error) {
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.TOTPEnabled || u.TOTPSecret == "" {
		return nil, domain.ErrConflict
	}
	step, ok := s.TOTP.Verify(u.TOTPSecret, code, s.Clock.Now())
	if !ok {
		return nil, domain.ErrInvalidTwoFactor
	}
	u.TOTPEnabled, u.TOTPLastStep, u.UpdatedAt = true, step, s.Clock.Now()
	if err := s.Users.Update(ctx, u); err != nil {
		return nil, err
	}
	s.audit(ctx, u.ID, Act2FAEnabled, meta, "")
	return s.newRecoveryCodes(ctx, u.ID)
}

func (s *Auth) DisableTwoFactor(ctx context.Context, userID, password, code string, meta ClientMeta) error {
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return err
	}
	if ok, _ := s.Hasher.Verify(password, u.PasswordHash); !ok {
		return &domain.ValidationError{Fields: map[string]string{"password": "password is incorrect"}}
	}
	if u.TOTPEnabled {
		step, ok := s.TOTP.Verify(u.TOTPSecret, code, s.Clock.Now())
		if !ok || step <= u.TOTPLastStep {
			return domain.ErrInvalidTwoFactor
		}
	}
	u.TOTPSecret, u.TOTPEnabled, u.TOTPLastStep, u.UpdatedAt = "", false, 0, s.Clock.Now()
	if err := s.Users.Update(ctx, u); err != nil {
		return err
	}
	s.audit(ctx, u.ID, Act2FADisabled, meta, "")
	return s.Recovery.Replace(ctx, u.ID, nil)
}

func (s *Auth) RegenerateRecoveryCodes(ctx context.Context, userID, password string) ([]string, error) {
	u, err := s.Users.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !u.TOTPEnabled {
		return nil, domain.ErrConflict
	}
	if ok, _ := s.Hasher.Verify(password, u.PasswordHash); !ok {
		return nil, &domain.ValidationError{Fields: map[string]string{"password": "password is incorrect"}}
	}
	return s.newRecoveryCodes(ctx, userID)
}

// ---- housekeeping ------------------------------------------------------------------------------

func (s *Auth) Cleanup(ctx context.Context) {
	now := s.Clock.Now()
	_, _ = s.Sessions.DeleteExpired(ctx, now, s.Cfg.SessionIdle)
	_, _ = s.OneTime.DeleteExpired(ctx, now)
}

// ---- helpers -----------------------------------------------------------------------------------

func (s *Auth) checkCaptcha(ctx context.Context, required bool, token, ip string) error {
	if !required || s.Captcha == nil || !s.Captcha.Enabled() {
		return nil
	}
	if token == "" {
		return domain.ErrCaptchaRequired
	}
	if err := s.Captcha.Verify(ctx, token, ip); err != nil {
		return domain.ErrCaptchaFailed
	}
	return nil
}

func (s *Auth) loadToken(ctx context.Context, purpose domain.TokenPurpose, raw string) (*domain.OneTimeToken, error) {
	if raw == "" || len(raw) > 256 {
		return nil, domain.ErrInvalidToken
	}
	t, err := s.OneTime.ByHash(ctx, purpose, s.Crypto.Hash(raw))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrInvalidToken
		}
		return nil, err
	}
	if t.UsedAt != nil || s.Clock.Now().After(t.ExpiresAt) {
		return nil, domain.ErrInvalidToken
	}
	return t, nil
}

func (s *Auth) sendVerification(ctx context.Context, u *domain.User) {
	raw, hash := s.Crypto.NewToken()
	now := s.Clock.Now()
	_ = s.OneTime.DeleteByUser(ctx, u.ID, domain.PurposeVerifyEmail)
	if err := s.OneTime.Create(ctx, &domain.OneTimeToken{ID: s.Crypto.NewID(), UserID: u.ID, Purpose: domain.PurposeVerifyEmail,
		TokenHash: hash, ExpiresAt: now.Add(s.Cfg.VerifyTTL), CreatedAt: now}); err != nil {
		return
	}
	link := strings.TrimRight(s.Cfg.BaseURL, "/") + "/verify-email#token=" + raw
	s.Async(func() {
		s.mail(func(c context.Context) error { return s.Mailer.SendVerifyEmail(c, u.Email, u.Name, link) })
	})
}

func (s *Auth) mail(send func(context.Context) error) {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = send(c) // delivery failures are logged by the mailer; the caller must not learn about them
}

func (s *Auth) newRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	plain := make([]string, 10)
	rows := make([]*domain.RecoveryCode, 10)
	for i := range plain {
		plain[i] = s.Crypto.NewRecoveryCode()
		rows[i] = &domain.RecoveryCode{ID: s.Crypto.NewID(), UserID: userID, CodeHash: s.Crypto.Hash(normalizeRecovery(plain[i]))}
	}
	return plain, s.Recovery.Replace(ctx, userID, rows)
}

func normalizeRecovery(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func (s *Auth) audit(ctx context.Context, userID, action string, m ClientMeta, detail string) {
	if s.Audit == nil {
		return
	}
	_ = s.Audit.Add(ctx, &domain.AuditEvent{ID: s.Crypto.NewID(), UserID: userID, Action: action, IP: m.IP,
		UserAgent: clip(m.UserAgent, 255), Detail: detail, CreatedAt: s.Clock.Now()})
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// CreateVerifiedUser is the administrative path (CLI): no registration switch, no captcha, e-mail already trusted.
func (s *Auth) CreateVerifiedUser(ctx context.Context, name, rawEmail, password string) (*domain.User, error) {
	n, err := domain.ValidateName(name)
	if err != nil {
		return nil, &domain.ValidationError{Fields: map[string]string{"name": err.Error()}}
	}
	email, err := domain.NormalizeEmail(rawEmail)
	if err != nil {
		return nil, &domain.ValidationError{Fields: map[string]string{"email": err.Error()}}
	}
	if err := ValidatePassword(password, email, n); err != nil {
		return nil, err
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	now := s.Clock.Now()
	u := &domain.User{ID: s.Crypto.NewID(), Email: email, Name: n, PasswordHash: hash, EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	return u, s.Users.Create(ctx, u)
}
