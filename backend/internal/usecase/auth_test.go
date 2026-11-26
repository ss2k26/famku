package usecase_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"famku/internal/domain"
	"famku/internal/infrastructure/persistence/memory"
	"famku/internal/infrastructure/ratelimit"
	"famku/internal/infrastructure/security"
	"famku/internal/usecase"
)

// ---- fakes -------------------------------------------------------------------------------------

type fakeHasher struct{ dummies int }

func (f *fakeHasher) Hash(p string) (string, error)     { return "h:" + p, nil }
func (f *fakeHasher) Verify(p, enc string) (bool, bool) { return enc == "h:"+p, false }
func (f *fakeHasher) Dummy(string)                      { f.dummies++ }

type fakeTOTP struct{}

func (fakeTOTP) NewSecret() (string, error) { return "SECRET", nil }
func (fakeTOTP) URI(i, a, s string) string  { return "otpauth://" + i + a + s }
func (fakeTOTP) Verify(_, code string, now time.Time) (int64, bool) {
	return now.Unix() / 30, code == "123456"
}

type fakeCaptcha struct{ on bool }

func (f fakeCaptcha) Enabled() bool { return f.on }
func (f fakeCaptcha) Verify(_ context.Context, token, _ string) error {
	if token == "human" {
		return nil
	}
	return errors.New("bot")
}

type fakeMailer struct {
	mu    sync.Mutex
	links []string
}

func (m *fakeMailer) add(l string) { m.mu.Lock(); m.links = append(m.links, l); m.mu.Unlock() }
func (m *fakeMailer) SendPasswordReset(_ context.Context, _, _, link string) error {
	m.add(link)
	return nil
}
func (m *fakeMailer) SendVerifyEmail(_ context.Context, _, _, link string) error {
	m.add(link)
	return nil
}
func (m *fakeMailer) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.links) == 0 {
		return ""
	}
	return m.links[len(m.links)-1]
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

type env struct {
	a      *usecase.Auth
	store  *memory.Store
	hasher *fakeHasher
	mail   *fakeMailer
	clk    *clock
}

func setup(t *testing.T, mut func(*usecase.AuthConfig)) *env {
	t.Helper()
	st := memory.New()
	e := &env{store: st, hasher: &fakeHasher{}, mail: &fakeMailer{}, clk: &clock{t: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)}}
	cfg := usecase.AuthConfig{
		BaseURL: "https://famku.test", Issuer: "Famku", RegistrationOpen: true, CaptchaMode: "adaptive",
		CaptchaAfterFailures: 3, LockAfterFailures: 5, LockDuration: 15 * time.Minute,
		SessionIdle: time.Hour, SessionAbsolute: 24 * time.Hour, ResetTTL: 30 * time.Minute, VerifyTTL: 24 * time.Hour,
	}
	if mut != nil {
		mut(&cfg)
	}
	e.a = usecase.NewAuth(usecase.Deps{
		Users: st.Users(), Sessions: st.Sessions(), OneTime: st.Tokens(), Recovery: st.Recovery(), Audit: st.AuditLog(),
		Hasher: e.hasher, Crypto: security.Tokens{}, TOTP: fakeTOTP{}, Mailer: e.mail, Captcha: fakeCaptcha{on: true},
		Attempts: ratelimit.NewAttempts(), Clock: e.clk,
	}, cfg)
	e.a.Async = func(f func()) { f() }
	return e
}

var meta = usecase.ClientMeta{IP: "203.0.113.7", UserAgent: "test"}

const goodPW = "correct horse battery"

func (e *env) register(t *testing.T, email string) *domain.User {
	t.Helper()
	u, err := e.a.Register(context.Background(), usecase.RegisterInput{Name: "Ana", Email: email, Password: goodPW, CaptchaToken: "human", Meta: meta})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return u
}

func (e *env) login(email, pw string, extra ...func(*usecase.LoginInput)) (*usecase.LoginResult, error) {
	in := usecase.LoginInput{Email: email, Password: pw, Meta: meta}
	for _, f := range extra {
		f(&in)
	}
	return e.a.Login(context.Background(), in)
}

// ---- registration ------------------------------------------------------------------------------

func TestRegisterValidationAndCaptcha(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	if _, err := e.a.Register(ctx, usecase.RegisterInput{Name: "Ana", Email: "a@x.io", Password: goodPW, Meta: meta}); !errors.Is(err, domain.ErrCaptchaRequired) {
		t.Fatalf("missing captcha: %v", err)
	}
	if _, err := e.a.Register(ctx, usecase.RegisterInput{Name: "Ana", Email: "a@x.io", Password: goodPW, CaptchaToken: "bot", Meta: meta}); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("bad captcha: %v", err)
	}
	_, err := e.a.Register(ctx, usecase.RegisterInput{Name: "", Email: "not-an-email", Password: "short", CaptchaToken: "human", Meta: meta})
	var ve *domain.ValidationError
	if !errors.As(err, &ve) || ve.Fields["name"] == "" || ve.Fields["email"] == "" {
		t.Fatalf("expected field errors, got %v", err)
	}
	_, err = e.a.Register(ctx, usecase.RegisterInput{Name: "Ana", Email: "ana@x.io", Password: "password1234", CaptchaToken: "human", Meta: meta})
	if !errors.As(err, &ve) || ve.Fields["password"] == "" {
		t.Fatalf("common password accepted: %v", err)
	}
	e.register(t, "Ana@X.io")
	if _, err := e.a.Register(ctx, usecase.RegisterInput{Name: "Ana", Email: "ana@x.io", Password: goodPW, CaptchaToken: "human", Meta: meta}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestRegisterClosedAndNoEnumerationWhenVerifying(t *testing.T) {
	e := setup(t, func(c *usecase.AuthConfig) { c.RegistrationOpen = false })
	if _, err := e.a.Register(context.Background(), usecase.RegisterInput{Meta: meta}); !errors.Is(err, domain.ErrRegistrationClosed) {
		t.Fatalf("closed: %v", err)
	}
	e = setup(t, func(c *usecase.AuthConfig) { c.RequireVerifiedEmail = true })
	e.register(t, "ana@x.io")
	u, err := e.a.Register(context.Background(), usecase.RegisterInput{Name: "Eve", Email: "ana@x.io", Password: goodPW, CaptchaToken: "human", Meta: meta})
	if u != nil || err != nil {
		t.Fatalf("existing address must look like success, got %v %v", u, err)
	}
}

// ---- login, sessions ---------------------------------------------------------------------------

func TestLoginSessionLifecycle(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	e.register(t, "ana@x.io")
	res, err := e.login("ANA@x.io ", goodPW)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token == "" || strings.Contains(res.Session.TokenHash, res.Token) || res.Session.CSRFToken == "" {
		t.Fatal("session token must be random and only its hash stored")
	}
	u, s, err := e.a.Authenticate(ctx, res.Token)
	if err != nil || u.Email != "ana@x.io" || s.ID != res.Session.ID {
		t.Fatalf("authenticate: %v", err)
	}
	e.clk.t = e.clk.t.Add(2 * time.Hour) // idle timeout (1h)
	if _, _, err := e.a.Authenticate(ctx, res.Token); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("idle session still valid: %v", err)
	}
	res, _ = e.login("ana@x.io", goodPW)
	for i := 0; i < 30; i++ { // stay active, but the absolute lifetime (24h) still applies
		e.clk.t = e.clk.t.Add(50 * time.Minute)
		if _, _, err := e.a.Authenticate(ctx, res.Token); err != nil {
			break
		}
	}
	if _, _, err := e.a.Authenticate(ctx, res.Token); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("absolute lifetime not enforced")
	}
	res, _ = e.login("ana@x.io", goodPW)
	_ = e.a.Logout(ctx, res.Session, meta)
	if _, _, err := e.a.Authenticate(ctx, res.Token); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("logout did not end the session")
	}
}

func TestLoginFailuresDoNotRevealAccounts(t *testing.T) {
	e := setup(t, nil)
	e.register(t, "ana@x.io")
	_, err1 := e.login("ana@x.io", "wrong-password-1")
	_, err2 := e.login("nobody@x.io", "wrong-password-1")
	if !errors.Is(err1, domain.ErrInvalidCredentials) || err1 != err2 {
		t.Fatalf("different answers: %v / %v", err1, err2)
	}
	if e.hasher.dummies != 1 {
		t.Fatalf("unknown account must still cost one hash, dummies=%d", e.hasher.dummies)
	}
}

func TestAdaptiveCaptchaAndLock(t *testing.T) {
	e := setup(t, nil)
	e.register(t, "ana@x.io")
	for i := 0; i < 3; i++ {
		if _, err := e.login("ana@x.io", "bad-password-xx"); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// 3 failures: even the right password needs the captcha now
	if _, err := e.login("ana@x.io", goodPW); !errors.Is(err, domain.ErrCaptchaRequired) {
		t.Fatalf("expected captcha_required, got %v", err)
	}
	if _, err := e.login("ana@x.io", goodPW, func(in *usecase.LoginInput) { in.CaptchaToken = "bot" }); !errors.Is(err, domain.ErrCaptchaFailed) {
		t.Fatalf("expected captcha_failed, got %v", err)
	}
	human := func(in *usecase.LoginInput) { in.CaptchaToken = "human" }
	for i := 0; i < 2; i++ {
		_, _ = e.login("ana@x.io", "bad-password-xx", human)
	}
	// 5 failures = lock, even with the right password and a captcha
	_, err := e.login("ana@x.io", goodPW, human)
	var le *domain.LockedError
	if !errors.As(err, &le) || !errors.Is(err, domain.ErrAccountLocked) || le.RetryAfter <= 0 {
		t.Fatalf("expected lock, got %v", err)
	}
}

func TestVerifiedEmailRequired(t *testing.T) {
	e := setup(t, func(c *usecase.AuthConfig) { c.RequireVerifiedEmail = true })
	e.register(t, "ana@x.io")
	if _, err := e.login("ana@x.io", goodPW); !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("unverified login: %v", err)
	}
	link := e.mail.last()
	if !strings.Contains(link, "/verify-email#token=") {
		t.Fatalf("verification link %q", link)
	}
	token := link[strings.Index(link, "token=")+6:]
	ctx := context.Background()
	if err := e.a.VerifyEmail(ctx, token, meta); err != nil {
		t.Fatal(err)
	}
	if err := e.a.VerifyEmail(ctx, token, meta); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatal("verification token reusable")
	}
	if _, err := e.login("ana@x.io", goodPW); err != nil {
		t.Fatalf("login after verification: %v", err)
	}
}

// ---- password change / reset -------------------------------------------------------------------

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	u := e.register(t, "ana@x.io")
	a, _ := e.login("ana@x.io", goodPW)
	b, _ := e.login("ana@x.io", goodPW)
	err := e.a.ChangePassword(ctx, u.ID, a.Session.ID, "not the password", "another long passphrase", meta)
	var ve *domain.ValidationError
	if !errors.As(err, &ve) || ve.Fields["current_password"] == "" {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := e.a.ChangePassword(ctx, u.ID, a.Session.ID, goodPW, "another long passphrase", meta); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.a.Authenticate(ctx, a.Token); err != nil {
		t.Fatal("current session must survive")
	}
	if _, _, err := e.a.Authenticate(ctx, b.Token); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("other session must be revoked")
	}
	if _, err := e.login("ana@x.io", goodPW); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal("old password still works")
	}
}

func TestPasswordResetFlow(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	e.register(t, "ana@x.io")
	sess, _ := e.login("ana@x.io", goodPW)

	if err := e.a.RequestPasswordReset(ctx, "ghost@x.io", "human", meta); err != nil || e.mail.last() != "" {
		t.Fatalf("unknown address: err=%v mail=%q (must be silent)", err, e.mail.last())
	}
	if err := e.a.RequestPasswordReset(ctx, "ana@x.io", "", meta); !errors.Is(err, domain.ErrCaptchaRequired) {
		t.Fatalf("reset without captcha: %v", err)
	}
	if err := e.a.RequestPasswordReset(ctx, "ana@x.io", "human", meta); err != nil {
		t.Fatal(err)
	}
	link := e.mail.last()
	token := link[strings.Index(link, "token=")+6:]
	if strings.Contains(link, "?token=") {
		t.Fatal("token must be in the URL fragment so it never reaches server logs")
	}

	if err := e.a.ResetPassword(ctx, token, "short", meta); err == nil {
		t.Fatal("weak password accepted")
	}
	if err := e.a.ResetPassword(ctx, token, "a brand new passphrase", meta); err != nil {
		t.Fatalf("token must survive a rejected password: %v", err)
	}
	if err := e.a.ResetPassword(ctx, token, "yet another passphrase", meta); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatal("reset token reusable")
	}
	if _, _, err := e.a.Authenticate(ctx, sess.Token); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatal("reset must log out every session")
	}
	if _, err := e.login("ana@x.io", "a brand new passphrase"); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}

func TestResetTokenExpires(t *testing.T) {
	e := setup(t, nil)
	e.register(t, "ana@x.io")
	_ = e.a.RequestPasswordReset(context.Background(), "ana@x.io", "human", meta)
	link := e.mail.last()
	e.clk.t = e.clk.t.Add(31 * time.Minute)
	if err := e.a.ResetPassword(context.Background(), link[strings.Index(link, "token=")+6:], "a brand new passphrase", meta); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestResetMailRateLimitedPerAddress(t *testing.T) {
	e := setup(t, nil)
	e.register(t, "ana@x.io")
	for i := 0; i < 6; i++ {
		_ = e.a.RequestPasswordReset(context.Background(), "ana@x.io", "human", meta)
	}
	e.mail.mu.Lock()
	n := len(e.mail.links)
	e.mail.mu.Unlock()
	if n != 3 {
		t.Fatalf("expected 3 mails per hour per address, got %d", n)
	}
}

// ---- two-factor --------------------------------------------------------------------------------

func TestTwoFactor(t *testing.T) {
	e := setup(t, nil)
	ctx := context.Background()
	u := e.register(t, "ana@x.io")
	setup2, err := e.a.BeginTwoFactor(ctx, u.ID)
	if err != nil || setup2.Secret == "" || !strings.HasPrefix(setup2.URI, "otpauth://") {
		t.Fatalf("setup: %v", err)
	}
	if _, err := e.a.EnableTwoFactor(ctx, u.ID, "000000", meta); !errors.Is(err, domain.ErrInvalidTwoFactor) {
		t.Fatal("wrong code enabled 2FA")
	}
	codes, err := e.a.EnableTwoFactor(ctx, u.ID, "123456", meta)
	if err != nil || len(codes) != 10 {
		t.Fatalf("enable: %v %v", err, codes)
	}
	// password alone is not enough any more
	if _, err := e.login("ana@x.io", goodPW); !errors.Is(err, domain.ErrTwoFactorRequired) {
		t.Fatalf("expected two_factor_required, got %v", err)
	}
	// the code used to enable 2FA is spent for this 30 s step (replay protection)
	withCode := func(in *usecase.LoginInput) { in.TOTPCode = "123456" }
	if _, err := e.login("ana@x.io", goodPW, withCode); !errors.Is(err, domain.ErrInvalidTwoFactor) {
		t.Fatalf("replayed code accepted: %v", err)
	}
	e.clk.t = e.clk.t.Add(31 * time.Second)
	if _, err := e.login("ana@x.io", goodPW, withCode); err != nil {
		t.Fatalf("fresh code refused: %v", err)
	}
	// recovery codes work once
	rec := func(in *usecase.LoginInput) { in.RecoveryCode = strings.ToLower(codes[0]) }
	if _, err := e.login("ana@x.io", goodPW, rec); err != nil {
		t.Fatalf("recovery code refused: %v", err)
	}
	if _, err := e.login("ana@x.io", goodPW, rec); !errors.Is(err, domain.ErrInvalidTwoFactor) {
		t.Fatal("recovery code reusable")
	}
	// disabling needs the password and a code
	e.clk.t = e.clk.t.Add(31 * time.Second)
	if err := e.a.DisableTwoFactor(ctx, u.ID, "wrong password!!", "123456", meta); err == nil {
		t.Fatal("disabled without the password")
	}
	if err := e.a.DisableTwoFactor(ctx, u.ID, goodPW, "123456", meta); err != nil {
		t.Fatal(err)
	}
	if _, err := e.login("ana@x.io", goodPW); err != nil {
		t.Fatalf("login after disable: %v", err)
	}
}

func TestAuditTrailHasNoSecrets(t *testing.T) {
	e := setup(t, nil)
	e.register(t, "ana@x.io")
	_, _ = e.login("ana@x.io", "wrong-password-1")
	_, _ = e.login("ana@x.io", goodPW)
	var actions []string
	for _, ev := range e.store.Audit() {
		actions = append(actions, ev.Action)
		if strings.Contains(ev.Detail, goodPW) || strings.Contains(ev.Detail, "wrong-password") {
			t.Fatal("password leaked into the audit log")
		}
	}
	if strings.Join(actions, ",") != "register,login_failed,login_ok" {
		t.Fatalf("audit actions: %v", actions)
	}
}
