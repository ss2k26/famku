package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"famku/internal/delivery/httpapi"
	"famku/internal/infrastructure/captcha"
	"famku/internal/infrastructure/config"
	"famku/internal/infrastructure/persistence/memory"
	"famku/internal/infrastructure/ratelimit"
	"famku/internal/infrastructure/security"
	"famku/internal/usecase"
)

type mailbox struct {
	mu    sync.Mutex
	links []string
}

func (m *mailbox) SendPasswordReset(_ context.Context, _, _, l string) error { m.add(l); return nil }
func (m *mailbox) SendVerifyEmail(_ context.Context, _, _, l string) error   { m.add(l); return nil }
func (m *mailbox) add(l string)                                              { m.mu.Lock(); m.links = append(m.links, l); m.mu.Unlock() }
func (m *mailbox) last() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.links) == 0 {
		return ""
	}
	return m.links[len(m.links)-1]
}

type app struct {
	ts   *httptest.Server
	cap  *captcha.Provider
	mail *mailbox
	cfg  *config.Config
}

func newApp(t *testing.T, mut func(*config.Config)) *app {
	t.Helper()
	t.Setenv("PUBLIC_URL", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.CookieSecure = false // httptest speaks plain http
	cfg.CaptchaDifficulty = 8
	cfg.RateAuthPerMin = 1000
	cfg.RateAPIPerMin = 100000
	if mut != nil {
		mut(cfg)
	}
	cap, err := captcha.New(captcha.Config{Provider: cfg.CaptchaProvider, Difficulty: cfg.CaptchaDifficulty, HMACKey: cfg.CaptchaHMACKey})
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	mb := &mailbox{}
	auth := usecase.NewAuth(usecase.Deps{
		Users: st.Users(), Sessions: st.Sessions(), OneTime: st.Tokens(), Recovery: st.Recovery(), Audit: st.AuditLog(),
		Hasher: security.NewArgon2Hasher(security.Argon2Params{MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32, MaxParallel: 2}, "pepper"),
		Crypto: security.Tokens{}, TOTP: security.TOTP{}, Mailer: mb, Captcha: cap, Attempts: ratelimit.NewAttempts(),
	}, usecase.AuthConfig{
		BaseURL: cfg.PublicURL, Issuer: "Famku", RegistrationOpen: cfg.RegistrationOpen, RequireVerifiedEmail: cfg.RequireVerifiedEmail,
		CaptchaMode: cfg.CaptchaMode, CaptchaAfterFailures: cfg.CaptchaAfter, LockAfterFailures: cfg.LockAfterFailures, LockDuration: cfg.LockDuration,
		SessionIdle: cfg.SessionIdle, SessionAbsolute: cfg.SessionAbsolute, ResetTTL: 30 * time.Minute, VerifyTTL: 24 * time.Hour,
	})
	auth.Async = func(f func()) { f() }
	spa := fstest.MapFS{
		"index.html":        {Data: []byte("<html>spa</html>")},
		"assets/app-abc.js": {Data: []byte("console.log(1)")},
	}
	h := httpapi.New(httpapi.Deps{Cfg: cfg, Auth: auth, Captcha: cap, Limiter: ratelimit.NewLimiter(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Ready: func(context.Context) error { return nil }, SPA: spa})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &app{ts: ts, cap: cap, mail: mb, cfg: cfg}
}

// client keeps cookies like a browser would.
type client struct {
	t    *testing.T
	a    *app
	http *http.Client
	csrf string
}

func (a *app) client(t *testing.T) *client {
	jar, _ := newJar()
	return &client{t: t, a: a, http: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *client) do(method, path string, body any, hdr map[string]string) (*http.Response, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.a.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" && !strings.HasPrefix(path, "/api/auth/login") {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func errCode(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (a *app) solve() string {
	ch, _ := a.cap.NewChallenge()
	return captcha.Solve(ch)
}

const pw = "correct horse battery"

func (c *client) register(email string) {
	c.t.Helper()
	resp, m := c.do("POST", "/api/auth/register", map[string]any{"name": "Ana", "email": email, "password": pw, "captcha": c.a.solve()}, nil)
	if resp.StatusCode != 202 {
		c.t.Fatalf("register: %d %v", resp.StatusCode, m)
	}
}

func (c *client) login(email string, extra map[string]any) (*http.Response, map[string]any) {
	body := map[string]any{"email": email, "password": pw}
	for k, v := range extra {
		body[k] = v
	}
	resp, m := c.do("POST", "/api/auth/login", body, nil)
	if resp.StatusCode == 200 {
		c.csrf, _ = m["csrfToken"].(string)
	}
	return resp, m
}

// ---- tests -------------------------------------------------------------------------------------

func TestRegisterLoginMeLogoutAndCookieFlags(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	c.register("ana@example.com")
	resp, m := c.login("ana@example.com", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d %v", resp.StatusCode, m)
	}
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		cookie = ck
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.Value == "" {
		t.Fatalf("session cookie flags wrong: %+v", cookie)
	}
	if strings.Contains(resp.Header.Get("Set-Cookie"), "Domain") {
		t.Fatal("session cookie must be host-only")
	}
	if resp, m = c.do("GET", "/api/auth/me", nil, nil); resp.StatusCode != 200 || m["user"].(map[string]any)["email"] != "ana@example.com" {
		t.Fatalf("me: %d %v", resp.StatusCode, m)
	}
	if resp, _ = c.do("POST", "/api/auth/logout", map[string]any{}, nil); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ = c.do("GET", "/api/auth/me", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("session still valid after logout: %d", resp.StatusCode)
	}
}

func TestCSRFAndOriginProtection(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	c.register("ana@example.com")
	c.login("ana@example.com", nil)

	good := c.csrf
	c.csrf = ""
	if resp, m := c.do("PATCH", "/api/account/profile", map[string]any{"name": "Eve"}, nil); resp.StatusCode != 403 || errCode(m) != "csrf" {
		t.Fatalf("missing CSRF token accepted: %d %v", resp.StatusCode, m)
	}
	c.csrf = "wrong"
	if resp, _ := c.do("PATCH", "/api/account/profile", map[string]any{"name": "Eve"}, nil); resp.StatusCode != 403 {
		t.Fatal("wrong CSRF token accepted")
	}
	c.csrf = good
	if resp, m := c.do("PATCH", "/api/account/profile", map[string]any{"name": "Eve"}, nil); resp.StatusCode != 200 {
		t.Fatalf("valid request refused: %d %v", resp.StatusCode, m)
	}
	// a cross-site page cannot post, even with the cookie and a guessed token
	if resp, m := c.do("PATCH", "/api/account/profile", map[string]any{"name": "Eve"}, map[string]string{"Origin": "https://evil.example"}); resp.StatusCode != 403 || errCode(m) != "forbidden_origin" {
		t.Fatalf("foreign Origin accepted: %d %v", resp.StatusCode, m)
	}
	if resp, _ := c.do("PATCH", "/api/account/profile", map[string]any{"name": "Eve"}, map[string]string{"Sec-Fetch-Site": "cross-site"}); resp.StatusCode != 403 {
		t.Fatal("cross-site fetch accepted")
	}
	// login is protected too (login CSRF)
	if resp, _ := c.do("POST", "/api/auth/login", map[string]any{"email": "ana@example.com", "password": pw}, map[string]string{"Origin": "https://evil.example"}); resp.StatusCode != 403 {
		t.Fatal("login from a foreign origin accepted")
	}
	// form posts are refused: JSON only
	req, _ := http.NewRequest("POST", a.ts.URL+"/api/auth/login", strings.NewReader("email=a&password=b"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 415 {
		t.Fatalf("form post status %d", resp.StatusCode)
	}
}

func TestStrictJSONAndBodyLimit(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	if resp, m := c.do("POST", "/api/auth/login", map[string]any{"email": "a@b.co", "password": "x", "isAdmin": true}, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field accepted: %d %v", resp.StatusCode, m)
	}
	big := strings.Repeat("a", 70<<10)
	if resp, _ := c.do("POST", "/api/auth/login", map[string]any{"email": big, "password": "x"}, nil); resp.StatusCode != 413 {
		t.Fatalf("oversized body status %d", resp.StatusCode)
	}
}

func TestCaptchaGateAndAdaptiveLogin(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	if resp, m := c.do("POST", "/api/auth/register", map[string]any{"name": "Ana", "email": "ana@example.com", "password": pw}, nil); resp.StatusCode != 403 || errCode(m) != "captcha_required" {
		t.Fatalf("register without captcha: %d %v", resp.StatusCode, m)
	}
	c.register("ana@example.com")
	for i := 0; i < 3; i++ {
		if resp, m := c.login("ana@example.com", map[string]any{"password": "wrong-password-12"}); resp.StatusCode != 401 || errCode(m) != "invalid_credentials" {
			t.Fatalf("bad login %d: %d %v", i, resp.StatusCode, m)
		}
	}
	if resp, m := c.login("ana@example.com", nil); resp.StatusCode != 403 || errCode(m) != "captcha_required" {
		t.Fatalf("captcha not demanded after failures: %d %v", resp.StatusCode, m)
	}
	if resp, m := c.login("ana@example.com", map[string]any{"captcha": a.solve()}); resp.StatusCode != 200 {
		t.Fatalf("login with solved captcha: %d %v", resp.StatusCode, m)
	}
	// the same solution cannot be used twice
	ch, _ := a.cap.NewChallenge()
	tok := captcha.Solve(ch)
	if resp, _ := c.do("POST", "/api/auth/forgot-password", map[string]any{"email": "ana@example.com", "captcha": tok}, nil); resp.StatusCode != 202 {
		t.Fatal("forgot-password with a valid captcha failed")
	}
	if resp, m := c.do("POST", "/api/auth/forgot-password", map[string]any{"email": "ana@example.com", "captcha": tok}, nil); resp.StatusCode != 403 || errCode(m) != "captcha_failed" {
		t.Fatalf("captcha replay accepted: %d %v", resp.StatusCode, m)
	}
}

func TestChallengeEndpoint(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	resp, m := c.do("GET", "/api/captcha/challenge", nil, nil)
	if resp.StatusCode != 200 || m["payload"] == nil || m["difficulty"].(float64) != 8 {
		t.Fatalf("challenge: %d %v", resp.StatusCode, m)
	}
	if resp, m = c.do("GET", "/api/captcha/config", nil, nil); m["provider"] != "pow" || m["mode"] != "adaptive" {
		t.Fatalf("config: %v", m)
	}
}

func TestRateLimiting(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.RateAuthPerMin = 3 })
	c := a.client(t)
	var last *http.Response
	for i := 0; i < 5; i++ {
		last, _ = c.do("POST", "/api/auth/login", map[string]any{"email": "x@example.com", "password": "bad-password-12"}, nil)
	}
	if last.StatusCode != 429 || last.Header.Get("Retry-After") == "" {
		t.Fatalf("per-route limit not applied: %d retry-after=%q", last.StatusCode, last.Header.Get("Retry-After"))
	}
	b := newApp(t, func(c *config.Config) { c.RateAPIPerMin = 10 })
	d := b.client(t)
	for i := 0; i < 12; i++ {
		last, _ = d.do("GET", "/api/captcha/config", nil, nil)
	}
	if last.StatusCode != 429 {
		t.Fatalf("global API limit not applied: %d", last.StatusCode)
	}
}

func TestSecurityHeadersAndSPA(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	resp, _ := c.do("GET", "/", nil, nil)
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin"} {
		if resp.Header.Get(h) != want {
			t.Errorf("%s = %q", h, resp.Header.Get(h))
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("script-src must stay strict")
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("index.html cache-control %q", resp.Header.Get("Cache-Control"))
	}
	if r, _ := c.do("GET", "/dashboard/settings", nil, nil); r.StatusCode != 200 {
		t.Errorf("client-side route should serve index.html, got %d", r.StatusCode)
	}
	if r, _ := c.do("GET", "/assets/missing.js", nil, nil); r.StatusCode != 404 {
		t.Errorf("missing asset must 404, got %d", r.StatusCode)
	}
	if r, _ := c.do("GET", "/assets/app-abc.js", nil, nil); !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("hashed asset not immutable: %q", r.Header.Get("Cache-Control"))
	}
	r, _ := c.do("GET", "/api/captcha/config", nil, nil)
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("API responses must be no-store: %q", r.Header.Get("Cache-Control"))
	}
	if r, _ := c.do("GET", "/api/nope", nil, nil); r.StatusCode != 404 {
		t.Errorf("unknown API route: %d", r.StatusCode)
	}
}

func TestProviderCSPAllowsOnlyThatProvider(t *testing.T) {
	// CSP is derived from the captcha provider; built-in PoW needs no third-party host
	a := newApp(t, nil)
	resp, _ := a.client(t).do("GET", "/", nil, nil)
	if strings.Contains(resp.Header.Get("Content-Security-Policy"), "https://") {
		t.Fatalf("pow must not allow third-party hosts: %s", resp.Header.Get("Content-Security-Policy"))
	}
}

func TestCORSForExternalSPA(t *testing.T) {
	a := newApp(t, func(c *config.Config) {
		c.SPAMode = "external"
		c.CORSOrigins = []string{"https://app.example.com", "*.pages.dev"}
	})
	c := a.client(t)
	resp, _ := c.do("OPTIONS", "/api/auth/login", nil, map[string]string{"Origin": "https://x.pages.dev", "Access-Control-Request-Method": "POST"})
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Origin") != "https://x.pages.dev" || resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight: %d %v", resp.StatusCode, resp.Header)
	}
	resp, _ = c.do("GET", "/api/captcha/config", nil, map[string]string{"Origin": "https://evil.example"})
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("foreign origin got CORS headers")
	}
	// an allowed SPA origin may also pass the state-changing origin check
	resp, m := c.do("POST", "/api/auth/forgot-password", map[string]any{"email": "a@example.com", "captcha": a.solve()}, map[string]string{"Origin": "https://app.example.com"})
	if resp.StatusCode != 202 {
		t.Fatalf("allowed origin refused: %d %v", resp.StatusCode, m)
	}
	if r, _ := c.do("GET", "/", nil, nil); r.StatusCode != 404 {
		t.Fatalf("external mode must not serve the SPA: %d", r.StatusCode)
	}
}

func TestResetFlowOverHTTP(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	c.register("ana@example.com")
	c.login("ana@example.com", nil)
	// unknown and known addresses get the identical answer
	r1, m1 := c.do("POST", "/api/auth/forgot-password", map[string]any{"email": "ghost@example.com", "captcha": a.solve()}, nil)
	r2, m2 := c.do("POST", "/api/auth/forgot-password", map[string]any{"email": "ana@example.com", "captcha": a.solve()}, nil)
	if r1.StatusCode != r2.StatusCode || len(m1) != len(m2) {
		t.Fatalf("answers differ: %d %v / %d %v", r1.StatusCode, m1, r2.StatusCode, m2)
	}
	link := a.mail.last()
	tok := link[strings.Index(link, "token=")+6:]
	if r, m := c.do("POST", "/api/auth/reset-password", map[string]any{"token": tok, "password": "a brand new passphrase"}, nil); r.StatusCode != 200 {
		t.Fatalf("reset: %d %v", r.StatusCode, m)
	}
	if r, _ := c.do("GET", "/api/auth/me", nil, nil); r.StatusCode != 401 {
		t.Fatal("old session survived the password reset")
	}
	if r, m := c.do("POST", "/api/auth/reset-password", map[string]any{"token": tok, "password": "yet another passphrase"}, nil); r.StatusCode != 400 || errCode(m) != "invalid_token" {
		t.Fatalf("token reuse: %d %v", r.StatusCode, m)
	}
}

func TestTwoFactorOverHTTP(t *testing.T) {
	a := newApp(t, nil)
	c := a.client(t)
	c.register("ana@example.com")
	c.login("ana@example.com", nil)
	_, m := c.do("POST", "/api/account/2fa/setup", map[string]any{}, nil)
	secret := m["secret"].(string)
	if !strings.HasPrefix(m["uri"].(string), "otpauth://totp/") {
		t.Fatalf("uri %v", m["uri"])
	}
	code := totpNow(t, secret, 0)
	r, m := c.do("POST", "/api/account/2fa/enable", map[string]any{"code": code}, nil)
	if r.StatusCode != 200 || len(m["recoveryCodes"].([]any)) != 10 {
		t.Fatalf("enable: %d %v", r.StatusCode, m)
	}
	rec := m["recoveryCodes"].([]any)[0].(string)
	c2 := a.client(t)
	if r, m := c2.login("ana@example.com", nil); r.StatusCode != 401 || errCode(m) != "two_factor_required" {
		t.Fatalf("2FA not demanded: %d %v", r.StatusCode, m)
	}
	if r, m := c2.login("ana@example.com", map[string]any{"recoveryCode": rec}); r.StatusCode != 200 {
		t.Fatalf("recovery login: %d %v", r.StatusCode, m)
	}
	if r, _ := a.client(t).login("ana@example.com", map[string]any{"recoveryCode": rec}); r.StatusCode != 401 {
		t.Fatal("recovery code reusable")
	}
}

func TestClientIPOnlyTrustedFromProxies(t *testing.T) {
	// the test server connects from 127.0.0.1, which is not a trusted proxy: X-Forwarded-For must be ignored,
	// so a client cannot dodge per-IP limits by sending random XFF values
	b := newApp(t, func(c *config.Config) { c.RateAuthPerMin = 2 })
	cl := b.client(t)
	var last *http.Response
	for i := 0; i < 4; i++ {
		last, _ = cl.do("POST", "/api/auth/login", map[string]any{"email": "x@example.com", "password": "bad-password-12"}, map[string]string{"X-Forwarded-For": "198.51.100." + string(rune('1'+i))})
	}
	if last.StatusCode != 429 {
		t.Fatalf("spoofed X-Forwarded-For bypassed the limiter: %d", last.StatusCode)
	}
}
