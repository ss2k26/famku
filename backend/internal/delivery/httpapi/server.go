// Package httpapi is the delivery layer: it translates HTTP into use-case calls and back.
// It knows about cookies, JSON and headers; it contains no business rules.
package httpapi

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"famku/internal/infrastructure/captcha"
	"famku/internal/infrastructure/config"
	"famku/internal/infrastructure/ratelimit"
	"famku/internal/usecase"
)

type Deps struct {
	Cfg     *config.Config
	Auth    *usecase.Auth
	Captcha *captcha.Provider
	Limiter *ratelimit.Limiter
	Logger  *slog.Logger
	Ready   func(context.Context) error // database ping
	SPA     fs.FS                       // the built frontend (embedded or a directory); nil = none
}

type Server struct {
	Deps
	cookieName string
	csp        string
}

// Rules for per-IP limits on top of the global API limit.
var (
	ruleSendsMail = ratelimit.Rule{Limit: 5, Window: time.Hour}
	ruleCaptcha   = ratelimit.Rule{Limit: 30, Window: time.Minute}
	ruleRegister  = ratelimit.Rule{Limit: 10, Window: time.Hour}
)

func New(d Deps) http.Handler {
	s := &Server{Deps: d}
	s.cookieName = "famku_sid"
	if d.Cfg.CookieSecure && d.Cfg.CookieDomain == "" {
		s.cookieName = "__Host-famku_sid" // browser-enforced: Secure, Path=/, no Domain
	}
	s.csp = contentSecurityPolicy(d.Cfg.CaptchaProvider)

	auth := ratelimit.Rule{Limit: d.Cfg.RateAuthPerMin, Window: time.Minute}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", s.readyz)

	// public auth endpoints
	mux.HandleFunc("POST /api/auth/register", s.api(s.limit("register", ruleRegister, s.register)))
	mux.HandleFunc("POST /api/auth/login", s.api(s.limit("login", auth, s.login)))
	mux.HandleFunc("POST /api/auth/forgot-password", s.api(s.limit("forgot", ruleSendsMail, s.forgotPassword)))
	mux.HandleFunc("POST /api/auth/reset-password", s.api(s.limit("reset", auth, s.resetPassword)))
	mux.HandleFunc("POST /api/auth/verify-email", s.api(s.limit("verify", auth, s.verifyEmail)))
	mux.HandleFunc("POST /api/auth/resend-verification", s.api(s.limit("resend", ruleSendsMail, s.resendVerification)))
	mux.HandleFunc("GET /api/captcha/config", s.api(s.limit("captcha", ruleCaptcha, s.captchaConfig)))
	mux.HandleFunc("GET /api/captcha/challenge", s.api(s.limit("captcha", ruleCaptcha, s.captchaChallenge)))

	// authenticated endpoints (session cookie; unsafe methods also need the X-CSRF-Token header)
	priv := func(h http.HandlerFunc) http.HandlerFunc { return s.api(s.requireAuth(h)) }
	mux.HandleFunc("GET /api/auth/me", priv(s.me))
	mux.HandleFunc("POST /api/auth/logout", priv(s.logout))
	mux.HandleFunc("PATCH /api/account/profile", priv(s.updateProfile))
	mux.HandleFunc("POST /api/account/password", priv(s.limit("chpw", auth, s.changePassword)))
	mux.HandleFunc("GET /api/account/sessions", priv(s.listSessions))
	mux.HandleFunc("DELETE /api/account/sessions/{id}", priv(s.revokeSession))
	mux.HandleFunc("POST /api/account/sessions/revoke-others", priv(s.revokeOthers))
	mux.HandleFunc("POST /api/account/2fa/setup", priv(s.limit("2fa", auth, s.twoFactorSetup)))
	mux.HandleFunc("POST /api/account/2fa/enable", priv(s.limit("2fa", auth, s.twoFactorEnable)))
	mux.HandleFunc("POST /api/account/2fa/disable", priv(s.limit("2fa", auth, s.twoFactorDisable)))
	mux.HandleFunc("POST /api/account/2fa/recovery-codes", priv(s.limit("2fa", auth, s.recoveryCodes)))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeAPIError(w, 404, "not_found", "Not found.") })
	mux.Handle("/", s.spa())

	// outermost first
	var h http.Handler = mux
	h = s.cors(h)
	h = s.securityHeaders(h)
	h = s.globalLimit(h)
	h = s.logRequests(h)
	h = s.realIP(h)
	h = s.recoverer(h)
	return h
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.Ready != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.Ready(ctx); err != nil {
			s.Logger.Error("readiness check failed", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}
