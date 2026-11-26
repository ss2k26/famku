package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"mime"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"famku/internal/domain"
	"famku/internal/infrastructure/ratelimit"
	"famku/internal/usecase"
)

type ctxKey int

const (
	keyIP ctxKey = iota
	keyReqID
	keyAuth
)

type authInfo struct {
	user *domain.User
	sess *domain.Session
}

func requestID(ctx context.Context) string { s, _ := ctx.Value(keyReqID).(string); return s }
func ipOf(ctx context.Context) string      { s, _ := ctx.Value(keyIP).(string); return s }
func authOf(ctx context.Context) *authInfo { a, _ := ctx.Value(keyAuth).(*authInfo); return a }

func meta(r *http.Request) usecase.ClientMeta {
	return usecase.ClientMeta{IP: ipOf(r.Context()), UserAgent: r.UserAgent()}
}

// ---- panic recovery, request id, real client IP, logging ---------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Logger.Error("panic", "value", v, "stack", string(debug.Stack()), "request_id", requestID(r.Context()))
				writeAPIError(w, 500, "internal", "Something went wrong. Please try again.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) realIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), keyReqID, id)
		ctx = context.WithValue(ctx, keyIP, s.clientIP(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// clientIP believes X-Forwarded-For only when the TCP peer is one of our proxies (Traefik), and then takes the
// right-most address that is not itself a trusted proxy (the left side is client-controlled).
func (s *Server) clientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !s.trusted(peer) {
		return peer
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if net.ParseIP(h) != nil && !s.trusted(h) {
			return h
		}
	}
	return peer
}

func (s *Server) trusted(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range s.Cfg.Trusted {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

type recorder struct {
	http.ResponseWriter
	status int
	n      int
}

func (r *recorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	n, err := r.ResponseWriter.Write(b)
	r.n += n
	return n, err
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		uid := ""
		if a := authOf(r.Context()); a != nil {
			uid = a.user.ID
		}
		// the path only: never the query string, headers, cookies or bodies
		s.Logger.Info("request", "request_id", requestID(r.Context()), "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "bytes", rec.n, "ms", time.Since(start).Milliseconds(), "ip", ipOf(r.Context()), "user", uid)
	})
}

// ---- security headers --------------------------------------------------------------------------

func contentSecurityPolicy(provider string) string {
	script, frame, connect := "'self'", "'none'", "'self'"
	switch provider {
	case "turnstile":
		script, frame = "'self' https://challenges.cloudflare.com", "https://challenges.cloudflare.com"
	case "hcaptcha":
		script, frame, connect = "'self' https://js.hcaptcha.com https://*.hcaptcha.com", "https://*.hcaptcha.com", "'self' https://*.hcaptcha.com"
	case "recaptcha":
		script, frame = "'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/", "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + script,
		"style-src 'self' 'unsafe-inline'", // Svelte transitions set inline styles; scripts stay strict
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + connect,
		"frame-src " + frame,
		"worker-src 'self' blob:", // the proof-of-work solver runs in a web worker
		"manifest-src 'self'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
	}, "; ")
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", s.csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-site")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		if s.Cfg.CookieSecure || r.Header.Get("X-Forwarded-Proto") == "https" || r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// ---- CORS (only needed when the SPA is hosted elsewhere) ---------------------------------------

func (s *Server) originAllowed(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	for _, a := range s.Cfg.CORSOrigins {
		if a == origin {
			return true
		}
		if strings.HasPrefix(a, "*.") && strings.HasSuffix(u.Hostname(), a[1:]) { // *.pages.dev
			return true
		}
	}
	return false
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && len(s.Cfg.CORSOrigins) > 0 {
			w.Header().Add("Vary", "Origin")
			if s.originAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Expose-Headers", "Retry-After, X-Request-Id")
				if s.Cfg.CORSCreds {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
					w.Header().Set("Access-Control-Max-Age", "600")
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- rate limiting -----------------------------------------------------------------------------

func (s *Server) globalLimit(next http.Handler) http.Handler {
	rule := ratelimit.Rule{Limit: s.Cfg.RateAPIPerMin, Window: time.Minute}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if ok, wait := s.Limiter.Allow("api:"+ipOf(r.Context()), rule); !ok {
				retry(w, wait)
				writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Slow down and try again shortly.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limit(name string, rule ratelimit.Rule, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.Limiter.Allow(name+":"+ipOf(r.Context()), rule); !ok {
			retry(w, wait)
			writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Too many attempts. Try again later.")
			return
		}
		h(w, r)
	}
}

// ---- API guards: origin check, JSON only, authentication + CSRF --------------------------------

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// api wraps every /api handler: a browser request that changes state must come from our own origin
// (or an allowed SPA origin) and carry JSON, which also rules out classic cross-site form posts.
func (s *Server) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isSafeMethod(r.Method) {
			if !s.originOK(r) {
				writeAPIError(w, http.StatusForbidden, "forbidden_origin", "This request was blocked.")
				return
			}
			if r.ContentLength != 0 {
				if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
					writeAPIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Send application/json.")
					return
				}
			}
		}
		h(w, r)
	}
}

func (s *Server) originOK(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err == nil && (u.Host == r.Host || s.sameAsPublic(u)) {
			return true
		}
		return s.originAllowed(origin)
	}
	switch r.Header.Get("Sec-Fetch-Site") { // sent by every modern browser; absent for curl and other non-browser clients
	case "", "same-origin", "none":
		return true
	}
	return false
}

func (s *Server) sameAsPublic(u *url.URL) bool {
	p, err := url.Parse(s.Cfg.PublicURL)
	return err == nil && p.Host == u.Host
}

func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookieName)
		if err != nil {
			writeAPIError(w, 401, "unauthenticated", "Please sign in.")
			return
		}
		u, sess, err := s.Auth.Authenticate(r.Context(), c.Value)
		if err != nil {
			s.clearCookie(w)
			s.fail(w, r, err)
			return
		}
		if !isSafeMethod(r.Method) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRFToken)) != 1 {
			writeAPIError(w, http.StatusForbidden, "csrf", "Your session needs a refresh. Reload the page and try again.")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), keyAuth, &authInfo{user: u, sess: sess})))
	}
}

// ---- session cookie ----------------------------------------------------------------------------

func (s *Server) setCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: token, Path: "/", Domain: s.Cfg.CookieDomain,
		Expires: expires, MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: s.Cfg.CookieSite})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: "", Path: "/", Domain: s.Cfg.CookieDomain,
		MaxAge: -1, HttpOnly: true, Secure: s.Cfg.CookieSecure, SameSite: s.Cfg.CookieSite})
}
