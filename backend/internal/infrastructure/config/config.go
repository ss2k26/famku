// Package config reads the configuration from environment variables (12-factor) and refuses to start in
// production with an unsafe combination. Secrets can also come from files: set NAME_FILE=/run/secrets/x.
package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env       string // development | production
	Port      string
	PublicURL string // https://famku.example.com : used for e-mail links and the Origin check

	// database
	Store                                      string // mysql | memory
	DBHost, DBPort, DBName, DBUser, DBPassword string
	AutoMigrate                                bool

	// SPA + CORS + cookies (platform contract, see docs/go-apps.md)
	SPAMode      string // embedded | dir | external | none
	SPADir       string
	SPAURL       string
	CORSOrigins  []string
	CORSCreds    bool
	CookieDomain string
	CookieSecure bool
	CookieSite   http.SameSite
	Trusted      []*net.IPNet

	// auth
	RegistrationOpen     bool
	RequireVerifiedEmail bool
	SessionIdle          time.Duration
	SessionAbsolute      time.Duration
	LockAfterFailures    int
	LockDuration         time.Duration
	PasswordPepper       string
	Argon2MemoryKiB      uint32
	Argon2Iterations     uint32

	// captcha
	CaptchaProvider   string // none | pow | turnstile | hcaptcha | recaptcha
	CaptchaMode       string // off | adaptive | always
	CaptchaAfter      int
	CaptchaSiteKey    string
	CaptchaSecret     string
	CaptchaDifficulty int
	CaptchaHMACKey    []byte

	// rate limits (per client IP)
	RateAPIPerMin  int
	RateAuthPerMin int

	// mail
	MailDriver                             string // log | smtp
	SMTPHost, SMTPUser, SMTPPass, SMTPFrom string
	SMTPPort                               int
	SMTPTLS                                string // starttls | tls | none

	Warnings []string
}

func (c *Config) Production() bool { return c.Env == "production" }

func Load() (*Config, error) {
	var errs []string
	str := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	secret := func(k string) string { // NAME or NAME_FILE
		if f := strings.TrimSpace(os.Getenv(k + "_FILE")); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				errs = append(errs, k+"_FILE: "+err.Error())
				return ""
			}
			return strings.TrimSpace(string(b))
		}
		return os.Getenv(k)
	}
	boolean := func(k string, def bool) bool {
		switch strings.ToLower(str(k, "")) {
		case "":
			return def
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
		errs = append(errs, k+" must be true or false")
		return def
	}
	integer := func(k string, def, min, max int) int {
		v := str(k, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Sprintf("%s must be a number between %d and %d", k, min, max))
			return def
		}
		return n
	}
	duration := func(k string, def time.Duration) time.Duration {
		v := str(k, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, k+" must be a duration like 30m or 720h")
			return def
		}
		return d
	}
	oneOf := func(k, def string, allowed ...string) string {
		v := strings.ToLower(str(k, def))
		for _, a := range allowed {
			if v == a {
				return v
			}
		}
		errs = append(errs, fmt.Sprintf("%s must be one of %s", k, strings.Join(allowed, "|")))
		return def
	}

	c := &Config{
		Env:       oneOf("APP_ENV", "development", "development", "production"),
		Port:      str("PORT", "8080"),
		PublicURL: strings.TrimRight(str("PUBLIC_URL", "http://localhost:8080"), "/"),

		Store:       oneOf("STORE", "mysql", "mysql", "memory"),
		DBHost:      str("DB_HOST", "mysql84"),
		DBPort:      str("DB_PORT", "3306"),
		DBName:      str("DB_NAME", "famku"),
		DBUser:      str("DB_USER", "famku"),
		DBPassword:  secret("DB_PASSWORD"),
		AutoMigrate: boolean("AUTO_MIGRATE", true),

		SPAMode:      oneOf("SPA_MODE", "embedded", "embedded", "dir", "external", "none"),
		SPADir:       str("SPA_DIR", "/spa"),
		SPAURL:       str("SPA_URL", ""),
		CORSCreds:    boolean("CORS_ALLOW_CREDENTIALS", true),
		CookieDomain: str("COOKIE_DOMAIN", ""),
		CookieSecure: boolean("COOKIE_SECURE", true),

		RegistrationOpen:     boolean("REGISTRATION_OPEN", true),
		RequireVerifiedEmail: boolean("REQUIRE_VERIFIED_EMAIL", false),
		SessionIdle:          duration("SESSION_IDLE_TIMEOUT", 24*time.Hour),
		SessionAbsolute:      duration("SESSION_ABSOLUTE_TIMEOUT", 30*24*time.Hour),
		LockAfterFailures:    integer("LOGIN_LOCK_AFTER", 10, 3, 100),
		LockDuration:         duration("LOGIN_LOCK_DURATION", 15*time.Minute),
		PasswordPepper:       secret("PASSWORD_PEPPER"),
		Argon2MemoryKiB:      uint32(integer("ARGON2_MEMORY_KIB", 46*1024, 8*1024, 1024*1024)),
		Argon2Iterations:     uint32(integer("ARGON2_ITERATIONS", 2, 1, 10)),

		CaptchaProvider:   oneOf("CAPTCHA_PROVIDER", "pow", "none", "pow", "turnstile", "hcaptcha", "recaptcha"),
		CaptchaMode:       oneOf("CAPTCHA_MODE", "adaptive", "off", "adaptive", "always"),
		CaptchaAfter:      integer("CAPTCHA_AFTER_FAILURES", 3, 1, 50),
		CaptchaSiteKey:    str("CAPTCHA_SITE_KEY", ""),
		CaptchaSecret:     secret("CAPTCHA_SECRET"),
		CaptchaDifficulty: integer("CAPTCHA_DIFFICULTY", 18, 8, 28),

		RateAPIPerMin:  integer("RATE_API_PER_MIN", 120, 10, 100000),
		RateAuthPerMin: integer("RATE_AUTH_PER_MIN", 10, 1, 1000),

		MailDriver: oneOf("MAIL_DRIVER", "log", "log", "smtp"),
		SMTPHost:   str("SMTP_HOST", ""),
		SMTPPort:   integer("SMTP_PORT", 587, 1, 65535),
		SMTPUser:   str("SMTP_USER", ""),
		SMTPPass:   secret("SMTP_PASSWORD"),
		SMTPFrom:   str("SMTP_FROM", "Famku <no-reply@localhost>"),
		SMTPTLS:    oneOf("SMTP_TLS", "starttls", "starttls", "tls", "none"),
	}
	for _, o := range strings.Split(str("CORS_ALLOWED_ORIGINS", ""), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.CORSOrigins = append(c.CORSOrigins, o)
		}
	}
	switch strings.ToLower(str("COOKIE_SAMESITE", "Lax")) {
	case "lax":
		c.CookieSite = http.SameSiteLaxMode
	case "strict":
		c.CookieSite = http.SameSiteStrictMode
	case "none":
		c.CookieSite = http.SameSiteNoneMode
	default:
		errs = append(errs, "COOKIE_SAMESITE must be Lax, Strict or None")
	}
	for _, cidr := range strings.Split(str("TRUSTED_PROXIES", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"), ",") {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, "TRUSTED_PROXIES: "+err.Error())
		} else {
			c.Trusted = append(c.Trusted, n)
		}
	}

	// the proof-of-work challenges are signed with this key: set it, or restarts invalidate open challenges
	if k := secret("CAPTCHA_HMAC_KEY"); k != "" {
		c.CaptchaHMACKey = []byte(k)
	} else {
		c.CaptchaHMACKey = make([]byte, 32)
		_, _ = rand.Read(c.CaptchaHMACKey)
		if c.CaptchaProvider == "pow" {
			c.Warnings = append(c.Warnings, "CAPTCHA_HMAC_KEY not set: using a random key (fine for one instance; set it to share across replicas)")
		}
	}

	c.validate(&errs)
	if len(errs) > 0 {
		return nil, errors.New("invalid configuration:\n  - " + strings.Join(errs, "\n  - "))
	}
	return c, nil
}

func (c *Config) validate(errs *[]string) {
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		*errs = append(*errs, "PUBLIC_URL must be a full URL such as https://famku.example.com")
		return
	}
	if c.CookieSite == http.SameSiteNoneMode && !c.CookieSecure {
		*errs = append(*errs, "COOKIE_SAMESITE=None requires COOKIE_SECURE=true")
	}
	if c.SMTPTLS == "none" && c.Production() && c.MailDriver == "smtp" {
		*errs = append(*errs, "SMTP_TLS=none is not allowed in production")
	}
	if c.MailDriver == "smtp" && c.SMTPHost == "" {
		*errs = append(*errs, "MAIL_DRIVER=smtp needs SMTP_HOST")
	}
	if c.Store == "mysql" && c.DBPassword == "" && c.Production() {
		*errs = append(*errs, "DB_PASSWORD (or DB_PASSWORD_FILE) is required in production")
	}
	if c.SPAMode == "external" && len(c.CORSOrigins) == 0 {
		c.Warnings = append(c.Warnings, "SPA_MODE=external without CORS_ALLOWED_ORIGINS: browsers will block the frontend")
	}
	if !c.Production() {
		return
	}
	// ---- production gate ----
	if u.Scheme != "https" {
		*errs = append(*errs, "PUBLIC_URL must be https in production")
	}
	if !c.CookieSecure {
		*errs = append(*errs, "COOKIE_SECURE must be true in production")
	}
	if c.Store == "memory" {
		*errs = append(*errs, "STORE=memory is for development only")
	}
	if c.CaptchaProvider == "none" || c.CaptchaMode == "off" {
		c.Warnings = append(c.Warnings, "captcha is disabled")
	}
	if len(c.PasswordPepper) < 32 {
		c.Warnings = append(c.Warnings, "PASSWORD_PEPPER is empty or shorter than 32 characters (recommended: 32+ random characters, kept outside the database)")
	}
	if !c.RequireVerifiedEmail {
		c.Warnings = append(c.Warnings, "REQUIRE_VERIFIED_EMAIL=false: accounts can use addresses they do not own")
	}
	if c.MailDriver == "log" {
		c.Warnings = append(c.Warnings, "MAIL_DRIVER=log: password reset mails are only printed to the log")
	}
	for _, o := range c.CORSOrigins {
		if o == "*" {
			*errs = append(*errs, "CORS_ALLOWED_ORIGINS must list explicit origins, not *")
		}
	}
}

// DSN builds the go-sql-driver/mysql connection string (UTC, utf8mb4, sane timeouts).
func (c *Config) DSN() string {
	q := url.Values{}
	q.Set("parseTime", "true")
	q.Set("loc", "UTC")
	q.Set("charset", "utf8mb4")
	q.Set("timeout", "5s")
	q.Set("readTimeout", "30s")
	q.Set("writeTimeout", "30s")
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", c.DBUser, c.DBPassword, net.JoinHostPort(c.DBHost, c.DBPort), c.DBName, q.Encode())
}
