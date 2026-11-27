// Command server is the composition root: it wires the layers together and starts the HTTP server.
//
//	server                       run the API (+ SPA depending on SPA_MODE)
//	server -healthcheck          probe /healthz and exit 0/1 (container HEALTHCHECK)
//	server -migrate              apply database migrations and exit
//	server -create-user          create a verified user (reads FAMKU_PASSWORD, -email, -name, -username); works with REGISTRATION_OPEN=false
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"famku/internal/delivery/httpapi"
	"famku/internal/infrastructure/captcha"
	"famku/internal/infrastructure/config"
	"famku/internal/infrastructure/mailer"
	"famku/internal/infrastructure/persistence/memory"
	"famku/internal/infrastructure/persistence/mysql"
	"famku/internal/infrastructure/ratelimit"
	"famku/internal/infrastructure/security"
	"famku/internal/infrastructure/webui"
	"famku/internal/usecase"
)

// stores is what the composition root needs from a persistence adapter.
type stores struct {
	users    usecase.UserRepository
	sessions usecase.SessionRepository
	tokens   usecase.TokenRepository
	recovery usecase.RecoveryCodeRepository
	audit    usecase.AuditRepository
	ping     func(context.Context) error
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz and exit")
	migrateOnly := flag.Bool("migrate", false, "apply database migrations and exit")
	createUser := flag.Bool("create-user", false, "create a verified user (password from FAMKU_PASSWORD)")
	email := flag.String("email", "", "with -create-user")
	name := flag.String("name", "", "with -create-user")
	username := flag.String("username", "", "with -create-user (default: derived from the email)")
	flag.Parse()

	if *healthcheck {
		c := http.Client{Timeout: 3 * time.Second}
		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}
		resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	for _, w := range cfg.Warnings {
		logger.Warn("configuration", "warning", w)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, closeDB := openStore(ctx, cfg, logger, *migrateOnly)
	defer closeDB()
	if *migrateOnly {
		logger.Info("migrations applied")
		return
	}

	// ---- infrastructure adapters ----
	hasher := security.NewArgon2Hasher(security.Argon2Params{MemoryKiB: cfg.Argon2MemoryKiB, Iterations: cfg.Argon2Iterations,
		Parallelism: 1, SaltLen: 16, KeyLen: 32, MaxParallel: 2}, cfg.PasswordPepper)
	captchaProv, err := captcha.New(captcha.Config{Provider: cfg.CaptchaProvider, SiteKey: cfg.CaptchaSiteKey, Secret: cfg.CaptchaSecret,
		Difficulty: cfg.CaptchaDifficulty, HMACKey: cfg.CaptchaHMACKey})
	if err != nil {
		logger.Error("captcha", "err", err)
		os.Exit(2)
	}
	var mail usecase.Mailer = mailer.Log{App: "Famku", Logger: logger}
	if cfg.MailDriver == "smtp" {
		mail = &mailer.SMTP{App: "Famku", Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser, Password: cfg.SMTPPass,
			From: cfg.SMTPFrom, TLS: cfg.SMTPTLS, Logger: logger}
	}
	attempts := ratelimit.NewAttempts()
	limiter := ratelimit.NewLimiter()

	// ---- use cases ----
	auth := usecase.NewAuth(usecase.Deps{
		Users: st.users, Sessions: st.sessions, OneTime: st.tokens, Recovery: st.recovery, Audit: st.audit,
		Hasher: hasher, Crypto: security.Tokens{}, TOTP: security.TOTP{}, Mailer: mail, Captcha: captchaProv, Attempts: attempts,
	}, usecase.AuthConfig{
		BaseURL: cfg.PublicURL, Issuer: "Famku", RegistrationOpen: cfg.RegistrationOpen, RequireVerifiedEmail: cfg.RequireVerifiedEmail,
		CaptchaMode: cfg.CaptchaMode, CaptchaAfterFailures: cfg.CaptchaAfter, LockAfterFailures: cfg.LockAfterFailures,
		LockDuration: cfg.LockDuration, SessionIdle: cfg.SessionIdle, SessionAbsolute: cfg.SessionAbsolute,
		ResetTTL: 30 * time.Minute, VerifyTTL: 24 * time.Hour,
	})

	if *createUser {
		pw := os.Getenv("FAMKU_PASSWORD")
		u, err := auth.CreateVerifiedUser(ctx, *name, *username, *email, pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create-user:", err)
			os.Exit(1)
		}
		fmt.Println("created user", u.Username, u.Email)
		return
	}

	// ---- delivery ----
	var spa fs.FS
	switch cfg.SPAMode {
	case "embedded":
		spa = webui.FS()
	case "dir":
		spa = os.DirFS(cfg.SPADir)
	}
	handler := httpapi.New(httpapi.Deps{Cfg: cfg, Auth: auth, Captcha: captchaProv, Limiter: limiter, Logger: logger, Ready: st.ping, SPA: spa})

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second, // below Traefik's 180 s idle timeout
		MaxHeaderBytes:    16 << 10,
	}

	go janitor(ctx, auth, limiter, attempts)
	go func() {
		logger.Info("listening", "addr", srv.Addr, "env", cfg.Env, "store", cfg.Store, "spa_mode", cfg.SPAMode, "captcha", cfg.CaptchaProvider)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	logger.Info("stopped")
}

func openStore(ctx context.Context, cfg *config.Config, logger *slog.Logger, forceMigrate bool) (*stores, func()) {
	if cfg.Store == "memory" {
		logger.Warn("STORE=memory: data is lost on restart")
		m := memory.New()
		return &stores{users: m.Users(), sessions: m.Sessions(), tokens: m.Tokens(), recovery: m.Recovery(), audit: m.AuditLog(),
			ping: func(context.Context) error { return nil }}, func() {}
	}
	db, err := sql.Open("mysql", cfg.DSN())
	if err != nil {
		logger.Error("database", "err", err)
		os.Exit(2)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	// the database container may still be starting: retry for a while
	var pingErr error
	for i := 0; i < 30; i++ {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		pingErr = db.PingContext(c)
		cancel()
		if pingErr == nil {
			break
		}
		logger.Warn("waiting for the database", "err", pingErr)
		select {
		case <-ctx.Done():
			os.Exit(1)
		case <-time.After(2 * time.Second):
		}
	}
	if pingErr != nil {
		logger.Error("database unreachable", "err", pingErr)
		os.Exit(1)
	}
	if cfg.AutoMigrate || forceMigrate {
		if err := mysql.Migrate(ctx, db); err != nil {
			logger.Error("migration failed", "err", err)
			os.Exit(1)
		}
	}
	s := mysql.New(db)
	return &stores{users: s.Users(), sessions: s.Sessions(), tokens: s.Tokens(), recovery: s.Recovery(), audit: s.AuditLog(), ping: s.Ping},
		func() { _ = db.Close() }
}

// janitor removes expired sessions/tokens and idle limiter entries.
func janitor(ctx context.Context, auth *usecase.Auth, l *ratelimit.Limiter, a *ratelimit.Attempts) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			auth.Cleanup(ctx)
			l.Sweep()
			a.Sweep()
		}
	}
}
