# famku

Go API + Svelte 5 SPA with account security built in. Lives in `htdocs/famku` of the platform.

## Features
- **Login**: Argon2id (+ optional pepper), opaque server-side sessions (`__Host-` cookie, HttpOnly, Secure), idle + absolute timeouts, session list / revoke.
- **Account lockout & rate limiting**: per-IP token buckets (global + stricter on auth routes), failed-login counters with captcha escalation then lock.
- **Captcha**: built-in proof-of-work (no third party, no tracking) or Cloudflare Turnstile / hCaptcha / reCAPTCHA. Modes: `off`, `adaptive`, `always`.
- **2FA**: TOTP (RFC 6238, replay-protected) + 10 single-use recovery codes.
- **E-mail**: verification and password reset with single-use hashed tokens carried in the URL fragment.
- **Hardening**: CSRF token bound to the session, Origin / Fetch-Metadata checks, JSON-only API, strict body limits, CSP / HSTS / frame / referrer headers, no user enumeration, audit log, trusted-proxy aware client IP.

## Layout (clean architecture, dependencies point inward)
```
backend/
  cmd/server                      composition root (flags: -healthcheck -migrate -create-user)
  internal/domain                 entities, errors
  internal/usecase                Auth service + ports (interfaces)
  internal/delivery/httpapi       handlers, middleware, SPA serving
  internal/infrastructure         config, persistence/{memory,mysql}, security, captcha, ratelimit, mailer, webui
frontend/                         Svelte 5 (runes) + Vite + Tailwind v4 + shadcn-svelte style components
Dockerfile                        node build -> go build -> distroless
```

## Run on the platform
```bash
# stack files are in stacks/apps/famku (copy this zip over the platform root)
cp stacks/apps/famku/app.env.example stacks/apps/famku/app.env   # edit secrets
cp stacks/apps/famku/.env.dev.example stacks/apps/famku/.env      # or the prod one
bin/platform build-app famku && bin/platform up famku
# first user (no e-mail needed): put FAMKU_PASSWORD=... in app.env, restart, then
bin/platform exec famku app /server -create-user -email you@example.com -name You
# afterwards remove FAMKU_PASSWORD from app.env
```
Migrations run on start (`AUTO_MIGRATE=true`, guarded by a DB advisory lock).

## Local development
```bash
cd backend && go mod tidy && STORE=memory APP_ENV=development go run ./cmd/server   # :8080, in-memory store
cd frontend && npm install && npm run dev                                           # :5173, proxies /api
```
`go test -race ./...` in `backend/`; `npm run test:pow` checks the captcha solver.

## SPA hosting
`SPA_MODE=embedded` (default, one binary) · `dir` (files in `data/spa/famku`) · `external` (CDN / web hosting; set `CORS_ALLOWED_ORIGINS`, `COOKIE_SAMESITE`, and publish `/config.json` with `{"apiUrl":"https://api.example.com"}` next to the built SPA, or build with `VITE_API_URL`). The `__Host-` cookie requires HTTPS and no Domain, so keep the SPA and API on the same site where possible.

## Notes
- Captcha tokens are single use; the UI re-solves after each submit.
- 2FA setup shows the secret and an `otpauth://` link (no QR image).
- Commit `backend/go.sum` and `frontend/package-lock.json` after the first successful build.
