// Package captcha verifies that a request comes from a human (or at least from a client that paid a price).
//
// Providers:
//
//	pow        built-in proof of work (no third party, no tracking, no cookies); the browser must find a SHA-256
//	           nonce with N leading zero bits, which costs it about a second and costs a bot farm real money
//	turnstile  Cloudflare Turnstile      hcaptcha  hCaptcha      recaptcha  Google reCAPTCHA v2/v3 (siteverify API)
//	none       disabled (development only)
package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Provider   string // none | pow | turnstile | hcaptcha | recaptcha
	SiteKey    string // public key for the widget (turnstile/hcaptcha/recaptcha)
	Secret     string // provider secret key
	Difficulty int    // pow: leading zero bits (16 = ~65k hashes, 18 = ~260k)
	TTL        time.Duration
	HMACKey    []byte // pow: signs challenges (stateless)
	HTTPClient *http.Client
	VerifyURL  string // override of the provider endpoint (tests)
}

type Provider struct {
	cfg  Config
	now  func() time.Time
	mu   sync.Mutex
	used map[string]time.Time // pow: spent challenges until they expire (replay protection)
}

var endpoints = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"hcaptcha":  "https://api.hcaptcha.com/siteverify",
	"recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}

func New(cfg Config) (*Provider, error) {
	cfg.Provider = strings.ToLower(cfg.Provider)
	switch cfg.Provider {
	case "", "none":
		cfg.Provider = "none"
	case "pow":
		if len(cfg.HMACKey) < 16 {
			return nil, errors.New("captcha: pow needs an HMAC key of at least 16 bytes")
		}
		if cfg.Difficulty < 8 || cfg.Difficulty > 28 {
			return nil, errors.New("captcha: pow difficulty must be between 8 and 28 bits")
		}
	case "turnstile", "hcaptcha", "recaptcha":
		if cfg.Secret == "" || cfg.SiteKey == "" {
			return nil, fmt.Errorf("captcha: %s needs CAPTCHA_SITE_KEY and CAPTCHA_SECRET", cfg.Provider)
		}
	default:
		return nil, fmt.Errorf("captcha: unknown provider %q", cfg.Provider)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &Provider{cfg: cfg, now: time.Now, used: map[string]time.Time{}}, nil
}

func (p *Provider) Enabled() bool { return p.cfg.Provider != "none" }

// Info is what the frontend needs to render the right widget.
type Info struct {
	Provider string `json:"provider"`
	SiteKey  string `json:"siteKey,omitempty"`
}

func (p *Provider) Info() Info {
	i := Info{Provider: p.cfg.Provider}
	if p.cfg.Provider != "pow" && p.cfg.Provider != "none" {
		i.SiteKey = p.cfg.SiteKey
	}
	return i
}

func (p *Provider) Verify(ctx context.Context, token, ip string) error {
	if !p.Enabled() {
		return nil
	}
	if token == "" || len(token) > 4096 {
		return errors.New("captcha: missing token")
	}
	if p.cfg.Provider == "pow" {
		return p.verifyPoW(token)
	}
	return p.verifyRemote(ctx, token, ip)
}

// ---- remote providers --------------------------------------------------------------------------

func (p *Provider) verifyRemote(ctx context.Context, token, ip string) error {
	endpoint := p.cfg.VerifyURL
	if endpoint == "" {
		endpoint = endpoints[p.cfg.Provider]
	}
	form := url.Values{"secret": {p.cfg.Secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: provider unreachable: %w", err) // fail closed
	}
	defer resp.Body.Close()
	var out struct {
		Success bool     `json:"success"`
		Errors  []string `json:"error-codes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return fmt.Errorf("captcha: bad provider response: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("captcha: rejected %v", out.Errors)
	}
	return nil
}

// ---- proof of work -----------------------------------------------------------------------------

// Challenge is sent to the browser. The solver must find a decimal nonce such that
// SHA-256(payload + ":" + nonce) starts with Difficulty zero bits, then submit payload~signature~nonce.
type Challenge struct {
	Payload    string `json:"payload"`
	Signature  string `json:"signature"`
	Difficulty int    `json:"difficulty"`
	Algorithm  string `json:"algorithm"`
}

func (p *Provider) NewChallenge() (*Challenge, error) {
	if p.cfg.Provider != "pow" {
		return nil, errors.New("captcha: provider is not pow")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	payload := fmt.Sprintf("v1.%s.%d.%d", hex.EncodeToString(salt), p.now().Add(p.cfg.TTL).Unix(), p.cfg.Difficulty)
	return &Challenge{Payload: payload, Signature: p.sign(payload), Difficulty: p.cfg.Difficulty, Algorithm: "SHA-256"}, nil
}

func (p *Provider) sign(payload string) string {
	m := hmac.New(sha256.New, p.cfg.HMACKey)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func (p *Provider) verifyPoW(token string) error {
	parts := strings.Split(token, "~")
	if len(parts) != 3 {
		return errors.New("captcha: malformed token")
	}
	payload, sig, nonce := parts[0], parts[1], parts[2]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(p.sign(payload))) != 1 {
		return errors.New("captcha: bad signature")
	}
	f := strings.Split(payload, ".")
	if len(f) != 4 || f[0] != "v1" {
		return errors.New("captcha: bad payload")
	}
	exp, err1 := strconv.ParseInt(f[2], 10, 64)
	diff, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil || diff < p.cfg.Difficulty {
		return errors.New("captcha: bad payload")
	}
	now := p.now()
	if now.Unix() > exp {
		return errors.New("captcha: expired")
	}
	if len(nonce) == 0 || len(nonce) > 20 {
		return errors.New("captcha: bad nonce")
	}
	for _, c := range nonce {
		if c < '0' || c > '9' {
			return errors.New("captcha: bad nonce")
		}
	}
	sum := sha256.Sum256([]byte(payload + ":" + nonce))
	if leadingZeroBits(sum[:]) < diff {
		return errors.New("captcha: work not sufficient")
	}
	// single use
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.used) > 100_000 {
		for k, v := range p.used {
			if now.After(v) {
				delete(p.used, k)
			}
		}
	}
	if _, spent := p.used[f[1]]; spent {
		return errors.New("captcha: already used")
	}
	p.used[f[1]] = time.Unix(exp, 0).Add(time.Minute)
	return nil
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for m := byte(0x80); m != 0 && x&m == 0; m >>= 1 {
			n++
		}
		break
	}
	return n
}

// Solve is the reference solver (the browser uses the same algorithm in a web worker). Used by tests.
func Solve(c *Challenge) (token string) {
	for n := 0; ; n++ {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(c.Payload + ":" + nonce))
		if leadingZeroBits(sum[:]) >= c.Difficulty {
			return c.Payload + "~" + c.Signature + "~" + nonce
		}
	}
}
