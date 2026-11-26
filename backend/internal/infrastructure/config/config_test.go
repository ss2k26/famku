package config

import (
	"strings"
	"testing"
)

func set(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{"APP_ENV", "PUBLIC_URL", "DB_PASSWORD", "COOKIE_SECURE", "COOKIE_SAMESITE", "STORE", "CORS_ALLOWED_ORIGINS", "CAPTCHA_PROVIDER", "TRUSTED_PROXIES"} {
		t.Setenv(k, "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestDevelopmentDefaults(t *testing.T) {
	set(t, nil)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Production() || c.CaptchaProvider != "pow" || c.CaptchaMode != "adaptive" || len(c.CaptchaHMACKey) != 32 {
		t.Fatalf("unexpected defaults %+v", c)
	}
}

func TestProductionGate(t *testing.T) {
	set(t, map[string]string{"APP_ENV": "production", "PUBLIC_URL": "http://insecure.example.com", "STORE": "memory", "COOKIE_SECURE": "false"})
	_, err := Load()
	if err == nil {
		t.Fatal("unsafe production config accepted")
	}
	for _, want := range []string{"PUBLIC_URL must be https", "COOKIE_SECURE must be true", "STORE=memory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing complaint %q in %v", want, err)
		}
	}
	set(t, map[string]string{"APP_ENV": "production", "PUBLIC_URL": "https://famku.example.com", "DB_PASSWORD": "x", "CORS_ALLOWED_ORIGINS": "*"})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "explicit origins") {
		t.Fatalf("wildcard CORS must be refused: %v", err)
	}
	set(t, map[string]string{"APP_ENV": "production", "PUBLIC_URL": "https://famku.example.com", "DB_PASSWORD": "x"})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Warnings) == 0 {
		t.Fatal("expected hardening warnings (pepper, verified e-mail, mail driver)")
	}
}

func TestSameSiteNoneNeedsSecure(t *testing.T) {
	set(t, map[string]string{"COOKIE_SAMESITE": "None", "COOKIE_SECURE": "false"})
	if _, err := Load(); err == nil {
		t.Fatal("SameSite=None without Secure accepted")
	}
}

func TestDSN(t *testing.T) {
	set(t, map[string]string{"DB_PASSWORD": "p@ss:w/rd"})
	c, _ := Load()
	if d := c.DSN(); !strings.Contains(d, "@tcp(mysql84:3306)/famku?") || !strings.Contains(d, "parseTime=true") {
		t.Fatalf("dsn %s", d)
	}
}
