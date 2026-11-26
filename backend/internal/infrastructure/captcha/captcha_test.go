package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newPoW(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{Provider: "pow", Difficulty: 8, HMACKey: []byte("0123456789abcdef0123"), TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPoWRoundTripAndReplay(t *testing.T) {
	p := newPoW(t)
	ch, err := p.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	tok := Solve(ch)
	if err := p.Verify(context.Background(), tok, "1.2.3.4"); err != nil {
		t.Fatalf("valid solution refused: %v", err)
	}
	if err := p.Verify(context.Background(), tok, "1.2.3.4"); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestPoWRejectsForgeries(t *testing.T) {
	p := newPoW(t)
	ch, _ := p.NewChallenge()
	tok := Solve(ch)
	parts := strings.Split(tok, "~")

	bad := map[string]string{
		"tampered payload":  strings.Replace(parts[0], "v1.", "v1.0", 1) + "~" + parts[1] + "~" + parts[2],
		"foreign signature": parts[0] + "~" + strings.Repeat("0", 64) + "~" + parts[2],
		"non numeric nonce": parts[0] + "~" + parts[1] + "~abc",
		"garbage":           "hello",
		"empty nonce":       parts[0] + "~" + parts[1] + "~",
	}
	for name, tk := range bad {
		if err := p.Verify(context.Background(), tk, ""); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// a solution for an easier difficulty than the server floor must fail
	weak := &Challenge{Payload: "v1.00112233445566778899aabbccddeeff." + "9999999999.1", Difficulty: 1}
	weak.Signature = p.sign(weak.Payload)
	if err := p.Verify(context.Background(), Solve(weak), ""); err == nil {
		t.Error("difficulty below the floor accepted")
	}
}

func TestPoWExpiry(t *testing.T) {
	p := newPoW(t)
	ch, _ := p.NewChallenge()
	tok := Solve(ch)
	p.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := p.Verify(context.Background(), tok, ""); err == nil {
		t.Fatal("expired challenge accepted")
	}
}

func TestRemoteProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("secret") == "s3cret" && r.Form.Get("response") == "good" && r.Form.Get("remoteip") == "9.9.9.9" {
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer srv.Close()
	p, err := New(Config{Provider: "turnstile", SiteKey: "site", Secret: "s3cret", VerifyURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(context.Background(), "good", "9.9.9.9"); err != nil {
		t.Fatalf("good token refused: %v", err)
	}
	if err := p.Verify(context.Background(), "bad", "9.9.9.9"); err == nil {
		t.Fatal("bad token accepted")
	}
	if info := p.Info(); info.Provider != "turnstile" || info.SiteKey != "site" {
		t.Fatalf("info %+v", info)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{
		{Provider: "pow", Difficulty: 18},                                     // no key
		{Provider: "pow", Difficulty: 2, HMACKey: []byte("0123456789abcdef")}, // too easy
		{Provider: "turnstile"},                                               // no keys
		{Provider: "nope"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("config %+v accepted", c)
		}
	}
	if p, _ := New(Config{Provider: "none"}); p.Enabled() || p.Verify(context.Background(), "", "") != nil {
		t.Fatal("none must be a no-op")
	}
}
