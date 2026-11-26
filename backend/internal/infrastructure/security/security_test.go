package security

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	// RFC 6238 appendix B, SHA1 secret "12345678901234567890", T=59 -> 94287082 (last 6 digits 287082)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	step, ok := TOTP{}.Verify(secret, "287082", time.Unix(59, 0))
	if !ok || step != 1 {
		t.Fatalf("expected valid code at step 1, got ok=%v step=%d", ok, step)
	}
	if _, ok := (TOTP{}).Verify(secret, "287083", time.Unix(59, 0)); ok {
		t.Fatal("wrong code accepted")
	}
	if _, ok := (TOTP{}).Verify(secret, "287082", time.Unix(59+300, 0)); ok {
		t.Fatal("code accepted far outside the drift window")
	}
}

func TestTokens(t *testing.T) {
	tk := Tokens{}
	a, ha := tk.NewToken()
	b, _ := tk.NewToken()
	if a == b || len(a) < 40 || tk.Hash(a) != ha {
		t.Fatal("token generation/hash broken")
	}
	rc := tk.NewRecoveryCode()
	if len(rc) != 11 || rc[5] != '-' || strings.ContainsAny(rc, "01OI") {
		t.Fatalf("bad recovery code %q", rc)
	}
}

func TestArgon2HashVerify(t *testing.T) {
	p := DefaultArgon2()
	p.MemoryKiB = 1024 // keep the test fast
	h := NewArgon2Hasher(p, "pepper-for-tests")
	enc, err := h.Hash("correct horse battery staple")
	if err != nil || !strings.HasPrefix(enc, "$argon2id$") {
		t.Fatalf("hash: %v %q", err, enc)
	}
	if ok, rehash := h.Verify("correct horse battery staple", enc); !ok || rehash {
		t.Fatalf("verify ok=%v rehash=%v", ok, rehash)
	}
	if ok, _ := h.Verify("wrong password!!", enc); ok {
		t.Fatal("wrong password accepted")
	}
	// another pepper = another hash universe
	if ok, _ := NewArgon2Hasher(p, "other").Verify("correct horse battery staple", enc); ok {
		t.Fatal("pepper ignored")
	}
	// parameter upgrade is detected
	p2 := p
	p2.MemoryKiB = 2048
	if ok, rehash := NewArgon2Hasher(p2, "pepper-for-tests").Verify("correct horse battery staple", enc); !ok || !rehash {
		t.Fatalf("expected needsRehash, got ok=%v rehash=%v", ok, rehash)
	}
	// tampered parameters are refused, not executed
	if ok, _ := h.Verify("x", "$argon2id$v=19$m=4294967295,t=1,p=1$AAAA$AAAA"); ok {
		t.Fatal("absurd params accepted")
	}
	h.Dummy("anything") // must not panic
}
