package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter()
	l.now = func() time.Time { return now }
	r := Rule{Limit: 3, Window: time.Minute}
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip1", r); !ok {
			t.Fatalf("request %d should pass", i)
		}
	}
	ok, wait := l.Allow("ip1", r)
	if ok || wait <= 0 || wait > 21*time.Second {
		t.Fatalf("4th request must be refused with a short wait, ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("ip2", r); !ok {
		t.Fatal("other keys are independent")
	}
	now = now.Add(21 * time.Second) // 3 per minute = 1 token / 20 s
	if ok, _ := l.Allow("ip1", r); !ok {
		t.Fatal("token should have refilled")
	}
}

func TestAttemptsWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	a := NewAttempts()
	a.now = func() time.Time { return now }
	a.Fail("k", time.Minute)
	a.Fail("k", time.Minute)
	if n, reset := a.Failures("k"); n != 2 || reset != time.Minute {
		t.Fatalf("n=%d reset=%v", n, reset)
	}
	now = now.Add(30 * time.Second)
	a.Fail("k", time.Minute) // window does not slide
	if n, reset := a.Failures("k"); n != 3 || reset != 30*time.Second {
		t.Fatalf("n=%d reset=%v", n, reset)
	}
	now = now.Add(31 * time.Second)
	if n, _ := a.Failures("k"); n != 0 {
		t.Fatal("window should have expired")
	}
	a.Fail("x", time.Minute)
	a.Clear("x")
	if n, _ := a.Failures("x"); n != 0 {
		t.Fatal("clear failed")
	}
}
