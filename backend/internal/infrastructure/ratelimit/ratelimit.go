// Package ratelimit holds in-memory limiters. They are per process: fine for one container, and behind the
// same small interfaces a shared store (Redis) can replace them when you run several replicas.
package ratelimit

import (
	"sync"
	"time"
)

const maxKeys = 200_000 // memory bound: an attacker rotating keys cannot grow the maps without limit

// Rule allows Limit events per Window (token bucket: refills evenly, bursts up to Limit).
type Rule struct {
	Limit  int
	Window time.Duration
}

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

func NewLimiter() *Limiter { return &Limiter{buckets: map[string]*bucket{}, now: time.Now} }

// Allow consumes one token for key. When refused it says how long to wait.
func (l *Limiter) Allow(key string, r Rule) (bool, time.Duration) {
	if r.Limit <= 0 {
		return false, r.Window
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxKeys {
			l.evictLocked(now)
		}
		b = &bucket{tokens: float64(r.Limit), last: now}
		l.buckets[key] = b
	}
	rate := float64(r.Limit) / r.Window.Seconds() // tokens per second
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > float64(r.Limit) {
		b.tokens = float64(r.Limit)
	}
	b.last = now
	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
		return false, wait
	}
	b.tokens--
	return true, 0
}

// evictLocked drops idle (full) buckets, then arbitrary ones if still too big.
func (l *Limiter) evictLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
	for k := range l.buckets {
		if len(l.buckets) < maxKeys*9/10 {
			return
		}
		delete(l.buckets, k)
	}
}

// Sweep removes buckets idle for more than 10 minutes (call periodically).
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

// Attempts counts failures per key inside a fixed window that starts at the first failure.
// It implements usecase.AttemptCounter.
type Attempts struct {
	mu  sync.Mutex
	m   map[string]*entry
	now func() time.Time
}

type entry struct {
	n   int
	end time.Time
}

func NewAttempts() *Attempts { return &Attempts{m: map[string]*entry{}, now: time.Now} }

func (a *Attempts) Failures(key string) (int, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.m[key]
	if !ok {
		return 0, 0
	}
	now := a.now()
	if !now.Before(e.end) {
		delete(a.m, key)
		return 0, 0
	}
	return e.n, e.end.Sub(now)
}

func (a *Attempts) Fail(key string, window time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	e, ok := a.m[key]
	if !ok || !now.Before(e.end) {
		if len(a.m) >= maxKeys {
			for k, v := range a.m { // drop expired, else arbitrary
				if !now.Before(v.end) || len(a.m) >= maxKeys {
					delete(a.m, k)
				}
				if len(a.m) < maxKeys*9/10 {
					break
				}
			}
		}
		a.m[key] = &entry{n: 1, end: now.Add(window)}
		return
	}
	e.n++
}

func (a *Attempts) Clear(key string) {
	a.mu.Lock()
	delete(a.m, key)
	a.mu.Unlock()
}

func (a *Attempts) Sweep() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, e := range a.m {
		if !now.Before(e.end) {
			delete(a.m, k)
		}
	}
}
