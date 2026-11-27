// Package memory is an in-process store: used by the tests and for a quick start without a database
// (STORE=memory). Data disappears on restart.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"famku/internal/domain"
)

type Store struct {
	mu       sync.Mutex
	users    map[string]*domain.User
	sessions map[string]*domain.Session
	tokens   map[string]*domain.OneTimeToken
	recovery map[string]*domain.RecoveryCode
	audit    []*domain.AuditEvent
}

func New() *Store {
	return &Store{users: map[string]*domain.User{}, sessions: map[string]*domain.Session{},
		tokens: map[string]*domain.OneTimeToken{}, recovery: map[string]*domain.RecoveryCode{}}
}

func cp[T any](v *T) *T { c := *v; return &c }

// Audit returns a copy of the recorded events (tests).
func (s *Store) Audit() []*domain.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*domain.AuditEvent(nil), s.audit...)
}

// ---- users -------------------------------------------------------------------------------------

type Users struct{ *Store }

func (s *Store) Users() Users { return Users{s} }

func (r Users) Create(_ context.Context, u *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.users {
		if x.Email == u.Email || x.Username == u.Username {
			return domain.ErrConflict
		}
	}
	r.users[u.ID] = cp(u)
	return nil
}

func (r Users) ByID(_ context.Context, id string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u, ok := r.users[id]; ok {
		return cp(u), nil
	}
	return nil, domain.ErrNotFound
}

func (r Users) ByEmail(_ context.Context, email string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Email == email {
			return cp(u), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r Users) ByUsername(_ context.Context, username string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Username == username {
			return cp(u), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r Users) Update(_ context.Context, u *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[u.ID]; !ok {
		return domain.ErrNotFound
	}
	for _, x := range r.users {
		if x.ID != u.ID && x.Username == u.Username {
			return domain.ErrConflict
		}
	}
	r.users[u.ID] = cp(u)
	return nil
}

// ---- sessions ----------------------------------------------------------------------------------

type Sessions struct{ *Store }

func (s *Store) Sessions() Sessions { return Sessions{s} }

func (r Sessions) Create(_ context.Context, x *domain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[x.ID] = cp(x)
	return nil
}

func (r Sessions) ByTokenHash(_ context.Context, h string) (*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, x := range r.sessions {
		if x.TokenHash == h {
			return cp(x), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r Sessions) Touch(_ context.Context, id string, seen time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if x, ok := r.sessions[id]; ok {
		x.LastSeenAt = seen
	}
	return nil
}

func (r Sessions) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

func (r Sessions) DeleteByUser(_ context.Context, userID, except string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, x := range r.sessions {
		if x.UserID == userID && id != except {
			delete(r.sessions, id)
		}
	}
	return nil
}

func (r Sessions) ListByUser(_ context.Context, userID string) ([]*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*domain.Session
	for _, x := range r.sessions {
		if x.UserID == userID {
			out = append(out, cp(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (r Sessions) DeleteExpired(_ context.Context, now time.Time, idle time.Duration) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, x := range r.sessions {
		if now.After(x.ExpiresAt) || now.After(x.LastSeenAt.Add(idle)) {
			delete(r.sessions, id)
			n++
		}
	}
	return n, nil
}

// ---- one-time tokens ---------------------------------------------------------------------------

type Tokens struct{ *Store }

func (s *Store) Tokens() Tokens { return Tokens{s} }

func (r Tokens) Create(_ context.Context, t *domain.OneTimeToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[t.ID] = cp(t)
	return nil
}

func (r Tokens) ByHash(_ context.Context, p domain.TokenPurpose, h string) (*domain.OneTimeToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokens {
		if t.Purpose == p && t.TokenHash == h {
			return cp(t), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r Tokens) MarkUsed(_ context.Context, id string, at time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tokens[id]
	if !ok || t.UsedAt != nil {
		return false, nil
	}
	t.UsedAt = &at
	return true, nil
}

func (r Tokens) DeleteByUser(_ context.Context, userID string, p domain.TokenPurpose) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.tokens {
		if t.UserID == userID && t.Purpose == p {
			delete(r.tokens, id)
		}
	}
	return nil
}

func (r Tokens) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, t := range r.tokens {
		if now.After(t.ExpiresAt) {
			delete(r.tokens, id)
			n++
		}
	}
	return n, nil
}

// ---- recovery codes ----------------------------------------------------------------------------

type Recovery struct{ *Store }

func (s *Store) Recovery() Recovery { return Recovery{s} }

func (r Recovery) Replace(_ context.Context, userID string, codes []*domain.RecoveryCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, c := range r.recovery {
		if c.UserID == userID {
			delete(r.recovery, id)
		}
	}
	for _, c := range codes {
		r.recovery[c.ID] = cp(c)
	}
	return nil
}

func (r Recovery) Consume(_ context.Context, userID, hash string, at time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.recovery {
		if c.UserID == userID && c.CodeHash == hash && c.UsedAt == nil {
			c.UsedAt = &at
			return true, nil
		}
	}
	return false, nil
}

func (r Recovery) CountUnused(_ context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.recovery {
		if c.UserID == userID && c.UsedAt == nil {
			n++
		}
	}
	return n, nil
}

// ---- audit -------------------------------------------------------------------------------------

type Audit struct{ *Store }

func (s *Store) AuditLog() Audit { return Audit{s} }

func (r Audit) Add(_ context.Context, e *domain.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = append(r.audit, cp(e))
	return nil
}
