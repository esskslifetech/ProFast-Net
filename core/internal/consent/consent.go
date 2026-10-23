// Package consent enforces "ask the user first".
//
// Any destructive operation must be preceded by a short-lived, single-use
// token that is bound to the exact action and target set. The daemon refuses
// to act on a stale, reused or mismatched token, so a compromised client
// cannot silently kill services that the user approved an hour ago.
package consent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// ErrUnknown means the token was never issued or was already redeemed.
	ErrUnknown = errors.New("consent: unknown or already used confirmation token")
	// ErrExpired means the token outlived its time to live.
	ErrExpired = errors.New("consent: confirmation expired, ask the user again")
	// ErrMismatch means the token was issued for a different action or target.
	ErrMismatch = errors.New("consent: token does not match this request")
)

// Grant is an issued confirmation.
type Grant struct {
	Token   string    `json:"token"`
	Action  string    `json:"action"`
	Targets []string  `json:"targets"`
	Summary string    `json:"summary"`
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"expires"`
}

// Store keeps pending grants in memory. They are intentionally not persisted:
// restarting the daemon must invalidate every outstanding confirmation.
type Store struct {
	mu     sync.Mutex
	ttl    time.Duration
	grants map[string]*Grant
}

// New builds a store with the given token lifetime.
func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	return &Store{ttl: ttl, grants: make(map[string]*Grant)}
}

// Issue creates a token for one destructive action.
func (s *Store) Issue(action, summary string, targets []string) (*Grant, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}

	now := time.Now()
	grant := &Grant{
		Token:   hex.EncodeToString(raw),
		Action:  action,
		Targets: append([]string(nil), targets...),
		Summary: summary,
		Issued:  now,
		Expires: now.Add(s.ttl),
	}

	s.mu.Lock()
	s.grants[grant.Token] = grant
	s.pruneLocked(now)
	s.mu.Unlock()

	return grant, nil
}

// Redeem consumes a token. It fails when the token is unknown, expired, or was
// issued for a different action or target set.
func (s *Store) Redeem(token, action string, targets []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	grant, ok := s.grants[token]
	if !ok {
		return ErrUnknown
	}
	delete(s.grants, token)

	if time.Now().After(grant.Expires) {
		return ErrExpired
	}
	if grant.Action != action {
		return ErrMismatch
	}
	if fingerprint(grant.Targets) != fingerprint(targets) {
		return ErrMismatch
	}
	return nil
}

// Revoke invalidates a single token without redeeming it.
func (s *Store) Revoke(token string) {
	s.mu.Lock()
	delete(s.grants, token)
	s.mu.Unlock()
}

// Pending lists the grants the user still has to answer.
func (s *Store) Pending() []Grant {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		if now.Before(g.Expires) {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issued.Before(out[j].Issued) })
	return out
}

func (s *Store) pruneLocked(now time.Time) {
	for token, grant := range s.grants {
		if now.After(grant.Expires) {
			delete(s.grants, token)
		}
	}
}

// fingerprint normalises the target set so ordering never matters.
func fingerprint(targets []string) string {
	normalised := make([]string, 0, len(targets))
	for _, t := range targets {
		normalised = append(normalised, strings.TrimSpace(strings.ToLower(t)))
	}
	sort.Strings(normalised)

	sum := sha256.Sum256([]byte(strings.Join(normalised, "\x00")))
	return hex.EncodeToString(sum[:])
}
