// Package defense implements the reactive half of the virtual firewall.
//
// It watches inbound attempts, detects scans and floods, and escalates bans
// from minutes to hours. It never counter-attacks: hack-back is illegal in most
// jurisdictions and turns a defensive tool into a liability. "Forceful" here
// means the machine defends itself aggressively and immediately, not that it
// goes looking for the attacker.
package defense

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Config tunes the escalation ladder.
type Config struct {
	Enabled       bool
	AutoBan       bool
	Threshold     int
	Window        time.Duration
	ScanThreshold int
	InitialTTL    time.Duration
	MaxTTL        time.Duration
	MaxBans       int
	Tarpit        bool
}

// Ban is one blocked source.
type Ban struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Hits      int       `json:"hits"`
	Level     int       `json:"level"`
}

// Event is an audit line for the UI.
type Event struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
	Score  int       `json:"score"`
}

// Decision is the verdict for one inbound attempt.
type Decision struct {
	Action     string `json:"action"` // allow | tarpit | drop
	Reason     string `json:"reason"`
	BanSeconds int    `json:"ban_seconds,omitempty"`
}

// Engine is safe for concurrent use.
type Engine struct {
	mu       sync.Mutex
	cfg      Config
	attempts map[string][]time.Time
	ports    map[string]map[int]struct{}
	bans     map[string]*Ban
	history  map[string]int
	events   []Event
}

const maxEvents = 512

// New builds an engine from configuration.
func New(cfg Config) *Engine {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 40
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Second
	}
	if cfg.ScanThreshold <= 0 {
		cfg.ScanThreshold = 20
	}
	if cfg.InitialTTL <= 0 {
		cfg.InitialTTL = 5 * time.Minute
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = 24 * time.Hour
	}
	if cfg.MaxBans <= 0 {
		cfg.MaxBans = 4096
	}
	return &Engine{
		cfg:      cfg,
		attempts: make(map[string][]time.Time),
		ports:    make(map[string]map[int]struct{}),
		bans:     make(map[string]*Ban),
		history:  make(map[string]int),
	}
}

// Observe records an inbound attempt and returns the verdict.
func (e *Engine) Observe(source string, port int, now time.Time) Decision {
	if !e.cfg.Enabled {
		return Decision{Action: "allow", Reason: "defense disabled"}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if ban, ok := e.bans[source]; ok {
		if now.Before(ban.ExpiresAt) {
			ban.Hits++
			return Decision{Action: "drop", Reason: "source is banned: " + ban.Reason,
				BanSeconds: int(ban.ExpiresAt.Sub(now).Seconds())}
		}
		delete(e.bans, source)
	}

	cutoff := now.Add(-e.cfg.Window)
	hits := e.attempts[source]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	e.attempts[source] = kept

	if e.ports[source] == nil {
		e.ports[source] = make(map[int]struct{})
	}
	e.ports[source][port] = struct{}{}
	fanout := len(e.ports[source])

	if !e.cfg.AutoBan {
		return Decision{Action: "allow", Reason: "monitor only"}
	}

	if fanout >= e.cfg.ScanThreshold {
		seconds := e.banLocked(source, "port scan", now)
		delete(e.ports, source)
		return Decision{Action: "drop", Reason: "port scan detected", BanSeconds: int(seconds)}
	}

	if len(kept) >= e.cfg.Threshold {
		seconds := e.banLocked(source, "connection flood", now)
		return Decision{Action: "drop", Reason: "connection flood detected", BanSeconds: int(seconds)}
	}

	if e.cfg.Tarpit && len(kept) >= e.cfg.Threshold/2 {
		return Decision{Action: "tarpit", Reason: "throttling probe rate"}
	}

	return Decision{Action: "allow", Reason: "within policy"}
}

// banLocked registers a ban and returns its duration in seconds.
func (e *Engine) banLocked(source, reason string, now time.Time) int64 {
	level := e.history[source]
	ttl := e.cfg.InitialTTL
	for i := 0; i < level; i++ {
		ttl *= 2
		if ttl >= e.cfg.MaxTTL {
			ttl = e.cfg.MaxTTL
			break
		}
	}

	if len(e.bans) >= e.cfg.MaxBans {
		e.evictOldestLocked()
	}

	e.bans[source] = &Ban{
		IP: source, Reason: reason, BannedAt: now, ExpiresAt: now.Add(ttl),
		Level: level,
	}
	e.history[source] = level + 1
	e.pushEventLocked(Event{At: now, Source: source, Kind: "ban",
		Detail: reason, Score: 100})

	if len(e.events) >= maxEvents {
		e.events = e.events[len(e.events)-maxEvents+1:]
	}
	return int64(ttl.Seconds())
}

func (e *Engine) evictOldestLocked() {
	var oldest string
	var when time.Time
	first := true
	for ip, ban := range e.bans {
		if first || ban.BannedAt.Before(when) {
			oldest, when, first = ip, ban.BannedAt, false
		}
	}
	if oldest != "" {
		delete(e.bans, oldest)
	}
}

// Ban blocks a source explicitly, for example from the UI.
func (e *Engine) Ban(source, reason string, now time.Time) *Ban {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.banLocked(source, reason, now)
	return e.bans[source]
}

// Unban releases a source and resets its escalation level.
func (e *Engine) Unban(source string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, existed := e.bans[source]
	delete(e.bans, source)
	delete(e.attempts, source)
	delete(e.ports, source)
	delete(e.history, source)
	return existed
}

// Blocked reports whether a source is currently banned.
func (e *Engine) Blocked(source string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ban, ok := e.bans[source]
	return ok && now.Before(ban.ExpiresAt)
}

// Bans returns the active ban list, newest first.
func (e *Engine) Bans(now time.Time) []Ban {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]Ban, 0, len(e.bans))
	for ip, ban := range e.bans {
		if now.After(ban.ExpiresAt) {
			delete(e.bans, ip)
			continue
		}
		out = append(out, *ban)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BannedAt.After(out[j].BannedAt) })
	return out
}

// Events returns the most recent audit lines, newest first.
func (e *Engine) Events(limit int) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()

	if limit <= 0 || limit > len(e.events) {
		limit = len(e.events)
	}
	out := make([]Event, 0, limit)
	for i := len(e.events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, e.events[i])
	}
	return out
}

// Stats summarises the defense state for the dashboard.
func (e *Engine) Stats(now time.Time) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()

	active := 0
	for _, ban := range e.bans {
		if now.Before(ban.ExpiresAt) {
			active++
		}
	}
	return map[string]any{
		"enabled":     e.cfg.Enabled,
		"auto_ban":    e.cfg.AutoBan,
		"active_bans": active,
		"tracked":     len(e.attempts),
		"tarpit":      e.cfg.Tarpit,
	}
}

func (e *Engine) pushEventLocked(ev Event) {
	e.events = append(e.events, ev)
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
}

// NormalizeIP reduces a host:port or CIDR to a bare address, rejecting junk.
func NormalizeIP(value string) (string, bool) {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}
