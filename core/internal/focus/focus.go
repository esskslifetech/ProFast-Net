// Package focus concentrates the link on one task.
package focus

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/esskslifetech/profast-net/core/internal/config"
	"github.com/esskslifetech/profast-net/core/internal/qos"
)

// Session describes an active focus window.
type Session struct {
	Target         string     `json:"target"`
	PID            int        `json:"pid,omitempty"`
	Started        time.Time  `json:"started"`
	EndsAt         time.Time  `json:"ends_at"`
	Boosted        bool       `json:"boosted"`
	EcoQoSRelaxed  bool       `json:"eco_qos_relaxed"`
	BackgroundCaps bool       `json:"background_caps"`
	Report         qos.Report `json:"report"`
}

// Manager owns the single active focus session.
type Manager struct {
	mu      sync.Mutex
	cfg     config.FocusConfig
	native  string
	current *Session
}

// New builds a focus manager. native is the path to the pfbench binary; an
// empty value disables native process tuning without failing the session.
func New(cfg config.FocusConfig, native string) *Manager {
	return &Manager{cfg: cfg, native: native}
}

// Start applies the focus policy and records the session.
func (m *Manager) Start(ctx context.Context, target string, pid int, duration time.Duration) (*Session, error) {
	if target == "" && pid <= 0 {
		return nil, fmt.Errorf("focus requires an application path or a pid")
	}
	if duration <= 0 {
		duration = time.Duration(m.cfg.DefaultDurationS) * time.Second
	}

	m.mu.Lock()
	already := m.current != nil
	m.mu.Unlock()
	if already {
		return nil, fmt.Errorf("a focus session is already running; stop it first")
	}

	plan := qos.FocusPlan{
		AppPath:        target,
		BackgroundDSCP: m.cfg.BackgroundDSCP,
		DSCP:           46,
		ThrottleOthers: m.cfg.ThrottleOthers,
	}
	report := qos.Apply(ctx, plan)

	session := &Session{
		Target:         target,
		PID:            pid,
		Started:        time.Now(),
		EndsAt:         time.Now().Add(duration),
		BackgroundCaps: m.cfg.ThrottleOthers,
		Report:         report,
	}

	if pid > 0 && m.native != "" {
		if m.cfg.BoostPriority {
			if err := m.runNative(ctx, "priority", pid, 2); err == nil {
				session.Boosted = true
			} else {
				session.Report.Skipped = append(session.Report.Skipped,
					"process priority: "+err.Error())
			}
		}
		if m.cfg.DisableEcoQoS {
			if err := m.runNative(ctx, "power", pid, 1); err == nil {
				session.EcoQoSRelaxed = true
			} else {
				session.Report.Skipped = append(session.Report.Skipped,
					"power throttling: "+err.Error())
			}
		}
	}

	m.mu.Lock()
	m.current = session
	m.mu.Unlock()

	return session, nil
}

// Stop reverts every policy and clears the session.
func (m *Manager) Stop(ctx context.Context) (*Session, error) {
	m.mu.Lock()
	session := m.current
	m.current = nil
	m.mu.Unlock()

	if session == nil {
		return nil, fmt.Errorf("no focus session is running")
	}

	revert := qos.Revert(ctx, qos.FocusPlan{AppPath: session.Target})
	session.Report.Applied = append(session.Report.Applied, revert.Applied...)
	session.Report.Errors = append(session.Report.Errors, revert.Errors...)

	if session.PID > 0 && m.native != "" {
		_ = m.runNative(ctx, "priority", session.PID, 0)
		_ = m.runNative(ctx, "power", session.PID, 0)
	}
	return session, nil
}

// Status returns the active session, or nil.
func (m *Manager) Status() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	snapshot := *m.current
	return &snapshot
}

// Expired reports whether the session has outlived its window.
func (m *Manager) Expired(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current != nil && now.After(m.current.EndsAt)
}

func (m *Manager) runNative(ctx context.Context, verb string, pid, value int) error {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(callCtx, m.native, verb, strconv.Itoa(pid), strconv.Itoa(value)).
		CombinedOutput()
	if err != nil {
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			return fmt.Errorf("%s", trimmed)
		}
		return err
	}
	return nil
}
