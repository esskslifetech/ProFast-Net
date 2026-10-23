// Package engine wires the subsystems together and exposes them over IPC.
package engine

import (
	"context"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/esskslifetech/ProFast-Net/core/internal/config"
	"github.com/esskslifetech/ProFast-Net/core/internal/consent"
	"github.com/esskslifetech/ProFast-Net/core/internal/defense"
	"github.com/esskslifetech/ProFast-Net/core/internal/firewall"
	"github.com/esskslifetech/ProFast-Net/core/internal/focus"
	"github.com/esskslifetech/ProFast-Net/core/internal/mirage"
	"github.com/esskslifetech/ProFast-Net/core/internal/scan"
	"github.com/esskslifetech/ProFast-Net/core/internal/version"
)

// Peer is a node that proved knowledge of the cluster secret.
type Peer struct {
	NodeID   uint32    `json:"node_id"`
	Source   string    `json:"source"`
	Epoch    uint64    `json:"epoch"`
	Address  string    `json:"virtual_address"`
	LastSeen time.Time `json:"last_seen"`
}

// Event is a short audit line surfaced to the UI.
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

// Engine is the daemon's state machine. Every exported method is safe for
// concurrent use; the IPC server calls into it from multiple connections.
type Engine struct {
	cfg       *config.Config
	secret    []byte
	consent   *consent.Store
	defense   *defense.Engine
	focus     *focus.Manager
	replay    *mirage.Replay
	nativeBin string
	started   time.Time

	mu      sync.Mutex
	epoch   uint64
	vaddr   net.IP
	port    uint16
	fwState firewall.Report
	fwAt    time.Time
	peers   map[uint32]*Peer
	scanned []scan.Service
	scanAt  time.Time
	events  []Event

	stopOnce sync.Once
	stopCh   chan struct{}
}

const maxEvents = 256

// New prepares an engine. It does not touch the host until Start is called.
func New(cfg *config.Config, nativeBin string) (*Engine, error) {
	secret, err := cfg.Secret()
	if err != nil {
		return nil, err
	}

	return &Engine{
		cfg:       cfg,
		secret:    secret,
		nativeBin: nativeBin,
		started:   time.Now(),
		consent:   consent.New(90 * time.Second),
		defense: defense.New(defense.Config{
			Enabled:       cfg.Defense.Enabled,
			AutoBan:       cfg.Defense.AutoBan,
			Threshold:     cfg.Defense.BanThreshold,
			Window:        time.Duration(cfg.Defense.WindowSeconds) * time.Second,
			ScanThreshold: cfg.Defense.ScanThreshold,
			InitialTTL:    time.Duration(cfg.Defense.InitialBanMin) * time.Minute,
			MaxTTL:        time.Duration(cfg.Defense.MaxBanHours) * time.Hour,
			MaxBans:       cfg.Defense.MaxBans,
			Tarpit:        cfg.Defense.Tarpit,
		}),
		focus:  focus.New(cfg.Focus, nativeBin),
		replay: mirage.NewReplay(4096),
		peers:  make(map[uint32]*Peer),
		stopCh: make(chan struct{}),
	}, nil
}

// Start derives the first locator and enters the epoch loop.
func (e *Engine) Start(ctx context.Context) {
	e.rotate(ctx)
	e.record("core", "daemon started, epoch "+strconv.FormatUint(e.epoch, 10))
	go e.epochLoop()
}

// Close reverts host state and stops background work.
func (e *Engine) Close() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if e.cfg.Firewall.Enabled {
			report := firewall.Reset(ctx)
			if len(report.Errors) > 0 {
				slog.Warn("firewall reset incomplete", "errors", report.Errors)
			}
		}
		if e.focus.Status() != nil {
			if _, err := e.focus.Stop(ctx); err != nil {
				slog.Warn("focus revert failed", "error", err)
			}
		}
	})
}

func (e *Engine) epochLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case now := <-ticker.C:
			if mirage.Epoch(now, e.cfg.Mirage.EpochSeconds) != e.currentEpoch() {
				e.rotate(context.Background())
			}
			if e.focus.Expired(now) {
				if _, err := e.focus.Stop(context.Background()); err == nil {
					e.record("focus", "session window elapsed, policies reverted")
				}
			}
		}
	}
}

// rotate moves the identity to the current epoch and keeps the firewall hole
// aligned with the new port when the aggressive posture is enabled.
func (e *Engine) rotate(ctx context.Context) {
	now := time.Now()
	epoch := mirage.Epoch(now, e.cfg.Mirage.EpochSeconds)

	addr, port, err := mirage.Derive(e.secret, e.cfg.Mirage.NodeID, epoch)
	if err != nil {
		e.record("mirage", "derivation failed: "+err.Error())
		return
	}

	e.mu.Lock()
	e.epoch = epoch
	e.vaddr = addr
	e.port = port
	e.mu.Unlock()

	if e.cfg.Firewall.Enabled && e.cfg.Firewall.BlockInbound {
		if _, err := e.applyFirewall(ctx, true, e.cfg.Firewall.AllowPorts); err != nil {
			slog.Warn("epoch firewall refresh failed", "error", err)
		}
	}
}

func (e *Engine) currentLocator() (uint64, net.IP, uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.epoch, e.vaddr, e.port
}

func (e *Engine) currentEpoch() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.epoch
}

func (e *Engine) record(kind, detail string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, Event{At: time.Now(), Kind: kind, Detail: detail})
	if len(e.events) > maxEvents {
		e.events = e.events[len(e.events)-maxEvents:]
	}
}

// Events returns the newest audit lines first.
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

// Status is the whole daemon state in one document.
func (e *Engine) Status() map[string]any {
	now := time.Now()
	epoch, addr, port := e.currentLocator()

	e.mu.Lock()
	peerCount := len(e.peers)
	fwState := e.fwState
	fwAt := e.fwAt
	scanCount := len(e.scanned)
	e.mu.Unlock()

	nextRotation := int(mirage.UntilBoundary(now, e.cfg.Mirage.EpochSeconds).Seconds())

	return map[string]any{
		"version":     version.Version,
		"protocol":    version.ProtocolVersion,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"pid":         os.Getpid(),
		"uptime_s":    int(now.Sub(e.started).Seconds()),
		"elevated":    firewall.Elevated(),
		"kernel_tier": kernelTier(),
		"mirage": map[string]any{
			"enabled":         e.cfg.Mirage.Enabled,
			"node_id":         e.cfg.Mirage.NodeID,
			"node_name":       e.cfg.Mirage.NodeName,
			"epoch":           epoch,
			"epoch_seconds":   e.cfg.Mirage.EpochSeconds,
			"virtual_address": mirage.Format(addr),
			"port":            port,
			"next_rotation_s": nextRotation,
			"peers":           peerCount,
			"replay_cache":    e.replay.Size(),
			"identity_model":  "rotating-virtual-locator",
		},
		"focus":   e.focus.Status(),
		"defense": e.defense.Stats(now),
		"firewall": map[string]any{
			"enabled":       e.cfg.Firewall.Enabled,
			"block_inbound": e.cfg.Firewall.BlockInbound,
			"allow_lan":     e.cfg.Firewall.AllowLAN,
			"backend":       fwState.Backend,
			"last_applied":  fwAt,
			"applied":       len(fwState.Applied),
			"errors":        fwState.Errors,
		},
		"scan": map[string]any{
			"services":  scanCount,
			"cached_at": e.scanAtCached(),
		},
	}
}

func (e *Engine) scanAtCached() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scanAt
}

func kernelTier() string {
	switch runtime.GOOS {
	case "windows":
		return "wfp (user-mode filters active, callout driver optional)"
	case "darwin":
		return "pf + network-extension (entitlement required for the extension)"
	default:
		return "nftables + xdp (libbpf loader optional)"
	}
}
