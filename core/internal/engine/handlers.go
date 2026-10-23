package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/esskslifetech/ProFast-Net/core/internal/consent"
	"github.com/esskslifetech/ProFast-Net/core/internal/defense"
	"github.com/esskslifetech/ProFast-Net/core/internal/firewall"
	"github.com/esskslifetech/ProFast-Net/core/internal/ipc"
	"github.com/esskslifetech/ProFast-Net/core/internal/mirage"
	"github.com/esskslifetech/ProFast-Net/core/internal/scan"
	"github.com/esskslifetech/ProFast-Net/core/internal/version"
)

func decodeParams[T any](raw json.RawMessage, out *T) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ipc.Coded(ipc.CodeInvalidParams, "invalid params: %v", err)
	}
	return nil
}

// Handle dispatches one JSON-RPC method.
func (e *Engine) Handle(method string, params json.RawMessage) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	switch method {
	case "core.ping":
		return map[string]any{"ok": true, "version": version.Version, "protocol": version.ProtocolVersion}, nil

	case "core.status":
		return e.Status(), nil

	case "core.capabilities":
		return e.capabilities(), nil

	case "core.config":
		return e.cfg, nil

	case "core.events":
		var p struct {
			Limit int `json:"limit"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return e.Events(p.Limit), nil

	case "mirage.status":
		return e.Status()["mirage"], nil

	case "mirage.rotate":
		e.rotate(ctx)
		epoch, addr, port := e.currentLocator()
		return map[string]any{"epoch": epoch, "virtual_address": mirage.Format(addr), "port": port}, nil

	case "mirage.peers":
		return e.peerList(), nil

	case "mirage.spa":
		return e.mintSPA(params)

	case "mirage.accept":
		return e.acceptSPA(params)

	case "focus.start":
		var p struct {
			Target    string `json:"target"`
			PID       int    `json:"pid"`
			DurationS int    `json:"duration_s"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		session, err := e.focus.Start(ctx, p.Target, p.PID, time.Duration(p.DurationS)*time.Second)
		if err != nil {
			return nil, ipc.Coded(ipc.CodeUnavailable, "%s", err.Error())
		}
		e.record("focus", "started for "+p.Target)
		return session, nil

	case "focus.stop":
		session, err := e.focus.Stop(ctx)
		if err != nil {
			return nil, ipc.Coded(ipc.CodeUnavailable, "%s", err.Error())
		}
		e.record("focus", "stopped, policies reverted")
		return session, nil

	case "focus.status":
		return e.focus.Status(), nil

	case "scan.services":
		var p struct {
			Refresh bool `json:"refresh"`
			MinRisk int  `json:"min_risk"`
			Limit   int  `json:"limit"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		list, err := e.scanServices(ctx, p.Refresh)
		if err != nil {
			return nil, err
		}
		return filterServices(list, p.MinRisk, p.Limit), nil

	case "scan.risky":
		list, err := e.scanServices(ctx, false)
		if err != nil {
			return nil, err
		}
		return filterServices(list, 55, 0), nil

	case "consent.request":
		var p struct {
			Action  string   `json:"action"`
			Summary string   `json:"summary"`
			Targets []string `json:"targets"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if p.Action == "" {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "action is required")
		}
		grant, err := e.consent.Issue(p.Action, p.Summary, p.Targets)
		if err != nil {
			return nil, ipc.Coded(ipc.CodeInternal, "%s", err.Error())
		}
		e.record("consent", "requested: "+p.Action)
		return grant, nil

	case "consent.pending":
		return e.consent.Pending(), nil

	case "consent.revoke":
		var p struct {
			Token string `json:"token"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		e.consent.Revoke(p.Token)
		return map[string]any{"revoked": true}, nil

	case "services.terminate":
		return e.terminate(params)

	case "firewall.plan":
		var p firewallParams
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return firewall.Build(e.firewallRequest(p.block(), p.AllowPorts, p.allowLAN(e.cfg.Firewall.AllowLAN))), nil

	case "firewall.apply":
		var p firewallParams
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		report, err := e.applyFirewall(ctx, p.block(), p.AllowPorts)
		if err != nil {
			return report, ipc.Coded(ipc.CodeElevation, "%s", err.Error())
		}
		return report, nil

	case "firewall.reset":
		report := firewall.Reset(ctx)
		e.record("firewall", "all ProFast rules removed")
		return report, nil

	case "firewall.status":
		e.mu.Lock()
		defer e.mu.Unlock()
		return map[string]any{"report": e.fwState, "applied_at": e.fwAt}, nil

	case "defense.status":
		return e.defense.Stats(time.Now()), nil

	case "defense.bans":
		return e.defense.Bans(time.Now()), nil

	case "defense.ban":
		var p struct {
			IP      string `json:"ip"`
			Reason  string `json:"reason"`
			Minutes int    `json:"minutes"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		ip, ok := defense.NormalizeIP(p.IP)
		if !ok {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "not an IP address: %q", p.IP)
		}
		if p.Reason == "" {
			p.Reason = "manual ban"
		}
		ban := e.defense.Ban(ip, p.Reason, time.Now())
		e.record("defense", "banned "+ip+": "+p.Reason)
		return ban, nil

	case "defense.unban":
		var p struct {
			IP string `json:"ip"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		ip, ok := defense.NormalizeIP(p.IP)
		if !ok {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "not an IP address: %q", p.IP)
		}
		removed := e.defense.Unban(ip)
		e.record("defense", "unbanned "+ip)
		return map[string]any{"unbanned": removed}, nil

	case "defense.observe":
		var p struct {
			Source string `json:"source"`
			Port   int    `json:"port"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		ip, ok := defense.NormalizeIP(p.Source)
		if !ok {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "not an IP address: %q", p.Source)
		}
		return e.defense.Observe(ip, p.Port, time.Now()), nil
	}

	return nil, ipc.Coded(ipc.CodeMethodNotFound, "unknown method %q", method)
}

type firewallParams struct {
	BlockInbound *bool `json:"block_inbound"`
	AllowLAN     *bool `json:"allow_lan"`
	AllowPorts   []int `json:"allow_ports"`
}

func (p firewallParams) block() bool {
	return p.BlockInbound != nil && *p.BlockInbound
}

func (p firewallParams) allowLAN(fallback bool) bool {
	if p.AllowLAN == nil {
		return fallback
	}
	return *p.AllowLAN
}

func (e *Engine) capabilities() map[string]any {
	backend, backendErr := firewall.Available()

	features := []string{
		"focus.dscp",
		"focus.process-priority",
		"scan.services",
		"scan.risk",
		"defense.escalating-bans",
		"firewall.os-native",
		"mirage.rotating-locator",
		"mirage.spa",
	}
	if runtime.GOOS == "windows" {
		features = append(features, "focus.eco-qos-relax")
	}

	return map[string]any{
		"os":                 runtime.GOOS,
		"arch":               runtime.GOARCH,
		"elevated":           firewall.Elevated(),
		"firewall_backend":   backend,
		"firewall_available": backendErr == nil,
		"firewall_error":     errString(backendErr),
		"native_bridge":      e.nativeBin != "",
		"native_path":        e.nativeBin,
		"kernel_tier":        kernelTier(),
		"features":           features,
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (e *Engine) firewallRequest(block bool, ports []int, allowLAN bool) firewall.Request {
	_, _, port := e.currentLocator()
	return firewall.Request{
		BlockInbound: block,
		AllowLAN:     allowLAN,
		AllowPorts:   ports,
		MiragePort:   port,
		SPAPort:      port,
		Interface:    e.cfg.Mirage.Interface,
	}
}

func (e *Engine) applyFirewall(ctx context.Context, block bool, ports []int) (firewall.Report, error) {
	plan := firewall.Build(e.firewallRequest(block, ports, e.cfg.Firewall.AllowLAN))
	report, err := plan.Apply(ctx)

	e.mu.Lock()
	e.fwState = report
	e.fwAt = time.Now()
	e.mu.Unlock()

	e.record("firewall", fmt.Sprintf("%d rule(s) applied, %d error(s)",
		len(report.Applied), len(report.Errors)))
	return report, err
}

func (e *Engine) terminate(params json.RawMessage) (any, error) {
	var p struct {
		PIDs  []int  `json:"pids"`
		Token string `json:"token"`
		Force bool   `json:"force"`
	}
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if len(p.PIDs) == 0 {
		return nil, ipc.Coded(ipc.CodeInvalidParams, "pids is required")
	}
	if len(p.PIDs) > 64 {
		return nil, ipc.Coded(ipc.CodeInvalidParams, "at most 64 processes per request")
	}

	targets := make([]string, 0, len(p.PIDs))
	for _, pid := range p.PIDs {
		if pid <= 4 || pid == os.Getpid() {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "refusing to terminate pid %d", pid)
		}
		targets = append(targets, "pid:"+strconv.Itoa(pid))
	}
	sort.Strings(targets)

	if err := e.consent.Redeem(p.Token, "services.terminate", targets); err != nil {
		switch {
		case errors.Is(err, consent.ErrExpired):
			return nil, ipc.Coded(ipc.CodeConsentRequired, "confirmation expired, ask the user again")
		case errors.Is(err, consent.ErrMismatch):
			return nil, ipc.Coded(ipc.CodeConsentRequired, "confirmation was for a different process set")
		default:
			return nil, ipc.Coded(ipc.CodeConsentRequired, "a user confirmation is required before terminating processes")
		}
	}

	terminated := make([]int, 0, len(p.PIDs))
	failed := make([]map[string]any, 0)

	for _, pid := range p.PIDs {
		if err := terminateProcess(pid, p.Force); err != nil {
			failed = append(failed, map[string]any{"pid": pid, "error": err.Error()})
			continue
		}
		terminated = append(terminated, pid)
	}

	e.record("services", fmt.Sprintf("terminated %d process(es), %d failed",
		len(terminated), len(failed)))
	slog.Info("terminate request", "terminated", terminated, "failed", len(failed))

	if len(failed) > 0 {
		return map[string]any{"ok": false, "terminated": terminated, "failed": failed}, nil
	}
	return map[string]any{"ok": true, "terminated": terminated, "failed": failed}, nil
}

func terminateProcess(pid int, force bool) error {
	if pid <= 4 {
		return fmt.Errorf("pid %d is a system process", pid)
	}
	if pid == os.Getpid() {
		return fmt.Errorf("refusing to terminate the daemon itself")
	}

	if runtime.GOOS == "windows" {
		args := []string{"/PID", strconv.Itoa(pid), "/T"}
		if force {
			args = append(args, "/F")
		}
		out, err := exec.Command("taskkill", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if force {
		return proc.Kill()
	}
	if err := proc.Signal(os.Interrupt); err != nil {
		return proc.Kill()
	}
	return nil
}

func (e *Engine) scanServices(ctx context.Context, refresh bool) ([]scan.Service, error) {
	e.mu.Lock()
	cached, at := e.scanned, e.scanAt
	e.mu.Unlock()

	if !refresh && cached != nil && time.Since(at) < 45*time.Second {
		return cached, nil
	}

	list, err := scan.List(ctx)
	if err != nil {
		return nil, ipc.Coded(ipc.CodeUnavailable, "service scan failed: %s", err.Error())
	}

	e.mu.Lock()
	e.scanned = list
	e.scanAt = time.Now()
	e.mu.Unlock()

	return list, nil
}

func filterServices(list []scan.Service, minRisk, limit int) []scan.Service {
	out := make([]scan.Service, 0, len(list))
	for _, svc := range list {
		if svc.Risk >= minRisk {
			out = append(out, svc)
		}
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (e *Engine) mintSPA(params json.RawMessage) (any, error) {
	var p struct {
		NodeID   uint32 `json:"node_id"`
		NonceHex string `json:"nonce_hex"`
	}
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if p.NodeID == 0 {
		p.NodeID = e.cfg.Mirage.NodeID
	}

	nonce := make([]byte, 16)
	if p.NonceHex != "" {
		decoded, err := hex.DecodeString(p.NonceHex)
		if err != nil || len(decoded) != 16 {
			return nil, ipc.Coded(ipc.CodeInvalidParams, "nonce_hex must be 16 hex-encoded bytes")
		}
		copy(nonce, decoded)
	} else if _, err := rand.Read(nonce); err != nil {
		return nil, ipc.Coded(ipc.CodeInternal, "%s", err.Error())
	}

	epoch := mirage.Epoch(time.Now(), e.cfg.Mirage.EpochSeconds)
	_, encoded, err := mirage.Mint(e.secret, p.NodeID, epoch, nonce)
	if err != nil {
		return nil, ipc.Coded(ipc.CodeInternal, "%s", err.Error())
	}

	addr, port, _ := mirage.Derive(e.secret, p.NodeID, epoch)
	return map[string]any{
		"token":           encoded,
		"node_id":         p.NodeID,
		"epoch":           epoch,
		"virtual_address": mirage.Format(addr),
		"port":            port,
		"expires_in_s":    int(mirage.UntilBoundary(time.Now(), e.cfg.Mirage.EpochSeconds).Seconds()),
	}, nil
}

func (e *Engine) acceptSPA(params json.RawMessage) (any, error) {
	var p struct {
		Token  string `json:"token"`
		Source string `json:"source"`
		Port   int    `json:"port"`
	}
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}

	now := time.Now()
	nodeID, epoch, err := mirage.VerifyB64(e.secret, p.Token, now, e.cfg.Mirage.EpochSeconds)
	if err != nil {
		_, _, port := e.currentLocator()
		decision := e.defense.Observe(p.Source, int(port), now)
		e.record("mirage", "rejected SPA from "+p.Source+": "+err.Error())
		return map[string]any{"accepted": false, "reason": err.Error(), "defense": decision},
			ipc.Coded(ipc.CodeUnauthorized, "single packet authorization rejected")
	}

	raw, decodeErr := base64.RawURLEncoding.DecodeString(p.Token)
	if decodeErr != nil {
		return nil, ipc.Coded(ipc.CodeInvalidParams, "token is not base64url")
	}
	if e.replay.Check(raw) {
		e.record("mirage", "replay attempt from "+p.Source)
		return map[string]any{"accepted": false, "reason": "replayed token"},
			ipc.Coded(ipc.CodeUnauthorized, "token already used")
	}

	addr, port, _ := mirage.Derive(e.secret, nodeID, epoch)

	e.mu.Lock()
	e.peers[nodeID] = &Peer{
		NodeID: nodeID, Source: p.Source, Epoch: epoch,
		Address: mirage.Format(addr), LastSeen: now,
	}
	e.mu.Unlock()

	e.record("mirage", fmt.Sprintf("peer %d authorized from %s", nodeID, p.Source))
	return map[string]any{
		"accepted":        true,
		"node_id":         nodeID,
		"epoch":           epoch,
		"virtual_address": mirage.Format(addr),
		"port":            port,
		"source":          p.Source,
	}, nil
}

func (e *Engine) peerList() []Peer {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]Peer, 0, len(e.peers))
	for _, peer := range e.peers {
		out = append(out, *peer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
