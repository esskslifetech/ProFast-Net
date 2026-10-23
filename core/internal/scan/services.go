// Package scan enumerates local listening services and scores their risk.
//
// It deliberately shells out to the platform's own inventory tools instead of
// shipping a packet sniffer: `Get-NetTCPConnection` on Windows, `ss` on Linux
// and `lsof` on macOS. That keeps the dependency footprint at zero and means
// the list always matches what the OS believes is listening.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Service is one listening endpoint.
type Service struct {
	PID      int      `json:"pid"`
	Process  string   `json:"process"`
	Path     string   `json:"path,omitempty"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Address  string   `json:"address"`
	Public   bool     `json:"public"`
	Risk     int      `json:"risk"`
	Level    string   `json:"level"`
	Reasons  []string `json:"reasons"`
	System   bool     `json:"system"`
}

// List returns every listening TCP/UDP endpoint, highest risk first.
func List(ctx context.Context) ([]Service, error) {
	var (
		services []Service
		err      error
	)

	switch runtime.GOOS {
	case "windows":
		services, err = listWindows(ctx)
	case "darwin":
		services, err = listDarwin(ctx)
	default:
		services, err = listLinux(ctx)
	}
	if err != nil {
		return nil, err
	}

	deduped := dedupe(services)
	for i := range deduped {
		req := &deduped[i]
		req.Public = isPublic(req.Address)
		req.System = isSystemProcess(req.Process)
		req.Risk, req.Level, req.Reasons = Score(req)
	}

	sort.SliceStable(deduped, func(i, j int) bool {
		if deduped[i].Risk != deduped[j].Risk {
			return deduped[i].Risk > deduped[j].Risk
		}
		return deduped[i].Port < deduped[j].Port
	})
	return deduped, nil
}

func isPublic(address string) bool {
	switch address {
	case "", "*", "0.0.0.0", "::", "[::]", "any", "Any":
		return true
	}
	return false
}

func isSystemProcess(name string) bool {
	switch strings.ToLower(name) {
	case "system", "svchost", "lsass", "services", "wininit", "smss", "csrss",
		"kernel_task", "launchd", "systemd", "init", "root":
		return true
	}
	return false
}

func dedupe(in []Service) []Service {
	seen := make(map[string]int, len(in))
	out := make([]Service, 0, len(in))

	for _, s := range in {
		if s.Port == 0 {
			continue
		}
		key := fmt.Sprintf("%s|%d|%d", s.Protocol, s.Port, s.PID)
		if idx, ok := seen[key]; ok {
			// Keep the more exposed binding (0.0.0.0 wins over 127.0.0.1).
			if isPublic(s.Address) && !isPublic(out[idx].Address) {
				out[idx].Address = s.Address
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, s)
	}
	return out
}

/* ------------------------------------------------------------- windows -- */

type winEndpoint struct {
	LocalAddress  string
	LocalPort     int
	OwningProcess int
}

type winProcess struct {
	Id          int
	ProcessName string
	Path        string
}

func decodeList[T any](raw []byte) ([]T, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var list []T
		if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var single T
	if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
		return nil, err
	}
	return []T{single}, nil
}

func powershellJSON(ctx context.Context, script string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell inventory failed: %w", err)
	}
	return out, nil
}

func listWindows(ctx context.Context) ([]Service, error) {
	procsRaw, err := powershellJSON(ctx,
		"Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	procs, err := decodeList[winProcess](procsRaw)
	if err != nil {
		return nil, err
	}
	procIndex := make(map[int]winProcess, len(procs))
	for _, p := range procs {
		procIndex[p.Id] = p
	}

	var services []Service

	tcpRaw, err := powershellJSON(ctx,
		"Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress")
	if err == nil {
		endpoints, _ := decodeList[winEndpoint](tcpRaw)
		for _, ep := range endpoints {
			p := procIndex[ep.OwningProcess]
			services = append(services, Service{
				PID: ep.OwningProcess, Process: p.ProcessName, Path: p.Path,
				Port: ep.LocalPort, Protocol: "tcp", Address: ep.LocalAddress,
			})
		}
	}

	udpRaw, err := powershellJSON(ctx,
		"Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress")
	if err == nil {
		endpoints, _ := decodeList[winEndpoint](udpRaw)
		for _, ep := range endpoints {
			p := procIndex[ep.OwningProcess]
			services = append(services, Service{
				PID: ep.OwningProcess, Process: p.ProcessName, Path: p.Path,
				Port: ep.LocalPort, Protocol: "udp", Address: ep.LocalAddress,
			})
		}
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no listening endpoints reported (is the inventory cmdlet available?)")
	}
	return services, nil
}

/* --------------------------------------------------------------- linux -- */

var (
	ssPidRe  = regexp.MustCompile(`pid=(\d+)`)
	ssNameRe = regexp.MustCompile(`\("([^"]+)"`)
)

func listLinux(ctx context.Context) ([]Service, error) {
	cmd := exec.CommandContext(ctx, "ss", "-tulpnH")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ss failed: %w", err)
	}

	var services []Service
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		address, port, err := splitHostPort(fields[4])
		if err != nil {
			continue
		}

		name, pid := "", 0
		if m := ssPidRe.FindStringSubmatch(line); len(m) == 2 {
			pid, _ = strconv.Atoi(m[1])
		}
		if m := ssNameRe.FindStringSubmatch(line); len(m) == 2 {
			name = m[1]
		}

		services = append(services, Service{
			PID: pid, Process: name, Port: port, Protocol: proto, Address: strings.Trim(address, "[]"),
		})
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("ss reported no listening sockets")
	}
	return services, nil
}

func splitHostPort(value string) (string, int, error) {
	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("no port in %q", value)
	}
	port, err := strconv.Atoi(value[idx+1:])
	if err != nil {
		return "", 0, err
	}
	return value[:idx], port, nil
}

/* -------------------------------------------------------------- darwin -- */

func listDarwin(ctx context.Context) ([]Service, error) {
	var services []Service
	for _, args := range [][]string{
		{"-nP", "-iTCP", "-sTCP:LISTEN", "-FpcPn"},
		{"-nP", "-iUDP", "-FpcPn"},
	} {
		out, err := exec.CommandContext(ctx, "lsof", args...).Output()
		if err != nil {
			continue
		}
		proto := "tcp"
		if strings.Contains(strings.Join(args, " "), "UDP") {
			proto = "udp"
		}
		services = append(services, parseLsof(string(out), proto)...)
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("lsof reported no listening sockets (run as root for process names)")
	}
	return services, nil
}

func parseLsof(raw, proto string) []Service {
	var (
		out  []Service
		cur  Service
		have bool
	)
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			if have {
				out = append(out, cur)
			}
			cur = Service{Protocol: proto}
			cur.PID, _ = strconv.Atoi(line[1:])
			have = true
		case 'c':
			cur.Process = line[1:]
		case 'n':
			address, port, err := splitHostPort(line[1:])
			if err != nil {
				continue
			}
			cur.Address = strings.Trim(address, "[]")
			cur.Port = port
		}
	}
	if have && cur.Port != 0 {
		out = append(out, cur)
	}
	return out
}
