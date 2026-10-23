// Package firewall renders and applies the inbound posture for the host.
//
// ProFast never implements a packet filter from scratch: it drives the filter
// engine that already ships with the operating system (Windows Filtering
// Platform via netsh/advfirewall, nftables on Linux, pf on macOS). The kernel
// tier in native/ replaces this front end with a callout driver when the
// signed driver is installed; the rule model below is identical either way.
package firewall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Rule is one entry of the inbound posture.
type Rule struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	Ports     []int  `json:"ports,omitempty"`
	Remote    string `json:"remote,omitempty"`
}

// Request is the input needed to build a plan.
type Request struct {
	BlockInbound bool
	AllowLAN     bool
	AllowPorts   []int
	MiragePort   uint16
	SPAPort      uint16
	Interface    string
}

// Plan is a reviewable, replayable description of the intended state.
type Plan struct {
	Backend  string     `json:"backend"`
	Rules    []Rule     `json:"rules"`
	Commands [][]string `json:"commands,omitempty"`
	Script   string     `json:"script,omitempty"`
}

// Report is the outcome of an apply or reset.
type Report struct {
	Backend string   `json:"backend"`
	Applied []string `json:"applied"`
	Skipped []string `json:"skipped"`
	Errors  []string `json:"errors"`
}

const (
	prefix     = "ProFast/"
	anchorPF   = "com.profast"
	tableNFT   = "profast"
	mirageName = prefix + "Mirage"
	spaName    = prefix + "SPA"
	blockName  = prefix + "BlockInbound"
)

// Build renders the plan for the running platform.
func Build(req Request) Plan {
	switch runtime.GOOS {
	case "windows":
		return buildWindows(req)
	case "darwin":
		return buildDarwin(req)
	default:
		return buildLinux(req)
	}
}

func buildWindows(req Request) Plan {
	p := Plan{Backend: "netsh"}
	p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "delete", "rule",
		"name=" + mirageName})
	p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "delete", "rule",
		"name=" + spaName})
	p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "delete", "rule",
		"name=" + blockName})

	if req.MiragePort != 0 {
		remote := "any"
		if req.AllowLAN {
			remote = "LocalSubnet"
		}
		p.Rules = append(p.Rules, Rule{Name: mirageName, Direction: "in", Action: "allow",
			Protocol: "tcp", Ports: []int{int(req.MiragePort)}, Remote: remote})
		p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + mirageName, "dir=in", "action=allow", "protocol=TCP",
			fmt.Sprintf("localport=%d", req.MiragePort), "remoteip=" + remote, "profile=any"})

		p.Rules = append(p.Rules, Rule{Name: spaName, Direction: "in", Action: "allow",
			Protocol: "udp", Ports: []int{int(req.SPAPort)}, Remote: remote})
		p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + spaName, "dir=in", "action=allow", "protocol=UDP",
			fmt.Sprintf("localport=%d", req.SPAPort), "remoteip=" + remote, "profile=any"})
	}

	for _, port := range req.AllowPorts {
		name := fmt.Sprintf("%sPort-%d", prefix, port)
		p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "delete", "rule",
			"name=" + name})
		p.Rules = append(p.Rules, Rule{Name: name, Direction: "in", Action: "allow",
			Protocol: "tcp", Ports: []int{port}, Remote: "any"})
		p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + name, "dir=in", "action=allow", "protocol=TCP",
			fmt.Sprintf("localport=%d", port), "profile=any"})
	}

	if req.BlockInbound {
		p.Rules = append(p.Rules, Rule{Name: blockName, Direction: "in", Action: "block",
			Protocol: "any", Remote: "any"})
		p.Commands = append(p.Commands, []string{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=" + blockName, "dir=in", "action=block", "protocol=any", "profile=any"})
	}
	return p
}

func buildLinux(req Request) Plan {
	p := Plan{Backend: "nft"}
	var b strings.Builder

	fmt.Fprintf(&b, "add table inet %s\n", tableNFT)
	fmt.Fprintf(&b, "flush table inet %s\n", tableNFT)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority filter; policy accept; }\n", tableNFT)
	fmt.Fprintf(&b, "add rule inet %s input iif lo accept\n", tableNFT)
	fmt.Fprintf(&b, "add rule inet %s input ct state established,related accept\n", tableNFT)

	p.Rules = append(p.Rules, Rule{Name: "established", Direction: "in", Action: "allow"},
		Rule{Name: "loopback", Direction: "in", Action: "allow"})

	if req.MiragePort != 0 {
		fmt.Fprintf(&b, "add rule inet %s input tcp dport %d accept\n", tableNFT, req.MiragePort)
		fmt.Fprintf(&b, "add rule inet %s input udp dport %d accept\n", tableNFT, req.SPAPort)
		p.Rules = append(p.Rules, Rule{Name: mirageName, Direction: "in", Action: "allow",
			Protocol: "tcp", Ports: []int{int(req.MiragePort)}})
	}

	if req.BlockInbound {
		// DHCP and neighbour discovery must survive an aggressive posture or
		// the machine drops off the network entirely.
		fmt.Fprintf(&b, "add rule inet %s input udp dport { 67, 68, 546, 547 } accept\n", tableNFT)
		fmt.Fprintf(&b, "add rule inet %s input icmp type { destination-unreachable, time-exceeded } accept\n", tableNFT)
		p.Rules = append(p.Rules, Rule{Name: blockName, Direction: "in", Action: "block",
			Protocol: "any", Remote: "any"})
		fmt.Fprintf(&b, "add rule inet %s input counter drop\n", tableNFT)
	}

	p.Script = b.String()
	return p
}

func buildDarwin(req Request) Plan {
	p := Plan{Backend: "pf"}
	var b strings.Builder

	b.WriteString("pass out quick all\n")
	b.WriteString("pass in quick proto udp from any to any port 67\n")
	b.WriteString("pass in quick proto udp from any to any port 68\n")

	if req.MiragePort != 0 {
		fmt.Fprintf(&b, "pass in quick proto tcp from any to any port %d\n", req.MiragePort)
		fmt.Fprintf(&b, "pass in quick proto udp from any to any port %d\n", req.SPAPort)
		p.Rules = append(p.Rules, Rule{Name: mirageName, Direction: "in", Action: "allow",
			Protocol: "tcp", Ports: []int{int(req.MiragePort)}})
	}

	for _, port := range req.AllowPorts {
		fmt.Fprintf(&b, "pass in quick proto tcp from any to any port %d\n", port)
		p.Rules = append(p.Rules, Rule{Name: fmt.Sprintf("%sPort-%d", prefix, port),
			Direction: "in", Action: "allow", Protocol: "tcp", Ports: []int{port}})
	}

	if req.BlockInbound {
		b.WriteString("block drop in quick proto { tcp udp } from any to any\n")
		p.Rules = append(p.Rules, Rule{Name: blockName, Direction: "in", Action: "block",
			Protocol: "any", Remote: "any"})
	}

	p.Script = b.String()
	return p
}

// Available reports whether the platform backend can be driven right now.
func Available() (string, error) {
	bin := map[string]string{"windows": "netsh", "darwin": "pfctl"}[runtime.GOOS]
	if bin == "" {
		bin = "nft"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return bin, fmt.Errorf("%s not found on PATH: %w", bin, err)
	}
	return bin, nil
}

// Elevated reports whether the current process may change host firewall state.
func Elevated() bool {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("whoami", "/groups").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "S-1-16-12288") ||
			strings.Contains(string(out), "S-1-16-16384")
	default:
		out, err := exec.Command("id", "-u").Output()
		if err != nil {
			return false
		}
		return strings.TrimSpace(string(out)) == "0"
	}
}

// Apply installs the plan. It is idempotent: every rule is deleted and
// recreated so drift from another tool is corrected.
func (p Plan) Apply(ctx context.Context) (Report, error) {
	report := Report{Backend: p.Backend}

	switch p.Backend {
	case "netsh":
		for _, argv := range p.Commands {
			if len(argv) == 0 {
				continue
			}
			out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
			line := strings.Join(argv[2:], " ")
			if err != nil {
				// Deleting a rule that does not exist is not a failure.
				if strings.Contains(strings.ToLower(string(out)), "no rules match") {
					report.Skipped = append(report.Skipped, line)
					continue
				}
				report.Errors = append(report.Errors, fmt.Sprintf("%s: %s", line, strings.TrimSpace(string(out))))
				continue
			}
			report.Applied = append(report.Applied, line)
		}

	case "nft":
		cmd := exec.CommandContext(ctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(p.Script)
		out, err := cmd.CombinedOutput()
		if err != nil {
			report.Errors = append(report.Errors, strings.TrimSpace(string(out)))
			return report, fmt.Errorf("nft rejected the plan: %w", err)
		}
		report.Applied = append(report.Applied, "inet profast table installed")

	case "pf":
		path, err := os.CreateTemp("", "profast-pf-*.conf")
		if err != nil {
			return report, err
		}
		defer os.Remove(path.Name())
		if _, err := path.WriteString(p.Script); err != nil {
			path.Close()
			return report, err
		}
		path.Close()

		_ = exec.CommandContext(ctx, "pfctl", "-e").Run() // already enabled is fine
		cmd := exec.CommandContext(ctx, "pfctl", "-a", anchorPF, "-f", path.Name())
		out, err := cmd.CombinedOutput()
		if err != nil {
			report.Errors = append(report.Errors, strings.TrimSpace(string(out)))
			return report, fmt.Errorf("pfctl rejected the plan: %w", err)
		}
		report.Applied = append(report.Applied, "pf anchor "+anchorPF+" loaded")

	default:
		return report, fmt.Errorf("unsupported backend %q", p.Backend)
	}

	if len(report.Errors) > 0 {
		return report, fmt.Errorf("%d rule(s) failed: %s", len(report.Errors), report.Errors[0])
	}
	return report, nil
}

// Reset removes every rule ProFast owns, restoring the previous posture.
func Reset(ctx context.Context) Report {
	report := Report{Backend: map[string]string{"windows": "netsh", "darwin": "pf"}[runtime.GOOS]}
	if report.Backend == "" {
		report.Backend = "nft"
	}

	switch report.Backend {
	case "netsh":
		out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").Output()
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "Rule Name:") || !strings.Contains(line, prefix) {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(line, "Rule Name:"))
			cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule",
				"name="+name)
			if out, err := cmd.CombinedOutput(); err != nil {
				report.Errors = append(report.Errors, strings.TrimSpace(string(out)))
				continue
			}
			report.Applied = append(report.Applied, "deleted "+name)
		}

	case "nft":
		cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableNFT)
		if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "No such file") {
			report.Errors = append(report.Errors, strings.TrimSpace(string(out)))
		} else {
			report.Applied = append(report.Applied, "inet profast table removed")
		}

	case "pf":
		cmd := exec.CommandContext(ctx, "pfctl", "-a", anchorPF, "-F", "rules")
		if out, err := cmd.CombinedOutput(); err != nil {
			report.Errors = append(report.Errors, strings.TrimSpace(string(out)))
		} else {
			report.Applied = append(report.Applied, "pf anchor flushed")
		}
	}
	return report
}
