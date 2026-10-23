package scan

import (
	"fmt"
	"strings"
)

// portProfile is the intrinsic risk of exposing a well known service.
type portProfile struct {
	Score  int
	Reason string
}

// The table is intentionally opinionated: these are the ports that turn a
// laptop on a coffee shop network into somebody else's machine.
var portProfiles = map[int]portProfile{
	21:    {70, "FTP carries credentials in clear text"},
	23:    {90, "Telnet is unencrypted remote shell access"},
	25:    {40, "SMTP relay exposed to the network"},
	69:    {50, "TFTP has no authentication"},
	135:   {65, "MSRPC endpoint mapper is a classic lateral movement target"},
	137:   {55, "NetBIOS name service leaks host information"},
	139:   {75, "NetBIOS session service exposes SMB"},
	445:   {85, "SMB file sharing exposed to the LAN"},
	512:   {70, "rexec allows unauthenticated remote execution"},
	513:   {65, "rlogin trusts the source host"},
	514:   {60, "rsh/rlogind family, legacy and unsafe"},
	1433:  {70, "SQL Server reachable from the network"},
	1521:  {60, "Oracle listener exposed"},
	1900:  {35, "SSDP/UPnP discovery answers arbitrary probes"},
	2049:  {60, "NFS export exposed"},
	3306:  {65, "MySQL reachable from the network"},
	3389:  {80, "RDP is the most attacked Windows service"},
	5432:  {55, "PostgreSQL reachable from the network"},
	5900:  {75, "VNC often runs without a password"},
	5985:  {70, "WinRM over HTTP accepts remote management"},
	5986:  {50, "WinRM over HTTPS exposed"},
	6379:  {85, "Redis has no authentication by default"},
	8080:  {30, "HTTP proxy or dev server exposed"},
	9200:  {70, "Elasticsearch has no authentication by default"},
	11211: {60, "memcached amplifies traffic and leaks data"},
	27017: {80, "MongoDB historically allows anonymous access"},
}

var riskyPathFragments = []string{
	`\temp\`, `\tmp\`, `/tmp/`, `\downloads\`, `/downloads/`, `\appdata\local\temp`,
}

// Score returns the risk value, its level and the human reasons behind it.
func Score(s *Service) (int, string, []string) {
	score := 5
	reasons := []string{}

	if profile, ok := portProfiles[s.Port]; ok {
		score = profile.Score
		reasons = append(reasons, profile.Reason)
	} else if s.Port < 1024 {
		score = 25
		reasons = append(reasons, fmt.Sprintf("privileged port %d is bound", s.Port))
	}

	if s.Public {
		score += 20
		reasons = append(reasons, "listening on every interface, not just loopback")
	} else if s.Address == "127.0.0.1" || s.Address == "::1" {
		score -= 10
	}

	if s.System {
		score += 10
		reasons = append(reasons, "runs as a system account, so a compromise is total")
	}

	path := strings.ToLower(s.Path)
	for _, fragment := range riskyPathFragments {
		if path != "" && strings.Contains(path, fragment) {
			score += 15
			reasons = append(reasons, "binary executed from a temporary or download folder")
			break
		}
	}

	if s.Protocol == "udp" && s.Public {
		score += 5
		reasons = append(reasons, "UDP service is spoofable and amplifies probes")
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no known exposure signature")
	}

	return score, Level(score), reasons
}

// Level maps a numeric score to the vocabulary used by the UI.
func Level(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 55:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// ShouldRecommend reports whether a service deserves a termination prompt.
func ShouldRecommend(s *Service) bool {
	return s.Risk >= 55
}
