// Package config loads, validates and persists the daemon configuration.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FocusConfig controls what happens when the user focuses a single task.
type FocusConfig struct {
	TargetPath       string `json:"target_path"`
	BoostPriority    bool   `json:"boost_priority"`
	DisableEcoQoS    bool   `json:"disable_eco_qos"`
	DefaultDurationS int    `json:"default_duration_s"`
	ThrottleOthers   bool   `json:"throttle_others"`
	BackgroundDSCP   int    `json:"background_dscp"`
}

// DefenseConfig controls the reactive half of the firewall.
type DefenseConfig struct {
	Enabled       bool `json:"enabled"`
	AutoBan       bool `json:"auto_ban"`
	BanThreshold  int  `json:"ban_threshold"`
	WindowSeconds int  `json:"window_seconds"`
	ScanThreshold int  `json:"scan_threshold"`
	InitialBanMin int  `json:"initial_ban_minutes"`
	MaxBanHours   int  `json:"max_ban_hours"`
	MaxBans       int  `json:"max_bans"`
	Tarpit        bool `json:"tarpit"`
}

// FirewallConfig describes the inbound posture.
type FirewallConfig struct {
	Enabled      bool  `json:"enabled"`
	AllowLAN     bool  `json:"allow_lan"`
	BlockInbound bool  `json:"block_inbound"`
	AllowPorts   []int `json:"allow_ports"`
}

// MirageConfig holds the rotating identity parameters.
type MirageConfig struct {
	Enabled      bool   `json:"enabled"`
	Interface    string `json:"interface"`
	NodeName     string `json:"node_name"`
	NodeID       uint32 `json:"node_id"`
	SecretHex    string `json:"secret_hex"`
	EpochSeconds int    `json:"epoch_seconds"`
	PeerPort     uint16 `json:"peer_port"`
}

// Config is the root document persisted as JSON.
type Config struct {
	Version  int            `json:"version"`
	Mirage   MirageConfig   `json:"mirage"`
	Focus    FocusConfig    `json:"focus"`
	Defense  DefenseConfig  `json:"defense"`
	Firewall FirewallConfig `json:"firewall"`
	LogLevel string         `json:"log_level"`
}

// Default returns a conservative configuration: nothing destructive is on by
// default, and every killing action still requires a consent token.
func Default() Config {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "profast-node"
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("config: cannot read CSPRNG: " + err.Error())
	}

	sum := sha256.Sum256([]byte(host))

	return Config{
		Version: 1,
		Mirage: MirageConfig{
			Enabled:      true,
			Interface:    "auto",
			NodeName:     host,
			NodeID:       binary.BigEndian.Uint32(sum[:4]),
			SecretHex:    hex.EncodeToString(secret),
			EpochSeconds: 10,
			PeerPort:     0,
		},
		Focus: FocusConfig{
			BoostPriority:    true,
			DisableEcoQoS:    true,
			DefaultDurationS: 3600,
			ThrottleOthers:   true,
			BackgroundDSCP:   8,
		},
		Defense: DefenseConfig{
			Enabled:       true,
			AutoBan:       true,
			BanThreshold:  40,
			WindowSeconds: 10,
			ScanThreshold: 20,
			InitialBanMin: 5,
			MaxBanHours:   24,
			MaxBans:       4096,
			Tarpit:        true,
		},
		Firewall: FirewallConfig{
			Enabled:      true,
			AllowLAN:     true,
			BlockInbound: false,
			AllowPorts:   []int{},
		},
		LogLevel: "info",
	}
}

// Secret decodes the cluster secret used by the mirage derivation.
func (c *Config) Secret() ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(c.Mirage.SecretHex))
	if err != nil {
		return nil, fmt.Errorf("mirage secret is not valid hex: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("mirage secret must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// Validate clamps values that would otherwise produce a broken runtime.
func (c *Config) Validate() error {
	if c.Version <= 0 {
		c.Version = 1
	}
	if c.Mirage.EpochSeconds < 2 {
		c.Mirage.EpochSeconds = 2
	}
	if c.Mirage.EpochSeconds > 300 {
		c.Mirage.EpochSeconds = 300
	}
	if c.Focus.DefaultDurationS <= 0 {
		c.Focus.DefaultDurationS = 3600
	}
	if c.Defense.BanThreshold <= 0 {
		c.Defense.BanThreshold = 40
	}
	if c.Defense.WindowSeconds <= 0 {
		c.Defense.WindowSeconds = 10
	}
	if c.Defense.MaxBans <= 0 {
		c.Defense.MaxBans = 4096
	}
	if _, err := c.Secret(); err != nil {
		return err
	}
	return nil
}

// ConfigPath returns the per-user configuration file location.
func ConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ProFast-Net", "config.json"), nil
}

// RuntimeDir is the directory holding the IPC endpoint and transient state.
// POSIX sockets must stay short, so it lives in the temp directory there.
func RuntimeDir() (string, error) {
	if runtime.GOOS == "windows" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(base, "ProFast-Net"), nil
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "user"
	}
	return filepath.Join(os.TempDir(), "profast-"+user), nil
}

// EndpointPath is the JSON file describing how to reach the running daemon.
func EndpointPath() (string, error) {
	dir, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "endpoint.json"), nil
}

// StatePath is where the ban list and peer table survive a restart.
func StatePath() (string, error) {
	dir, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

// Load reads the configuration at path, creating a default one when absent.
func Load(path string) (*Config, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, false, err
		}
		cfg := Default()
		if err := cfg.Save(path); err != nil {
			return nil, false, err
		}
		return &cfg, true, nil
	}

	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return &cfg, false, nil
}

// Save writes the configuration atomically with owner-only permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
