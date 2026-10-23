// Command profastd is the privileged ProFast-Net daemon.
//
// It owns the rotating identity, the host firewall rules, the service
// inventory and the defence engine. The Python control plane and the GUI never
// touch the operating system directly: they speak the JSON-RPC protocol in
// docs/PROTOCOL.md, which is why the same UI works on all three platforms.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/esskslifetech/profast-net/core/internal/config"
	"github.com/esskslifetech/profast-net/core/internal/engine"
	"github.com/esskslifetech/profast-net/core/internal/firewall"
	"github.com/esskslifetech/profast-net/core/internal/ipc"
	"github.com/esskslifetech/profast-net/core/internal/version"
)

func main() {
	var (
		configFlag   = flag.String("config", "", "path to config.json (default: per-user config dir)")
		endpointFlag = flag.String("endpoint", "", "path to the IPC endpoint file")
		showVersion  = flag.Bool("version", false, "print version and exit")
		checkOnly    = flag.Bool("check", false, "validate the configuration and exit")
		noFirewall   = flag.Bool("no-firewall", false, "never modify host firewall rules")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("profastd %s (protocol %s, %s/%s)\n",
			version.Version, version.ProtocolVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfgPath := *configFlag
	if cfgPath == "" {
		resolved, err := config.ConfigPath()
		if err != nil {
			fatal("cannot resolve the configuration path", err)
		}
		cfgPath = resolved
	}

	cfg, created, err := config.Load(cfgPath)
	if err != nil {
		fatal("cannot load configuration", err)
	}
	if *noFirewall {
		cfg.Firewall.Enabled = false
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)})))

	if created {
		slog.Info("created default configuration", "path", cfgPath)
	}
	if *checkOnly {
		fmt.Printf("configuration ok: %s\n", cfgPath)
		return
	}

	endpointPath := *endpointFlag
	if endpointPath == "" {
		resolved, err := config.EndpointPath()
		if err != nil {
			fatal("cannot resolve the endpoint path", err)
		}
		endpointPath = resolved
	}

	nativeBin := findNative()
	eng, err := engine.New(cfg, nativeBin)
	if err != nil {
		fatal("cannot initialise the engine", err)
	}

	server, err := ipc.Listen(endpointPath, eng.Handle)
	if err != nil {
		fatal("cannot bind the control socket", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng.Start(ctx)

	ep := server.Endpoint()
	slog.Info("profastd ready",
		"version", version.Version,
		"network", ep.Network,
		"address", ep.Address,
		"endpoint_file", endpointPath,
		"native_bridge", nativeBin != "",
	)

	if !firewall.Elevated() {
		slog.Warn("running without elevation: firewall and service termination will be refused by the OS")
	}

	<-ctx.Done()
	slog.Info("shutting down, reverting host state")
	if err := server.Close(); err != nil {
		slog.Warn("control socket close failed", "error", err)
	}
	eng.Close()
}

// findNative locates the C++ bridge. It is optional: without it the daemon
// loses process priority tuning, nothing else.
func findNative() string {
	name := "pfbench"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	if path, err := exec.LookPath(name); err == nil {
		return path
	}

	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, name),
			filepath.Join(dir, "..", "native", "build", "bin", name),
			filepath.Join(dir, "..", "..", "build", "native", "bin", name),
		)
	}
	candidates = append(candidates, filepath.Join("build", "native", "bin", name))

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			absolute, err := filepath.Abs(candidate)
			if err != nil {
				continue
			}
			return absolute
		}
	}
	return ""
}

func logLevel(value string) slog.Level {
	switch value {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func fatal(message string, err error) {
	slog.Error(message, "error", err)
	os.Exit(1)
}
