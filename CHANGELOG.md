# Changelog

All notable changes to ProFast-Net are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-23

### Added

- C++17 core: SHA-256/HMAC, mirage locator derivation, SPA tokens, packet
  parsing, token-bucket shaper, process priority and EcoQoS, a C ABI, the
  `pfbench` verification tool and 44 known-answer tests.
- Go daemon `profastd` (standard library only) speaking JSON-RPC 2.0 over a unix
  socket or loopback TCP, with a 0600 endpoint file rotated on every start.
- Python control plane: `profast` CLI, rich TUI, PySide6 GUI, reference daemon,
  in-process engine fallback and 88 tests.
- Focus mode: scheduling priority, EcoQoS relaxation, DSCP 46 marking and
  background traffic capped at best-effort.
- Listening-service inventory with exposure, port-class, origin and privilege
  scoring, plus a consent-gated terminate path.
- Adaptive defence: observation, tarpit at half the flood threshold, escalating
  bans from 5 minutes to 24 hours, bounded ban table, no packets sent in reply.
- Mirage identity and single-packet authorization with a replay cache; the
  derivation is byte-identical in C++, Go and Python.
- Consent tokens for `services.terminate`: action-bound, target-bound,
  90-second TTL, single use, memory only.
- Tier-1 firewall drivers: Windows Firewall cmdlets with a `netsh` fallback,
  nftables on Linux and a pf anchor on macOS.
- Reference kernel programs: a WFP callout driver, an XDP program with a libbpf
  loader, and a macOS NetworkExtension data provider.
- Documentation: architecture, protocol, security model and kernel tier.
- CI on Linux, macOS and Windows for the native, Python and Go layers.

[Unreleased]: https://github.com/esskslifetech/profast-net/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/esskslifetech/profast-net/releases/tag/v0.1.0
