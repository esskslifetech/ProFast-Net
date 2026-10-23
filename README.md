# ProFast-Net

[![ci](https://github.com/esskslifetech/profast-net/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/esskslifetech/profast-net/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-3da639.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](python/pyproject.toml)
[![go](https://img.shields.io/badge/go-1.22-00add8.svg)](core/go.mod)
[![platforms](https://img.shields.io/badge/platforms-windows%20%7C%20macOS%20%7C%20linux-555.svg)](#status)

**Concentrate the link. Rotate the identity. Defend the host. Ask first.**

ProFast-Net is a cross-platform network supervisor written in C++, Go and
Python. It does four things, and it is careful about the fourth:

1. **Focus** — pins one application as the priority workload: higher scheduling
   priority, EcoQoS power throttling relaxed on Windows 11, DSCP 46 (EF) marking
   for its traffic, and background traffic tagged best-effort or capped.
2. **Concentrate** — inventories every listening socket, scores it by exposure,
   port class, process origin and privilege, and shows you what is worth closing.
3. **Defend** — observes inbound probes, tarpits repeat offenders, bans port
   scanners, and escalates repeat bans from 5 minutes to 24 hours.
4. **Ask** — before anything is terminated, the daemon requires a short-lived,
   single-use, target-bound confirmation token that only the user interface can
   obtain after you say yes.

The "virtual firewall that keeps changing its IP" is implemented honestly: no
software can change your public address, so ProFast-Net rotates a **virtual
locator** — an address and a port derived by HMAC from a cluster secret and the
current time epoch. Authorized peers compute the same locator and reach you;
an unauthorised scanner sees a host that keeps moving and a door that keeps
closing.

```
        epoch 1000                        epoch 1001
  fd41:ae7d:9004:782d:...:0e99:35239  ->  fd8c:03b1:...:7f42:51188
        ^ peers derive it from the shared secret
        ^ everyone else sees a dead target
```

## Status

| Layer | Language | State |
| --- | --- | --- |
| Core crypto, packet parsing, shaper, priority | C++17 | Built, 44 known-answer tests pass |
| Daemon (`profastd`) | Go (stdlib only) | Complete, compiled in CI |
| Control plane: CLI, TUI, GUI, reference daemon | Python 3.10+ | 88 tests pass |
| Kernel tier: WFP callout, XDP, NetworkExtension | C / eBPF / Swift | Reference implementations, require platform SDKs |

The user-mode path works today on all three operating systems: Windows Firewall
via the NetSecurity cmdlets (with a netsh fallback), nftables on Linux, and a pf
anchor on macOS. The kernel programs in `native/windows`, `native/linux` and
`native/macos` are the second tier; they need a WDK, clang-bpf and an Apple
entitlement respectively, so they are not built by CI. See
[docs/KERNEL.md](docs/KERNEL.md).

## Quick start

Python 3.10+ is enough to run the control plane. The native core needs CMake 3.16+
and a C++17 compiler, the Go daemon needs Go 1.22+, and the desktop dashboard
needs `PySide6` (`pip install -e "python[gui]"`).

```bash
# C++ core (optional at runtime, required for focus priority)
cmake -S native -B build/native -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/native
./build/native/bin/pfbench selftest        # prints the canonical vectors

# Python control plane
python -m pip install -e "python[dev]"     # or: pip install -e python
profast doctor                             # what works on this host
profast status                             # one screen
profast scan --min-risk 55                 # what is listening, and why it matters
profast scan --kill                        # asks before terminating anything
profast focus start --pid 1234 --minutes 90
profast watch                              # live terminal dashboard
profast gui                                # desktop dashboard (needs PySide6)
```

The CLI falls back to an in-process engine when no daemon is running. Start the
real one for state that survives between commands:

```bash
profast serve                 # Python reference daemon
go run ./core/cmd/profastd    # Go daemon (same protocol, same endpoint file)
```

Firewall rules, QoS policies and terminating services need administrator
rights. A process cannot promote itself, so the window offers **Ask for
Administrative Permissions** in the sidebar: it hands `profast` to UAC and the
old window closes. The elevated copy runs the engine itself, because the
privilege belongs to the process doing the work rather than to the window - so
an unelevated daemon is stopped on the way. Starting `profast gui` from an
already elevated shell skips all of this.

## Identity and authorization

`mirage` derives the locator; `spa` proves a peer belongs to the cluster.

```bash
profast mirage status          # address, port, epoch, peers, replay cache
profast mirage spa --node-id 7 # single packet authorization token, 59 chars
profast mirage accept <token>  # validate a token received from a peer
profast mirage peers
```

A token is 44 bytes (`node_id || epoch || nonce || HMAC-SHA256 half`), valid for
the current epoch plus one either side of clock skew, and recorded in a bounded
replay cache so it is accepted exactly once. The derivation is byte-identical in
C++, Go and Python and pinned by the same vectors in all three test suites.

## Consent, not a prompt

The confirmation dialog is not decoration. `services.terminate` refuses to run
without a token that is:

- issued by the daemon for the action `services.terminate`,
- bound to the SHA-256 fingerprint of the exact pid set,
- valid for 90 seconds,
- redeemable exactly once, in-process only (never persisted).

The CLI asks with `rich`, the GUI asks with a dialog that requires an explicit
acknowledgement, and the daemon refuses either way if the token is missing,
stale, replayed, or bound to different pids.

## What ProFast-Net will not do

- It will not change your public IP address. It rotates a derived locator.
- It will not retaliate. Defence means refuse, throttle and remember; no packet
  is ever sent to an attacker. See [docs/SECURITY.md](docs/SECURITY.md).
- It will not terminate a system process, its own pid, or pid <= 4.
- It will not enable default-deny inbound unless you ask, and DHCP/ICMP control
  traffic is always preserved so the link cannot strand itself.
- It will not silently install kernel code. The drivers are reference sources you
  build and sign yourself.

## Repository layout

```
native/     C++17 core: SHA-256/HMAC, mirage, SPA, packet parse, token bucket,
            process priority, C ABI, pfbench tool, 44 known-answer tests
            windows/driver     WFP callout driver (reference)
            linux/xdp          XDP program + libbpf loader
            macos/networkextension  NEFilterDataProvider
core/       Go daemon, stdlib only: ipc, consent, mirage, firewall, qos, scan,
            defense, focus, engine
python/     Python control plane: engine, daemon, rpc, scan, firewall, focus,
            defense, cli, tui, gui (PySide6), tests
docs/       ARCHITECTURE.md, PROTOCOL.md, SECURITY.md, KERNEL.md
scripts/    build.ps1, build.sh
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — layers, data flow, method surface
- [Protocol](docs/PROTOCOL.md) — derivation, token format, IPC, test vectors
- [Security model](docs/SECURITY.md) — threats, non-goals, key handling
- [Kernel tier](docs/KERNEL.md) — what each program enforces and what it needs
- [Changelog](CHANGELOG.md) — what shipped in each release

## Development

```bash
( cd python && python -m pytest -q )        # 88 tests, no install needed
ctest --test-dir build/native               # or: ./build/native/bin/pf_native_tests
( cd core && gofmt -l . && go vet ./... && go test ./... )
```

CI runs all three on Linux, macOS and Windows. Kernel programs are reviewed but
not compiled: see the README next to each one for the toolchain it needs.

## Contributing

Bug reports, ideas and pull requests are welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md); the [Code of Conduct](CODE_OF_CONDUCT.md)
applies to every project space. Security issues go through
[SECURITY.md](SECURITY.md) — never a public issue.

## Author

Built and maintained by **Kanishk Soni ([K-S](https://github.com/Kanishk-Soni))**
at **ESS KS Life Tech**.

## License

MIT — see [LICENSE](LICENSE).

Copyright (c) 2026 Kanishk Soni (K-S), ESS KS Life Tech.
