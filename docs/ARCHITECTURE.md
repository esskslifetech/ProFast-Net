# Architecture

## Three languages, one contract

```
┌──────────────────────────────────────────────────────────────────────┐
│  Python  ──  profast CLI · rich TUI · PySide6 GUI · reference daemon  │
└───────────────┬──────────────────────────────────────────────────────┘
                │  JSON-RPC 2.0 over unix socket / loopback TCP
                │  (endpoint file carries the token and the address)
┌───────────────┴──────────────────────────────────────────────────────┐
│  Go  ──  profastd: ipc · consent · mirage · firewall · qos · scan    │
│          defense · focus · engine                                    │
└───────────────┬──────────────────────────────────────────────────────┘
                │  C ABI (native/profast/native.h), or pfbench via exec
┌───────────────┴──────────────────────────────────────────────────────┐
│  C++17  ──  sha256/hmac · mirage · spa · packet parse · token bucket  │
│             process priority · EcoQoS · flow table                   │
└───────────────┬──────────────────────────────────────────────────────┘
                │  policy
┌───────────────┴──────────────────────────────────────────────────────┐
│  OS  ──  WFP / nftables / pf   (tier 1)   +   callout / XDP / NE (tier 2) │
└──────────────────────────────────────────────────────────────────────┘
```

Each layer is useful on its own:

- `pfbench selftest` exercises the C++ core with no daemon.
- `profast --embedded status` runs the engine in-process with no daemon.
- `profast serve` runs the Python engine over the real IPC socket.
- `profastd` (Go) speaks the same protocol and is interchangeable.

That last property is the point: the GUI cannot tell which daemon answered, and
a bug fixed in one engine is a test vector for the other.

## Why three languages

| Layer | Language | Reason |
| --- | --- | --- |
| Crypto and packet work | C++17 | Deterministic, dependency-free, usable from Go (cgo) or Python (ctypes/pfbench) without a runtime |
| Daemon and policy | Go | Cheap concurrency for a long-lived process, static binary, easy cross-compile, no runtime to ship |
| Control plane | Python | Fast iteration on CLI/GUI, `psutil` for inventory, `rich` for readable output, PySide6 for a real desktop window |

The C++ core has no third-party dependencies at all — SHA-256, HMAC, base64url,
IP parsing and the token bucket are implemented in-tree, which is what allows a
single `cmake --build` to produce a binary that runs on Windows, Linux and macOS
with nothing else installed.

## Data flow: one focus session

```
profast focus start --pid 1234
  │
  ├─ CLI parses args, opens backend (daemon if present, engine otherwise)
  │
  ├─ focus.start {target, pid, duration_s}
  │     │
  │     ├─ focus.Manager: find process, check privileges
  │     ├─ native.set_priority(pid, level)        -> pfbench priority
  │     ├─ native.set_power_throttling(pid, true) -> SetProcessInformation (Win)
  │     ├─ native.apply_focus(path, dscp=46)      -> New-NetQosPolicy / dnctl
  │     └─ session {applied, skipped, errors, ends_at}
  │
  ├─ event recorded: kind=focus
  │
  └─ window elapses: engine.tick() -> focus.Manager.tick() -> revert
        (QoS policies removed, priority restored, EcoQoS re-enabled)
```

`focus` never claims success it did not achieve: every capability that is missing
(missing native bridge, non-Windows host, failed cmdlet) lands in `skipped` or
`errors`, and the CLI prints those lines under the session.

## Data flow: one consent-gated termination

```
1. user picks services            (scan.services, risk >= 55)
2. UI shows the list + warning
3. user confirms                  (rich Confirm / Qt ConsentDialog)
4. client -> consent.request      {action, summary, targets: ["pid:1234", ...]}
      daemon -> Store.issue       token(16B), TTL 90s, fingerprint(sorted targets)
      daemon -> event(kind=consent)
5. client -> services.terminate   {pids: [1234], token}
      daemon: validate pid > 4 and != own pid
      daemon: Store.redeem(token, "services.terminate", sorted("pid:n"))
      daemon: terminate / force, collect failures
      daemon -> event(kind=services)
```

A token that arrives without step 3 cannot exist, because only the daemon mints
tokens and it mints them solely on `consent.request`. A token for a different pid
set fails the fingerprint check. A token reused fails because redemption removes
it.

## Engine internals

`Engine` (Go and Python mirror each other) owns:

| Component | Responsibility |
| --- | --- |
| `mirage` | derivation, mint, verify, replay cache |
| `consent` | issue, redeem, revoke, prune |
| `defense` | per-source attempt windows, port fan-out, escalating bans |
| `focus` | one active session at a time, revert on tick or stop |
| `scan` | cached inventory (45 s), risk table, system-process classification |
| `firewall` | render a plan, apply it, report what the OS says |
| `events` | bounded ring buffer, newest first |

Concurrency rules that are enforced, not assumed:

- `Engine` holds a single `RWMutex`/`RLock` for peers, cache and events.
- `defense` has its own lock; `observe` is the only writer of counters.
- `focus` serialises start/stop and refuses a second session instead of stacking
  policies it cannot revert.
- The daemon serves each connection on its own goroutine/thread and never shares
  a mutable request buffer.

## IPC

`ipc.Listen` (Go) and `_make_server` (Python) produce the same endpoint file and
the same handshake, described in [PROTOCOL.md](PROTOCOL.md). Consequences for the
clients:

- `rpc.Client` does one handshake per connection and multiplexes calls over it.
- The endpoint token rotates on every daemon start, so a stale file fails loudly
  with `-32002` rather than silently connecting to the wrong process.
- On Windows the socket is loopback TCP because `AF_UNIX` support in Python is
  unreliable on older builds; the token, not the transport, is the boundary.

## Native bridge

`native.find_native()` decides at runtime whether the C++ core is present:

```
find_native(): pfbench on PATH, then build/native/bin/pfbench(.exe), then next to python
```

When absent, priority tuning is reported as skipped. When present, it is invoked
through `pfbench` (a process, not a shared library) so a crash in native code
cannot take the daemon with it and so the same binary works from Python and Go
without cgo or ctypes marshalling.

## Testing strategy

| Layer | Test | Why it catches drift |
| --- | --- | --- |
| C++ | `pf_native_tests`, 44 assertions | SHA-256/HMAC FIPS + RFC 4231 vectors, derivation, token tamper, bucket maths |
| Python | 88 pytest cases | Same derivation vectors, consent semantics, risk table, real socket round trip |
| Go | `go test ./core/...` in CI | Compiles the daemon on all three OSes; unit tests for mirage and consent |
| Cross-language | shared vector table | If any implementation changes, its own suite fails on the same numbers |

The vectors are the contract. A change that "looks fine" in one language and not
in the others fails in the language that was not edited, which is exactly the
failure you want.
