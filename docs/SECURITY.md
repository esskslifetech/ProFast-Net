# Security model

## What ProFast-Net is defending

A single workstation or small cluster on a network where some peers are friendly
and some are scanning. The realistic adversary is opportunistic, not targeted:
mass scanners, credential stuffers, LAN neighbours looking for open shares, and
malware that opens a listening back door.

## Trust boundaries

| Boundary | Trusted | Notes |
| --- | --- | --- |
| `profastd` process | yes | Holds the cluster secret and the policy |
| Endpoint file + token | yes, 0600 | Rotated on every start; never persisted to config |
| GUI / CLI | same user | Consent is enforced by the daemon, not by the UI |
| Kernel programs | yes | Receive policy, never originate it |
| Network peers with the secret | degraded | Can derive locators and mint tokens |
| Everything else on the network | no | Sees a moving locator and a closed door |

The daemon never trusts the client's claim that a user confirmed something. The
client must present a token that the daemon itself issued for the same action and
the same target set. A malicious local process that can read the endpoint file can
issue itself a token — which is why the endpoint file is 0600 and the socket is
created with the same mode. Same-user malware already owns the session; ProFast-Net
does not claim to defend against that.

## Defensive behaviour, and its limits

**What "forcefully defends itself" means here**

1. Observe every inbound probe that reaches the daemon's observation points.
2. Tarpit at half the flood threshold: the host slows down, it does not answer.
3. Ban on fan-out (port scan) or on flood, with a 5-minute first strike.
4. Double the ban for every repeat offence, capped at 24 hours.
5. Cap the ban table (4096 entries, oldest evicted) so memory is bounded.
6. Never send a packet in response. No reset, no ICMP, no counter-scan.

**What it does not mean**

- No retaliation of any kind. Retaliation is illegal in most jurisdictions,
  escalates with the attacker, and turns a victim into a participant.
- No protection against volumetric DDoS; that is an upstream problem.
- No protection against an attacker who already has your cluster secret. Rotate
  the secret (`profast config init` after deleting the file) and re-issue tokens.
- No protection against a root/administrator attacker. Kernel programs and the
  daemon both run with privileges; a privileged attacker wins by definition.

## Consent as a security control

Terminating a process is the only destructive action in the product. The rules:

- The daemon refuses pid <= 4 and its own pid, before looking at any token.
- The token is bound to `sorted("pid:<n>")` of the exact set.
- The token expires in 90 seconds and is consumed on first use.
- Tokens live in memory only; restarting the daemon invalidates everything.
- The GUI dialog additionally requires a checkbox acknowledgement; the CLI
  defaults to "no".

This produces a paper trail in `core.events` (`consent`, `services`) and makes it
impossible for a script to terminate services without an explicit grant for that
exact set.

## Firewall safety

- Default-deny inbound is **off** by default (`firewall.block_inbound = false`).
- When enabled, DHCP (67/68/546/547) and ICMP unreachable/time-exceeded are always
  permitted, so the link cannot strand itself on a lease renewal.
- Rules are namespaced (`ProFast/*`, `inet profast`, `com.profast` anchor) and
  `firewall.reset` removes exactly those.
- Applying rules requires elevation and is reported, never silent: every change
  emits an event and returns the list of applied rules.
- Kernel programs start in observe-only mode. Enforcing requires an explicit
  transition.

## Key material

| Secret | Where | Protection |
| --- | --- | --- |
| Mirage secret (32 bytes) | `config.json` | File mode 0600, created with `secrets.token_bytes` |
| IPC token (32 bytes) | `endpoint.json` | Mode 0600, new on every daemon start, compared in constant time |
| SPA nonce | in the token | 16 random bytes, replay-cached |
| Consent token | memory | 16 random bytes, 90 s TTL, single use |

`profast config show` redacts `secret_hex`. The GUI never displays it. Nothing is
logged at info level that contains secret material.

Rotating the secret: stop the daemon, delete `config.json` (or set a new
`mirage.secret_hex`), start again. All existing tokens and peers become invalid,
by design.

## Failure modes we designed for

| Failure | Result |
| --- | --- |
| Daemon crashes | XDP/netfilter/qos policy stays, maps are pinned, endpoint file is stale and clients report "unavailable" |
| Daemon killed with default-deny on | Kernel policy remains in force; that is the intended fail-closed direction |
| Replay of an SPA token | Rejected by the replay cache, logged as a mirage event |
| Clock drift between peers | ±1 epoch tolerated; larger drift is rejected and logged |
| Wrong pid set in a consent token | `-32001`, no process is signalled |
| Firewall cmdlet unavailable | netsh fallback on Windows, error surfaced elsewhere |
| Missing native bridge | Focus priority is reported as skipped, never faked |

## Reporting

See [SECURITY.md](../SECURITY.md) at the repository root for the private
reporting process and the vulnerability scope.

This is a reference implementation, not an audited product. If you deploy it,
have the WFP callout and the XDP program reviewed for your environment before
enabling default-deny, and treat the cluster secret as you would an SSH host key.
