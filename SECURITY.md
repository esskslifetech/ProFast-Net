# Security policy

ProFast-Net changes firewall rules, rotates network identity and terminates
processes, so a vulnerability here can cost more than a crash. Reports are taken
seriously, even though this repository is a reference implementation rather than
an audited product.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes, on a best-effort basis |
| Older | No |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

1. Open the **Security** tab of this repository.
2. Choose **Report a vulnerability** (GitHub Security Advisories).
3. Include the version or commit, the operating system, which daemon is running
   (`profastd`, `profast serve` or the in-process engine), reproduction steps and
   the impact you believe the bug has.

If private reporting is unavailable, contact the maintainer
[@Kanishk-Soni](https://github.com/Kanishk-Soni) to agree on a private channel
before disclosing anything.

You will get an acknowledgement when the report is read and a note when a fix
ships. There is no bug bounty and no formal SLA; this is a small project.

## In scope

- Consent tokens that can be minted, replayed, reused, or bound to a different
  pid set than the one the user confirmed.
- IPC authentication bypass, endpoint-file permission problems, token leakage
  into logs, errors or the GUI.
- Divergence between the C++, Go and Python implementations of the mirage
  derivation or the SPA token — a vector mismatch is a security bug.
- Firewall or QoS policy applied without elevation, silently, or outside the
  `ProFast/*` namespace.
- Command injection, path traversal or unintended privilege retention in the
  elevation hand-off (`profast gui` restarting itself through UAC/sudo).
- Denial of service against the daemon through unbounded tables, caches or
  request queues.

## Out of scope

- Attacks that already require administrator or root on the same host.
- Volumetric DDoS, upstream routing and ISP-level filtering.
- The cluster secret once it is shared: anyone holding it can derive locators
  and mint tokens, by design.
- Kernel programs as shipped — they are reference sources you build and sign
  yourself; see [docs/KERNEL.md](docs/KERNEL.md).
- Claims about public IP rotation. ProFast-Net rotates a derived locator; it
  cannot and does not change your public address.

## Hardening before deployment

The threat model, trust boundaries, key handling and failure modes are in
[docs/SECURITY.md](docs/SECURITY.md). Read it before enabling default-deny
inbound, installing a kernel tier, or sharing the cluster secret with a peer.
