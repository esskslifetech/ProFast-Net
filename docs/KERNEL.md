# Kernel tier

ProFast-Net ships two tiers so that it is useful before it is privileged:

| Tier | Where the decision happens | Buildable in CI | Needs |
| --- | --- | --- | --- |
| 1. OS-native rules | Host firewall engine | yes | elevation |
| 2. Kernel programs | NIC driver / filter engine | no | platform SDK + signing |

Tier 1 is what `profast firewall apply` installs today. Tier 2 is the reference
source in `native/windows/driver`, `native/linux/xdp` and
`native/macos/networkextension`.

## Tier 1: what runs now

| OS | Backend | Mechanism |
| --- | --- | --- |
| Windows | `windows` | `New-NetFirewallRule` (WFP), netsh fallback, `New-NetQosPolicy` for DSCP |
| Linux | `nft` | `inet profast` table, input hook, `accept` for locator, `drop` last |
| macOS | `pf` | anchor `com.profast`, `pass`/`block` rules |

All three preserve DHCP and ICMP control traffic when default-deny is on. All
three are namespaced so `reset` removes exactly the rules ProFast owns, and all
three are rendered as a *plan* first (`firewall.plan`) so you can read the rules
before they are applied.

## Tier 2: reference programs

| OS | File | Hook point | Policy input |
| --- | --- | --- | --- |
| Windows | `native/windows/driver/profast_wfp.c` | WFP callout, `FWPS_LAYER_INBOUND_TRANSPORT_V4/V6` | `IOCTL_PF_SET_POLICY` |
| Linux | `native/linux/xdp/profast_xdp.bpf.c` | XDP, driver of the NIC | pinned maps `pf_mode`, `pf_ports`, `pf_stats` |
| macOS | `native/macos/networkextension/FilterDataProvider.swift` | `NEFilterDataProvider.handleNewFlow` | app-group defaults `policy` |

They share one contract:

- **Observe first.** Windows starts with `DenyInbound = FALSE`; XDP starts with
  `pf_mode = 0`; the macOS provider allows everything while `denyInbound` is
  false. Nothing is blocked until user mode flips the switch.
- **Bounded tables.** 64 ports in both the WFP driver and the XDP map. The daemon
  has 64 slots in an epoch, so the bound is structural rather than arbitrary.
- **Control traffic is sacred.** DHCP and ICMP are permitted before the locator
  check in all three programs.
- **No state of their own.** No program writes a listening socket, sends a
  packet, or makes an independent decision about who is friendly.

## Enabling tier 2

The daemon does not load kernel code for you. The intended sequence, per OS:

**Windows**

The driver needs the Windows Driver Kit, which installs only from an elevated
shell (`winget install Microsoft.WindowsWDK.10.0.26100`), plus the MSVC toolset.

```powershell
bcdedit /set testsigning on        # development only, reboot afterwards
sc create ProFastWfp type= kernel binPath= C:\profast\profast_wfp.sys
sc start ProFastWfp
```

Then have `profastd` open the control device and push the current policy on every
epoch change. The device ACL must be tightened to administrators + the daemon SID
before production; the skeleton relies on default WDM security.

**Linux**

```bash
make -C native/linux/xdp
sudo ./native/linux/xdp/profast-xdp attach eth0
sudo ./native/linux/xdp/profast-xdp allow eth0 $(profast status --json | jq .mirage.port)
sudo ./native/linux/xdp/profast-xdp enforce eth0
```

Maps stay pinned under `/sys/fs/bpf/profast`, so a daemon restart does not open
the door. Detach with `profast-xdp detach eth0` before unloading the program.

Verified with clang 14.0.0 and libbpf 1.8.0 on Ubuntu 22.04 (WSL2, kernel 6.18):
`make` produces `profast_xdp.bpf.o` (elf64-bpf, one `xdp` program, `.maps`) and
the `profast-xdp` loader, which prints its usage and needs root only to attach.
The Makefile adds Debian's multiarch include path itself. Ubuntu 22.04 ships
libbpf 0.5.0, which predates `bpf_xdp_attach`; build libbpf 1.x from source and
point the loader at it with `-I/usr/local/include -L/usr/local/lib64`.

**macOS**

Build the system extension with the `content-filter-provider` entitlement, write
the policy dictionary from `profastd`, enable the filter with `NEFilterManager`.
Without the entitlement the extension installs but receives no flows, which is a
silent failure: check `log stream --predicate 'subsystem == "net.profast.extension"'`.

## Why tier 2 is not built by CI

- Windows kernel drivers require the WDK, a signing certificate, and a
  test-signing reboot to load. Hosted runners have none of these.
- eBPF compilation is portable (`clang -target bpf`) but attaching needs
  `CAP_BPF`/root and a NIC; the unit under test would be the host, not the code.
- macOS system extensions need an Apple developer team id and a notarised bundle.

CI therefore compiles tier 1 and tests the *policy* that both tiers consume
(`firewall.build_plan`, the port table bounds, the epoch derivation). A kernel
change that alters semantics must update the tier-1 plan, which is where the
tests live.

## Failure direction

Both tiers fail closed once enabling has been requested:

- If `profastd` dies, installed rules and pinned maps remain.
- If the kernel program is unloaded, the tier-1 rules are still in place.
- If tier 1 is reset while tier 2 is attached, XDP still drops.
- If everything is removed, the host returns to its previous posture — ProFast
  never removes a rule it did not create.

That last point is why `firewall.reset` filters on the `ProFast/` prefix and the
pf anchor name, and why `nft delete table inet profast` is a no-op when the table
is absent.
