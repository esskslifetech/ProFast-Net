# Linux XDP program

`profast firewall apply` already renders nftables rules that work on any kernel
with nft. This directory is the kernel tier: an XDP program that drops traffic
in the NIC driver, before the stack allocates an skb.

## What is here

| File                  | Purpose                                                   |
| --------------------- | --------------------------------------------------------- |
| `profast_xdp.bpf.c`   | XDP program: parse Ethernet/IP/TCP/UDP, consult two maps   |
| `profast_loader.c`    | libbpf loader, map pinning under `/sys/fs/bpf/profast`     |
| `Makefile`            | `clang -target bpf` plus a normal `cc` link for the loader |

## Map contract

| Map         | Type          | Meaning                                              |
| ----------- | ------------- | ---------------------------------------------------- |
| `pf_mode`   | ARRAY[1]      | 0 = observe only (default), 1 = default-deny inbound |
| `pf_ports`  | HASH[64]      | ports the rotating locator currently accepts         |
| `pf_stats`  | PERCPU_ARRAY  | 0 pass, 1 drop, 2 bypass                             |

Maps are pinned, so restarting `profastd` does not drop policy, and a crashed
daemon leaves a closed door rather than an open one. `pf_mode` starts at
observe-only: nothing is dropped until an operator (or the daemon, with consent)
flips it.

## Building

```bash
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)   # Debian/Ubuntu
make                # builds profast_xdp.bpf.o and ./profast-xdp
sudo make load IF=eth0
sudo ./profast-xdp allow eth0 40000
sudo ./profast-xdp enforce eth0
sudo ./profast-xdp stats eth0
sudo make unload IF=eth0
```

`enforce` without an `allow` entry will drop everything inbound except DHCP and
ICMP. Do this on a machine you can reach physically, or over an already
established TCP session (XDP drops new flows, not established ones, only if you
add an `established` clause - the skeleton does not, so expect a hard cut).

## Limitations of the skeleton

- Fragment handling: non-first fragments are passed, a stricter program should
  reject them or match on the fragment metadata map.
- No IPv6 extension header walk; `nexthdr` is read once.
- No connection tracking, so "authorized peer" is a port decision only. The
  full design adds a `pf_peers` LPM trie keyed by the SPA-approved source.
- `BPF_F_XDP_HAS_FRAGS` / multi-buffer support is not used.
