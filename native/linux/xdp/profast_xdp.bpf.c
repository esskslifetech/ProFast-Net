/* SPDX-License-Identifier: MIT
 *
 * ProFast-Net XDP program.
 *
 * Runs in the driver of the NIC, before the kernel network stack allocates an
 * skb, so a blocked probe costs one packet's worth of work instead of a socket
 * wake-up. User mode (profastd) owns the policy through two maps:
 *
 *   pf_mode   ARRAY  index 0 -> 0 = observe only, 1 = default-deny inbound
 *   pf_ports  HASH   key = destination port (host byte order), value = 1
 *   pf_stats  PERCPU_ARRAY  index 0 pass, 1 drop, 2 bypass
 *
 * The maps are pinned under /sys/fs/bpf/profast by the loader so that a daemon
 * restart does not drop the policy and a crashed daemon does not open the host.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PF_MAX_PORTS 64

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pf_mode SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PF_MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} pf_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} pf_stats SEC(".maps");

static __always_inline void pf_count(__u32 slot)
{
    __u64 *counter = bpf_map_lookup_elem(&pf_stats, &slot);
    if (counter) {
        *counter += 1;
    }
}

static __always_inline int pf_is_control(__u8 protocol, __u16 dport)
{
    if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) {
        return 1;
    }
    if (protocol == IPPROTO_UDP &&
        (dport == 67 || dport == 68 || dport == 546 || dport == 547)) {
        return 1;
    }
    return 0;
}

SEC("xdp")
int profast_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 mode_key = 0;
    __u32 *mode;
    __u16 dport;
    __u8 protocol;

    if ((void *)(eth + 1) > end) {
        pf_count(2);
        return XDP_PASS;
    }

    mode = bpf_map_lookup_elem(&pf_mode, &mode_key);
    if (!mode || *mode == 0) {
        pf_count(2);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > end || ip->ihl < 5) {
            pf_count(2);
            return XDP_PASS;
        }
        protocol = ip->protocol;

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
            if ((void *)(tcp + 1) > end) {
                pf_count(2);
                return XDP_PASS;
            }
            dport = bpf_ntohs(tcp->dest);
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip->ihl * 4;
            if ((void *)(udp + 1) > end) {
                pf_count(2);
                return XDP_PASS;
            }
            dport = bpf_ntohs(udp->dest);
        } else if (pf_is_control(protocol, 0)) {
            pf_count(0);
            return XDP_PASS;
        } else {
            pf_count(1);
            return XDP_DROP;
        }
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > end) {
            pf_count(2);
            return XDP_PASS;
        }
        protocol = ip6->nexthdr;

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > end) {
                pf_count(2);
                return XDP_PASS;
            }
            dport = bpf_ntohs(tcp->dest);
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > end) {
                pf_count(2);
                return XDP_PASS;
            }
            dport = bpf_ntohs(udp->dest);
        } else if (pf_is_control(protocol, 0)) {
            pf_count(0);
            return XDP_PASS;
        } else {
            pf_count(1);
            return XDP_DROP;
        }
    } else {
        pf_count(2);
        return XDP_PASS;
    }

    if (pf_is_control(protocol, dport)) {
        pf_count(0);
        return XDP_PASS;
    }

    if (bpf_map_lookup_elem(&pf_ports, &dport)) {
        pf_count(0);
        return XDP_PASS;
    }

    pf_count(1);
    return XDP_DROP;
}

char _license[] SEC("license") = "MIT";
