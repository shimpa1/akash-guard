// SPDX-License-Identifier: GPL-2.0
// TC egress hook: per-pod traffic counters for abuse detection.
// Attached to each pod veth interface on the host side.
// Userspace reads metrics via BPF maps.

//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Key identifying a pod veth by its ifindex.
typedef __u32 ifindex_t;

// Per-interface counters stored in maps.
struct pkt_counters {
    __u64 packets;
    __u64 bytes;
    __u64 syn_packets;
    __u64 port25_conns;
};

// Map: ifindex → packet counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, ifindex_t);
    __type(value, struct pkt_counters);
    __uint(max_entries, 4096);
} counters SEC(".maps");

// Token-bucket state for per-interface rate limiting.
// Written by the Go-side Enforcer when a namespace exceeds a detection threshold;
// deleted when the cooldown expires. Lock must be the first field.
struct ratelimit_state {
    struct bpf_spin_lock lock;  // 4 bytes — must be first
    __u32  _pad;                // align following fields to 8-byte boundary
    __u64  tokens;              // current token count (bytes)
    __u64  last_ns;             // timestamp of last token refill (bpf_ktime_get_ns)
    __u64  rate_bps;            // allowed throughput in bytes/second
    __u64  burst;               // maximum token accumulation (bytes)
};

// Map: ifindex → ratelimit_state.
// BPF_MAP_TYPE_HASH is required for maps with bpf_spin_lock values.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, ifindex_t);
    __type(value, struct ratelimit_state);
    __uint(max_entries, 4096);
} iface_ratelimit SEC(".maps");

// Perf event map for sending per-packet events to userspace (dst IP tracking).
struct pkt_event {
    __u32 ifindex;
    __u32 dst_ip;
    __u8  proto;
    __u16 dst_port;
    __u8  tcp_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Only handle IPv4 for now.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    ifindex_t ifidx = skb->ifindex;

    // Update per-interface packet counters.
    struct pkt_counters *cnt = bpf_map_lookup_elem(&counters, &ifidx);
    if (!cnt) {
        struct pkt_counters zero = {};
        bpf_map_update_elem(&counters, &ifidx, &zero, BPF_ANY);
        cnt = bpf_map_lookup_elem(&counters, &ifidx);
        if (!cnt)
            return TC_ACT_OK;
    }
    cnt->packets++;
    cnt->bytes += skb->len;

    __u16 dst_port = 0;
    __u8  tcp_flags = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end)
            goto emit;
        dst_port  = bpf_ntohs(tcph->dest);
        tcp_flags = ((__u8 *)tcph)[13]; // flags byte

        // Count SYN packets (SYN set, ACK clear).
        if ((tcp_flags & 0x02) && !(tcp_flags & 0x10))
            cnt->syn_packets++;

        // Count new connections to port 25 (SMTP).
        if (dst_port == 25 && (tcp_flags & 0x02) && !(tcp_flags & 0x10))
            cnt->port25_conns++;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) > data_end)
            goto emit;
        dst_port = bpf_ntohs(udph->dest);
    }

emit:;
    // Emit event to ring buffer for unique-dst-IP tracking in userspace.
    struct pkt_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (ev) {
        ev->ifindex  = ifidx;
        ev->dst_ip   = iph->daddr;
        ev->proto    = iph->protocol;
        ev->dst_port = dst_port;
        ev->tcp_flags = tcp_flags;
        bpf_ringbuf_submit(ev, 0);
    }

    // eBPF token-bucket rate limiting.
    // Stats are recorded before this point so detection still fires on abusive
    // traffic even while it is being rate-limited.
    // The Go-side Enforcer inserts an entry here when a namespace trips a threshold
    // and removes it after the cooldown expires.
    struct ratelimit_state *rl = bpf_map_lookup_elem(&iface_ratelimit, &ifidx);
    if (rl) {
        __u64 now = bpf_ktime_get_ns();
        __u32 pkt_bytes = skb->len;
        int drop = 0;

        bpf_spin_lock(&rl->lock);

        __u64 elapsed = now - rl->last_ns;
        if (elapsed > 1000000000ULL)
            elapsed = 1000000000ULL;            // cap at 1 s to bound token gain and prevent overflow
        __u64 added   = rl->rate_bps * elapsed / 1000000000ULL;
        __u64 tokens  = rl->tokens + added;
        if (tokens > rl->burst)
            tokens = rl->burst;
        rl->last_ns = now;

        if (tokens >= pkt_bytes) {
            rl->tokens = tokens - pkt_bytes;
        } else {
            rl->tokens = tokens;
            drop = 1;
        }

        bpf_spin_unlock(&rl->lock);

        if (drop)
            return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
