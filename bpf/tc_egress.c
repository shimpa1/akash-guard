// SPDX-License-Identifier: GPL-2.0
// TC egress hook: per-pod traffic counters for abuse detection.
// Attached to each pod veth interface on the host side.
// Userspace reads metrics via BPF maps.

//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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

emit:
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

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
