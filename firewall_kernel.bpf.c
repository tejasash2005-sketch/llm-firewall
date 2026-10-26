// SPDX-License-Identifier: GPL-2.0
//
// Build:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//         -I/usr/include/$(uname -m)-linux-gnu \
//         -c firewall_kernel.bpf.c -o firewall_kernel.bpf.o
//
// Transparent redirection of outbound TCP/443 connections whose destination is
// in the target sets to the local firewall proxy, plus an audit ring buffer.
// The proxy's own PID is exempt so its upstream connections are never looped.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define HTTPS_PORT 443
#define MAX_TARGETS 4096

struct fw_cfg {
    __u32 proxy_ip;    /* network byte order */
    __u32 proxy_pid;   /* tgid of the proxy process */
    __u16 proxy_port;  /* network byte order */
    __u16 pad;
};

struct in6_key {
    __u32 addr[4];
};

struct fw_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 dst_ip4;     /* IPv4 address in network byte order; zero for IPv6 events */
    __u32 dst_ip6[4];  /* Full IPv6 address as four network-order words; zero for IPv4 events */
    __u16 dst_port;    /* network byte order */
    __u16 family;
    char comm[16];
    __u32 pad;
};

_Static_assert(sizeof(struct fw_cfg) == 12, "fw_cfg layout changed");
_Static_assert(offsetof(struct fw_cfg, proxy_ip) == 0, "fw_cfg proxy_ip offset changed");
_Static_assert(offsetof(struct fw_cfg, proxy_pid) == 4, "fw_cfg proxy_pid offset changed");
_Static_assert(offsetof(struct fw_cfg, proxy_port) == 8, "fw_cfg proxy_port offset changed");
_Static_assert(offsetof(struct fw_cfg, pad) == 10, "fw_cfg pad offset changed");
_Static_assert(sizeof(struct in6_key) == 16, "in6_key layout changed");
_Static_assert(offsetof(struct in6_key, addr) == 0, "in6_key addr offset changed");
_Static_assert(sizeof(struct fw_event) == 56, "fw_event layout changed");
_Static_assert(offsetof(struct fw_event, dst_ip4) == 12, "fw_event dst_ip4 offset changed");
_Static_assert(offsetof(struct fw_event, dst_ip6) == 16, "fw_event dst_ip6 offset changed");
_Static_assert(offsetof(struct fw_event, dst_port) == 32, "fw_event dst_port offset changed");
_Static_assert(offsetof(struct fw_event, comm) == 36, "fw_event comm offset changed");
_Static_assert(MAX_TARGETS == 4096, "target map capacity changed");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fw_cfg);
} fw_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGETS);
    __type(key, __u32);
    __type(value, __u8);
} target_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TARGETS);
    __type(key, struct in6_key);
    __type(value, __u8);
} target_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Per-CPU storage avoids cross-CPU contention. Incrementing this counter does not
 * affect whether a matching connection is redirected. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} audit_drops SEC(".maps");

static __always_inline void emit_event(__u32 ip4, __u32 ip6_0, __u32 ip6_1,
                                       __u32 ip6_2, __u32 ip6_3,
                                       __u16 port_be, __u16 family)
{
    struct fw_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 zero = 0;
        __u64 *dropped = bpf_map_lookup_elem(&audit_drops, &zero);
        if (dropped)
            *dropped += 1;
        return;
    }
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->dst_ip4 = ip4;
    e->dst_ip6[0] = ip6_0;
    e->dst_ip6[1] = ip6_1;
    e->dst_ip6[2] = ip6_2;
    e->dst_ip6[3] = ip6_3;
    e->dst_port = port_be;
    e->family = family;
    e->pad = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

SEC("cgroup/connect4")
int firewall_connect4(struct bpf_sock_addr *ctx)
{
    if (ctx->type != SOCK_STREAM)
        return 1;
    if (bpf_ntohs((__u16)ctx->user_port) != HTTPS_PORT)
        return 1;

    __u32 zero = 0;
    struct fw_cfg *cfg = bpf_map_lookup_elem(&fw_config, &zero);
    if (!cfg || cfg->proxy_port == 0)
        return 1;
    if ((__u32)(bpf_get_current_pid_tgid() >> 32) == cfg->proxy_pid)
        return 1;

    __u32 dst = ctx->user_ip4;
    if (!bpf_map_lookup_elem(&target_v4, &dst))
        return 1;

    emit_event(dst, 0, 0, 0, 0, (__u16)ctx->user_port, AF_INET);
    ctx->user_ip4 = cfg->proxy_ip;
    ctx->user_port = cfg->proxy_port;
    return 1;
}

SEC("cgroup/connect6")
int firewall_connect6(struct bpf_sock_addr *ctx)
{
    if (ctx->type != SOCK_STREAM)
        return 1;
    if (bpf_ntohs((__u16)ctx->user_port) != HTTPS_PORT)
        return 1;

    __u32 zero = 0;
    struct fw_cfg *cfg = bpf_map_lookup_elem(&fw_config, &zero);
    if (!cfg || cfg->proxy_port == 0)
        return 1;
    if ((__u32)(bpf_get_current_pid_tgid() >> 32) == cfg->proxy_pid)
        return 1;

    __u32 w0 = ctx->user_ip6[0];
    __u32 w1 = ctx->user_ip6[1];
    __u32 w2 = ctx->user_ip6[2];
    __u32 w3 = ctx->user_ip6[3];

    int hit;
    if (w0 == 0 && w1 == 0 && w2 == bpf_htonl(0x0000ffff)) {
        /* v4-mapped destination on a dual-stack socket */
        hit = bpf_map_lookup_elem(&target_v4, &w3) != 0;
    } else {
        struct in6_key key = {};
        key.addr[0] = w0;
        key.addr[1] = w1;
        key.addr[2] = w2;
        key.addr[3] = w3;
        hit = bpf_map_lookup_elem(&target_v6, &key) != 0;
    }
    if (!hit)
        return 1;

    emit_event(0, w0, w1, w2, w3, (__u16)ctx->user_port, AF_INET6);

    /* Redirect to ::ffff:<proxy_ip> (the proxy listens on IPv4 loopback). */
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
    ctx->user_ip6[3] = cfg->proxy_ip;
    ctx->user_port = cfg->proxy_port;
    return 1;
}

char LICENSE[] SEC("license") = "GPL";
