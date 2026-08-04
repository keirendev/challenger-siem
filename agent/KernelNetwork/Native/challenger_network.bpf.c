#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "challenger_network_shared.h"
#include "challenger_network_parser.h"

struct sock_common___local {
    __u32 skc_daddr;
    __u32 skc_rcv_saddr;
    __u16 skc_dport;
    __u16 skc_num;
    __u16 skc_family;
    __u8 skc_state;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock___local {
    struct sock_common___local __sk_common;
} __attribute__((preserve_access_index));

#define CHALLENGER_AF_INET 2
#define CHALLENGER_AF_INET6 10

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CHALLENGER_FLOW_MAP_ENTRIES);
    __type(key, struct challenger_flow_key);
    __type(value, struct challenger_flow_value);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, CHALLENGER_OWNER_MAP_ENTRIES);
    __type(key, struct challenger_owner_key);
    __type(value, struct challenger_owner_value);
} owner_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CHALLENGER_COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} health_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, CHALLENGER_RING_BYTES);
} flow_notices SEC(".maps");

static __always_inline void increment_counter(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&health_counters, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int load_network_bytes(
    const struct __sk_buff *skb,
    __u32 offset,
    void *destination,
    __u32 length)
{
    return bpf_skb_load_bytes_relative(
        skb,
        offset,
        destination,
        length,
        BPF_HDR_START_NET);
}

static __always_inline void record_unsupported_header(__u32 reason)
{
    increment_counter(CHALLENGER_COUNTER_UNSUPPORTED_HEADER);
    increment_counter(reason);
}

static __always_inline void record_ipv6_extension(__u8 protocol)
{
    if (protocol == 0) increment_counter(CHALLENGER_COUNTER_IPV6_HOP_BY_HOP);
    else if (protocol == 43) increment_counter(CHALLENGER_COUNTER_IPV6_ROUTING);
    else if (protocol == 44) increment_counter(CHALLENGER_COUNTER_IPV6_FRAGMENT);
    else if (protocol == 50) increment_counter(CHALLENGER_COUNTER_IPV6_ESP);
    else if (protocol == 51) increment_counter(CHALLENGER_COUNTER_IPV6_AH);
    else if (protocol == 60) increment_counter(CHALLENGER_COUNTER_IPV6_DESTINATION);
    else if (protocol == 135) increment_counter(CHALLENGER_COUNTER_IPV6_MOBILITY);
}

static __always_inline enum challenger_parse_result resolve_ipv6_transport(
    const struct __sk_buff *skb,
    struct challenger_parsed_ip *parsed)
{
    #pragma unroll
    for (int index = 0; index < 4; index++) {
        __u8 prefix[8] = {};
        __u8 protocol = parsed->protocol;
        __u8 next_protocol = 0;
        __u16 header_length = 0;
        if (!challenger_is_ipv6_extension(protocol))
            return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP
                ? CHALLENGER_PARSE_OK : CHALLENGER_PARSE_NOT_TCP_UDP;
        record_ipv6_extension(protocol);
        if (load_network_bytes(skb, parsed->layer4_offset, prefix, sizeof(prefix)) < 0)
            return CHALLENGER_PARSE_MALFORMED;
        enum challenger_parse_result result = challenger_parse_ipv6_extension(
            protocol, prefix, &next_protocol, &header_length);
        if (result != CHALLENGER_PARSE_OK)
            return result;
        if (header_length > 128 || parsed->layer4_offset > 256 - header_length)
            return CHALLENGER_PARSE_MALFORMED;
        parsed->layer4_offset += header_length;
        parsed->protocol = next_protocol;
    }
    if (parsed->protocol == IPPROTO_TCP || parsed->protocol == IPPROTO_UDP)
        return CHALLENGER_PARSE_OK;
    if (!challenger_is_ipv6_extension(parsed->protocol))
        return CHALLENGER_PARSE_NOT_TCP_UDP;
    increment_counter(CHALLENGER_COUNTER_IPV6_CHAIN_LIMIT);
    return CHALLENGER_PARSE_UNSUPPORTED;
}

static __always_inline int capture_owner(struct bpf_sock_addr *ctx, __u8 family)
{
    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return 1;

    struct challenger_owner_key key = {};
    struct challenger_owner_value value = {};
    key.family = family;
    key.protocol = (__u8)ctx->protocol;
    if (ctx->sk) {
        key.local_port = (__u16)ctx->sk->src_port;
        if (family == 4)
            __builtin_memcpy(key.local_address, &ctx->sk->src_ip4, 4);
        else {
            ((__u32 *)key.local_address)[0] = ctx->sk->src_ip6[0];
            ((__u32 *)key.local_address)[1] = ctx->sk->src_ip6[1];
            ((__u32 *)key.local_address)[2] = ctx->sk->src_ip6[2];
            ((__u32 *)key.local_address)[3] = ctx->sk->src_ip6[3];
        }
    }
    key.remote_port = bpf_ntohs((__u16)ctx->user_port);
    if (family == 4)
        __builtin_memcpy(key.remote_address, &ctx->user_ip4, 4);
    else {
        ((__u32 *)key.remote_address)[0] = ctx->user_ip6[0];
        ((__u32 *)key.remote_address)[1] = ctx->user_ip6[1];
        ((__u32 *)key.remote_address)[2] = ctx->user_ip6[2];
        ((__u32 *)key.remote_address)[3] = ctx->user_ip6[3];
    }
    value.process_id = (__u32)(bpf_get_current_pid_tgid() >> 32);
    value.user_id = (__u32)bpf_get_current_uid_gid();
    value.observed_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(value.process_name, sizeof(value.process_name));
    bpf_map_update_elem(&owner_map, &key, &value, BPF_ANY);
    return 1;
}

SEC("cgroup/connect4")
int challenger_connect4(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 4); }
SEC("cgroup/connect6")
int challenger_connect6(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 6); }
SEC("cgroup/sendmsg4")
int challenger_sendmsg4(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 4); }
SEC("cgroup/sendmsg6")
int challenger_sendmsg6(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 6); }
SEC("cgroup/recvmsg4")
int challenger_recvmsg4(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 4); }
SEC("cgroup/recvmsg6")
int challenger_recvmsg6(struct bpf_sock_addr *ctx) { return capture_owner(ctx, 6); }

static __always_inline int capture_bind_owner(struct bpf_sock_addr *ctx, __u8 family)
{
    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
        return 1;
    struct challenger_owner_key key = {};
    struct challenger_owner_value value = {};
    key.family = family;
    key.protocol = (__u8)ctx->protocol;
    key.local_port = bpf_ntohs((__u16)ctx->user_port);
    if (family == 4)
        __builtin_memcpy(key.local_address, &ctx->user_ip4, 4);
    else {
        ((__u32 *)key.local_address)[0] = ctx->user_ip6[0];
        ((__u32 *)key.local_address)[1] = ctx->user_ip6[1];
        ((__u32 *)key.local_address)[2] = ctx->user_ip6[2];
        ((__u32 *)key.local_address)[3] = ctx->user_ip6[3];
    }
    value.process_id = (__u32)(bpf_get_current_pid_tgid() >> 32);
    value.user_id = (__u32)bpf_get_current_uid_gid();
    value.observed_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(value.process_name, sizeof(value.process_name));
    bpf_map_update_elem(&owner_map, &key, &value, BPF_ANY);
    return 1;
}

SEC("cgroup/bind4")
int challenger_bind4(struct bpf_sock_addr *ctx) { return capture_bind_owner(ctx, 4); }
SEC("cgroup/bind6")
int challenger_bind6(struct bpf_sock_addr *ctx) { return capture_bind_owner(ctx, 6); }

SEC("cgroup/sock_create")
int challenger_socket_create(struct bpf_sock *socket)
{
    (void)socket;
    return 1;
}

static __always_inline void capture_sockops_owner(struct bpf_sock_ops *ctx)
{
    if (ctx->family != CHALLENGER_AF_INET && ctx->family != CHALLENGER_AF_INET6)
        return;
    struct challenger_owner_key key = {};
    struct challenger_owner_value value = {};
    key.family = ctx->family == CHALLENGER_AF_INET ? 4 : 6;
    key.protocol = IPPROTO_TCP;
    key.local_port = (__u16)ctx->local_port;
    key.remote_port = bpf_ntohl(ctx->remote_port) >> 16;
    if (key.family == 4) {
        __builtin_memcpy(key.local_address, &ctx->local_ip4, 4);
        __builtin_memcpy(key.remote_address, &ctx->remote_ip4, 4);
    } else {
        ((__u32 *)key.local_address)[0] = ctx->local_ip6[0];
        ((__u32 *)key.local_address)[1] = ctx->local_ip6[1];
        ((__u32 *)key.local_address)[2] = ctx->local_ip6[2];
        ((__u32 *)key.local_address)[3] = ctx->local_ip6[3];
        ((__u32 *)key.remote_address)[0] = ctx->remote_ip6[0];
        ((__u32 *)key.remote_address)[1] = ctx->remote_ip6[1];
        ((__u32 *)key.remote_address)[2] = ctx->remote_ip6[2];
        ((__u32 *)key.remote_address)[3] = ctx->remote_ip6[3];
    }
    value.process_id = (__u32)(bpf_get_current_pid_tgid() >> 32);
    value.user_id = CHALLENGER_UNKNOWN_USER_ID;
    value.observed_ns = bpf_ktime_get_ns();
    if (value.process_id != 0)
        bpf_map_update_elem(&owner_map, &key, &value, BPF_ANY);
}

SEC("sockops")
int challenger_sockops(struct bpf_sock_ops *ctx)
{
    if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB
        || ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
        capture_sockops_owner(ctx);
    return 1;
}

SEC("raw_tracepoint/inet_sock_set_state")
int challenger_accept_close_trace(struct bpf_raw_tracepoint_args *ctx)
{
    const struct sock___local *socket = (const struct sock___local *)(unsigned long)ctx->args[0];
    int old_state = (int)ctx->args[1];
    int new_state = (int)ctx->args[2];
    if (!socket || (new_state != BPF_TCP_ESTABLISHED && new_state != BPF_TCP_CLOSE))
        return 0;
    __u16 family = BPF_CORE_READ(socket, __sk_common.skc_family);
    if (family != CHALLENGER_AF_INET && family != CHALLENGER_AF_INET6)
        return 0;
    struct challenger_owner_key key = {};
    struct challenger_owner_value value = {};
    key.family = family == CHALLENGER_AF_INET ? 4 : 6;
    key.protocol = IPPROTO_TCP;
    key.local_port = BPF_CORE_READ(socket, __sk_common.skc_num);
    key.remote_port = bpf_ntohs(BPF_CORE_READ(socket, __sk_common.skc_dport));
    if (family == CHALLENGER_AF_INET) {
        __u32 local = BPF_CORE_READ(socket, __sk_common.skc_rcv_saddr);
        __u32 remote = BPF_CORE_READ(socket, __sk_common.skc_daddr);
        __builtin_memcpy(key.local_address, &local, 4);
        __builtin_memcpy(key.remote_address, &remote, 4);
    } else {
        BPF_CORE_READ_INTO(key.local_address, socket, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(key.remote_address, socket, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    value.process_id = (__u32)(bpf_get_current_pid_tgid() >> 32);
    value.user_id = (__u32)bpf_get_current_uid_gid();
    value.observed_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(value.process_name, sizeof(value.process_name));
    if (value.process_id != 0
        && (new_state == BPF_TCP_ESTABLISHED || old_state == BPF_TCP_ESTABLISHED))
        bpf_map_update_elem(&owner_map, &key, &value, BPF_ANY);
    return 0;
}

static __always_inline int capture_packet(struct __sk_buff *skb, __u8 direction)
{
    __u64 now = bpf_ktime_get_ns();
    __u8 first = 0;
    if (load_network_bytes(skb, 0, &first, 1) < 0) {
        increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
        return 1;
    }

    struct challenger_flow_key key = {};
    struct challenger_parsed_ip parsed = {};
    __u16 source_port = 0;
    __u16 destination_port = 0;
    __u8 tcp_flags = 0;
    __u8 version = first >> 4;
    if (version == 4) {
        __u8 header[20] = {};
        if (load_network_bytes(skb, 0, header, sizeof(header)) < 0) {
            increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
            return 1;
        }
        enum challenger_parse_result result = challenger_parse_ipv4(header, &parsed);
        if (result != CHALLENGER_PARSE_OK) {
            if (result == CHALLENGER_PARSE_MALFORMED) increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
            else if (result == CHALLENGER_PARSE_UNSUPPORTED)
                record_unsupported_header(CHALLENGER_COUNTER_UNSUPPORTED_IPV4_FRAGMENT);
            return 1;
        }
    } else if (version == 6) {
        __u8 header[40] = {};
        if (load_network_bytes(skb, 0, header, sizeof(header)) < 0) {
            increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
            return 1;
        }
        enum challenger_parse_result result = challenger_parse_ipv6(header, &parsed);
        if (result == CHALLENGER_PARSE_EXTENSION)
            result = resolve_ipv6_transport(skb, &parsed);
        if (result != CHALLENGER_PARSE_OK) {
            if (result == CHALLENGER_PARSE_MALFORMED) increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
            else if (result == CHALLENGER_PARSE_UNSUPPORTED)
                record_unsupported_header(CHALLENGER_COUNTER_UNSUPPORTED_IPV6_EXTENSION);
            return 1;
        }
    } else {
        record_unsupported_header(CHALLENGER_COUNTER_UNSUPPORTED_NON_IP);
        return 1;
    }

    key.family = parsed.family;
    challenger_normalize_addresses(
        &parsed,
        direction == CHALLENGER_DIRECTION_EGRESS,
        key.local_address,
        key.remote_address);
    if (load_network_bytes(skb, parsed.layer4_offset, &source_port, sizeof(source_port)) < 0
        || load_network_bytes(skb, parsed.layer4_offset + 2, &destination_port, sizeof(destination_port)) < 0) {
        increment_counter(CHALLENGER_COUNTER_PARSE_FAILURE);
        return 1;
    }
    source_port = bpf_ntohs(source_port);
    destination_port = bpf_ntohs(destination_port);
    key.protocol = parsed.protocol;
    key.direction = direction;
    key.local_port = direction == CHALLENGER_DIRECTION_EGRESS ? source_port : destination_port;
    key.remote_port = direction == CHALLENGER_DIRECTION_EGRESS ? destination_port : source_port;
    /* cgroup-SKB execution context is not a reliable userspace owner. */
    key.process_id = 0;
    key.user_id = CHALLENGER_UNKNOWN_USER_ID;
    key.reserved = 0;

    struct challenger_owner_key owner_key = {};
    owner_key.family = key.family;
    owner_key.protocol = key.protocol;
    owner_key.local_port = key.local_port;
    owner_key.remote_port = key.remote_port;
    __builtin_memcpy(owner_key.local_address, key.local_address, sizeof(owner_key.local_address));
    __builtin_memcpy(owner_key.remote_address, key.remote_address, sizeof(owner_key.remote_address));
    struct challenger_owner_value *owner = bpf_map_lookup_elem(&owner_map, &owner_key);
    if (!owner) {
        __builtin_memset(owner_key.local_address, 0, sizeof(owner_key.local_address));
        owner_key.local_port = 0;
        owner = bpf_map_lookup_elem(&owner_map, &owner_key);
    }
    if (!owner) {
        __builtin_memset(owner_key.remote_address, 0, sizeof(owner_key.remote_address));
        owner_key.remote_port = 0;
        owner_key.local_port = key.local_port;
        __builtin_memcpy(owner_key.local_address, key.local_address, sizeof(owner_key.local_address));
        owner = bpf_map_lookup_elem(&owner_map, &owner_key);
    }
    if (owner && owner->process_id != 0
        && now >= owner->observed_ns && now - owner->observed_ns <= CHALLENGER_OWNER_WINDOW_NS) {
        key.process_id = owner->process_id;
        key.user_id = owner->user_id;
        key.reserved = 2;
        __builtin_memcpy(key.process_name, owner->process_name, sizeof(key.process_name));
    } else {
        increment_counter(CHALLENGER_COUNTER_OWNER_MISS);
    }
    if (parsed.protocol == IPPROTO_TCP)
        load_network_bytes(skb, parsed.layer4_offset + 13, &tcp_flags, 1);

    struct challenger_flow_value *existing = bpf_map_lookup_elem(&flow_map, &key);
    if (existing) {
        __sync_fetch_and_add(&existing->packet_count, 1);
        __sync_fetch_and_add(&existing->byte_count, skb->len);
        __sync_fetch_and_or(&existing->tcp_flags, (__u32)tcp_flags);
        existing->last_seen_ns = now;
        return 1;
    }

    struct challenger_flow_value initial = {
        .first_seen_ns = now,
        .last_seen_ns = now,
        .packet_count = 1,
        .byte_count = skb->len,
        .tcp_flags = tcp_flags,
    };
    if (bpf_map_update_elem(&flow_map, &key, &initial, BPF_NOEXIST) < 0) {
        increment_counter(CHALLENGER_COUNTER_FLOW_MAP_FULL);
        return 1;
    }
    struct challenger_ring_notice *notice = bpf_ringbuf_reserve(&flow_notices, sizeof(*notice), 0);
    if (!notice) {
        increment_counter(CHALLENGER_COUNTER_RING_LOSS);
        return 1;
    }
    notice->key = key;
    notice->observed_ns = now;
    bpf_ringbuf_submit(notice, 0);
    return 1;
}

SEC("cgroup_skb/egress")
int challenger_egress(struct __sk_buff *skb) { return capture_packet(skb, CHALLENGER_DIRECTION_EGRESS); }
SEC("cgroup_skb/ingress")
int challenger_ingress(struct __sk_buff *skb) { return capture_packet(skb, CHALLENGER_DIRECTION_INGRESS); }

char LICENSE[] SEC("license") = "GPL";
