#ifndef CHALLENGER_NETWORK_SHARED_H
#define CHALLENGER_NETWORK_SHARED_H

#include <linux/types.h>

#define CHALLENGER_FLOW_MAP_ENTRIES 16384
#define CHALLENGER_OWNER_MAP_ENTRIES 32768
#define CHALLENGER_RING_BYTES (1024 * 1024)
#define CHALLENGER_MAX_DRAIN_RECORDS 500
#define CHALLENGER_KERNEL_DRAIN_INTERVAL_SECONDS 1
#define CHALLENGER_HEALTH_INTERVAL_SECONDS 10
#define CHALLENGER_MAX_KERNEL_RECORDS_PER_HEALTH_INTERVAL \
    (CHALLENGER_MAX_DRAIN_RECORDS * CHALLENGER_HEALTH_INTERVAL_SECONDS)
#define CHALLENGER_FRAME_MAX_BYTES 16384
#define CHALLENGER_OWNER_WINDOW_NS (60ULL * 1000000000ULL)
#define CHALLENGER_UNKNOWN_USER_ID ((__u32)-1)

enum challenger_direction {
    CHALLENGER_DIRECTION_UNKNOWN = 0,
    CHALLENGER_DIRECTION_INGRESS = 1,
    CHALLENGER_DIRECTION_EGRESS = 2,
};

enum challenger_counter {
    CHALLENGER_COUNTER_PARSE_FAILURE = 0,
    CHALLENGER_COUNTER_UNSUPPORTED_HEADER = 1,
    CHALLENGER_COUNTER_FLOW_MAP_FULL = 2,
    CHALLENGER_COUNTER_OWNER_MISS = 3,
    CHALLENGER_COUNTER_RING_LOSS = 4,
    CHALLENGER_COUNTER_UNSUPPORTED_NON_IP = 5,
    CHALLENGER_COUNTER_UNSUPPORTED_IPV4_FRAGMENT = 6,
    CHALLENGER_COUNTER_UNSUPPORTED_IPV6_EXTENSION = 7,
    CHALLENGER_COUNTER_IPV6_HOP_BY_HOP = 8,
    CHALLENGER_COUNTER_IPV6_ROUTING = 9,
    CHALLENGER_COUNTER_IPV6_FRAGMENT = 10,
    CHALLENGER_COUNTER_IPV6_ESP = 11,
    CHALLENGER_COUNTER_IPV6_AH = 12,
    CHALLENGER_COUNTER_IPV6_DESTINATION = 13,
    CHALLENGER_COUNTER_IPV6_MOBILITY = 14,
    CHALLENGER_COUNTER_IPV6_CHAIN_LIMIT = 15,
    CHALLENGER_COUNTER_TRACKED_FLOW_TABLE_FULL = 16,
    CHALLENGER_COUNTER_MAX = 17,
};

struct challenger_flow_key {
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 reserved;
    __u32 process_id;
    __u32 user_id;
    __u16 local_port;
    __u16 remote_port;
    __u8 local_address[16];
    __u8 remote_address[16];
    char process_name[16];
};

struct challenger_flow_value {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 packet_count;
    __u64 byte_count;
    __u32 tcp_flags;
    __u32 reserved;
};

struct challenger_owner_key {
    __u8 family;
    __u8 protocol;
    __u16 local_port;
    __u16 remote_port;
    __u16 reserved;
    __u8 local_address[16];
    __u8 remote_address[16];
};

struct challenger_owner_value {
    __u32 process_id;
    __u32 user_id;
    __u64 observed_ns;
    char process_name[16];
};

struct challenger_ring_notice {
    struct challenger_flow_key key;
    __u64 observed_ns;
};

#endif
