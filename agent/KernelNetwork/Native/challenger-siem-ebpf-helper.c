#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "challenger_network_shared.h"
#include "challenger_network_time.h"

#define HELPER_VERSION "challenger-siem-ebpf-helper-v1"
#define DEFAULT_CGROUP "/sys/fs/cgroup"
#define EXPECTED_CLIENT "challenger-siem"
#define ACTIVE_SUMMARY_NS (60ULL * 1000000000ULL)
#define TCP_FIN_FLAG 0x01U
#define TCP_RST_FLAG 0x04U

extern const unsigned char _binary_challenger_network_bpf_o_start[];
extern const unsigned char _binary_challenger_network_bpf_o_end[];

static volatile sig_atomic_t stopping;
static uint64_t ipc_send_failures;

struct tracked_flow {
    bool occupied;
    bool started_emitted;
    bool close_requested;
    struct challenger_flow_key key;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t last_emitted_ns;
    uint64_t packet_count;
    uint64_t byte_count;
    uint32_t tcp_flags;
};

static struct tracked_flow tracked_flows[CHALLENGER_FLOW_MAP_ENTRIES];
static size_t tracked_cursor;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static int discard_notice(void *context, void *data, size_t length)
{
    (void)context;
    (void)data;
    (void)length;
    return 0;
}

static void format_epoch(char output[33])
{
    unsigned char bytes[16] = {};
    ssize_t read_count = getrandom(bytes, sizeof(bytes), 0);
    if (read_count != (ssize_t)sizeof(bytes)) {
        struct timespec now = {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        memcpy(bytes, &now, sizeof(now) < sizeof(bytes) ? sizeof(now) : sizeof(bytes));
    }
    for (size_t index = 0; index < sizeof(bytes); index++)
        snprintf(output + index * 2, 3, "%02x", bytes[index]);
    output[32] = '\0';
}

static int inherited_listener(void)
{
    const char *pid_text = getenv("LISTEN_PID");
    const char *count_text = getenv("LISTEN_FDS");
    char *end = NULL;
    long pid = pid_text ? strtol(pid_text, &end, 10) : 0;
    if (!pid_text || *pid_text == '\0' || !end || *end != '\0' || pid != getpid())
        return -1;
    end = NULL;
    long count = count_text ? strtol(count_text, &end, 10) : 0;
    if (!count_text || *count_text == '\0' || !end || *end != '\0' || count != 1)
        return -1;
    int type = 0;
    socklen_t length = sizeof(type);
    if (getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &length) != 0 || type != SOCK_SEQPACKET)
        return -1;
    return 3;
}

static int expected_client_uid(uid_t *uid)
{
    struct passwd storage = {};
    struct passwd *result = NULL;
    char buffer[16384];
    int rc = getpwnam_r(EXPECTED_CLIENT, &storage, buffer, sizeof(buffer), &result);
    if (rc != 0 || !result || result->pw_uid == 0)
        return -1;
    *uid = result->pw_uid;
    return 0;
}

static int accept_client(int listener, uid_t expected_uid)
{
    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client < 0)
        return -1;
    struct ucred credentials = {};
    socklen_t length = sizeof(credentials);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0
        || length != sizeof(credentials)
        || credentials.uid != expected_uid
        || credentials.pid <= 0) {
        close(client);
        errno = EPERM;
        return -1;
    }
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    if (setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        close(client);
        return -1;
    }
    return client;
}

static int send_frame(int client, const char *frame)
{
    size_t length = strnlen(frame, CHALLENGER_FRAME_MAX_BYTES + 1);
    if (length == 0 || length > CHALLENGER_FRAME_MAX_BYTES) {
        errno = EMSGSIZE;
        return -1;
    }
    ssize_t sent = send(client, frame, length, MSG_NOSIGNAL);
    if (sent != (ssize_t)length) {
        ipc_send_failures++;
        return -1;
    }
    return 0;
}

static int read_clock_anchor(uint64_t *realtime_ns, uint64_t *monotonic_ns)
{
    struct timespec realtime = {};
    struct timespec monotonic = {};
    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0
        || clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0)
        return -1;
    *realtime_ns = (uint64_t)realtime.tv_sec * 1000000000ULL + (uint64_t)realtime.tv_nsec;
    *monotonic_ns = (uint64_t)monotonic.tv_sec * 1000000000ULL + (uint64_t)monotonic.tv_nsec;
    return 0;
}

static void address_text(const struct challenger_flow_key *key, bool local, char output[INET6_ADDRSTRLEN])
{
    const void *address = local ? (const void *)key->local_address : (const void *)key->remote_address;
    int family = key->family == 4 ? AF_INET : AF_INET6;
    if (!inet_ntop(family, address, output, INET6_ADDRSTRLEN))
        snprintf(output, INET6_ADDRSTRLEN, "invalid");
}

static void json_process_name(const char input[16], char output[65])
{
    size_t write_index = 0;
    for (size_t index = 0; index < 16 && input[index] != '\0' && write_index + 2 < 65; index++) {
        unsigned char value = (unsigned char)input[index];
        if (value == '"' || value == '\\') {
            output[write_index++] = '\\';
            output[write_index++] = (char)value;
        } else if (value >= 0x20 && value <= 0x7e) {
            output[write_index++] = (char)value;
        } else {
            output[write_index++] = '?';
        }
    }
    output[write_index] = '\0';
}

static void read_health(int health_fd, uint64_t values[CHALLENGER_COUNTER_MAX])
{
    memset(values, 0, sizeof(uint64_t) * CHALLENGER_COUNTER_MAX);
    for (uint32_t index = 0; index < CHALLENGER_COUNTER_MAX; index++)
        bpf_map_lookup_elem(health_fd, &index, &values[index]);
}

static void increment_health_counter(int health_fd, uint32_t index)
{
    uint64_t value = 0;
    if (bpf_map_lookup_elem(health_fd, &index, &value) == 0) {
        if (value != UINT64_MAX) value++;
        bpf_map_update_elem(health_fd, &index, &value, BPF_ANY);
    }
}

static uint64_t flow_hash(const struct challenger_flow_key *key)
{
    const unsigned char *bytes = (const unsigned char *)key;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t index = 0; index < sizeof(*key); index++) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static struct tracked_flow *find_tracked_flow(
    const struct challenger_flow_key *key,
    int health_fd)
{
    size_t start = (size_t)(flow_hash(key) & (CHALLENGER_FLOW_MAP_ENTRIES - 1));
    for (size_t offset = 0; offset < CHALLENGER_FLOW_MAP_ENTRIES; offset++) {
        struct tracked_flow *candidate = &tracked_flows[(start + offset) & (CHALLENGER_FLOW_MAP_ENTRIES - 1)];
        if (!candidate->occupied) {
            memset(candidate, 0, sizeof(*candidate));
            candidate->occupied = true;
            candidate->key = *key;
            return candidate;
        }
        if (memcmp(&candidate->key, key, sizeof(*key)) == 0)
            return candidate;
    }
    increment_health_counter(health_fd, CHALLENGER_COUNTER_FLOW_MAP_FULL);
    return NULL;
}

static int collect_flows(
    int flow_fd,
    int health_fd)
{
    int collected = 0;
    for (; collected < CHALLENGER_MAX_DRAIN_RECORDS && !stopping; collected++) {
        struct challenger_flow_key key = {};
        struct challenger_flow_value value = {};
        if (bpf_map_get_next_key(flow_fd, NULL, &key) != 0) {
            if (errno == ENOENT)
                return collected;
            return -1;
        }
        if (bpf_map_lookup_and_delete_elem(flow_fd, &key, &value) != 0)
            continue;
        struct tracked_flow *tracked = find_tracked_flow(&key, health_fd);
        if (!tracked)
            continue;
        if (tracked->first_seen_ns == 0 || value.first_seen_ns < tracked->first_seen_ns)
            tracked->first_seen_ns = value.first_seen_ns;
        if (value.last_seen_ns > tracked->last_seen_ns)
            tracked->last_seen_ns = value.last_seen_ns;
        tracked->packet_count = UINT64_MAX - tracked->packet_count < value.packet_count
            ? UINT64_MAX : tracked->packet_count + value.packet_count;
        tracked->byte_count = UINT64_MAX - tracked->byte_count < value.byte_count
            ? UINT64_MAX : tracked->byte_count + value.byte_count;
        tracked->tcp_flags |= value.tcp_flags;
        if (key.protocol == IPPROTO_TCP && (value.tcp_flags & (TCP_FIN_FLAG | TCP_RST_FLAG)) != 0)
            tracked->close_requested = true;
    }
    return collected;
}

static int send_tracked_flow(
    int client,
    int health_fd,
    const char *epoch,
    uint64_t *sequence,
    struct tracked_flow *tracked,
    const char *event_code,
    uint64_t now_ns)
{
        const struct challenger_flow_key *key = &tracked->key;
        char local_address[INET6_ADDRSTRLEN] = {};
        char remote_address[INET6_ADDRSTRLEN] = {};
        char process_name[65] = {};
        char frame[CHALLENGER_FRAME_MAX_BYTES] = {};
        uint64_t health[CHALLENGER_COUNTER_MAX] = {};
        uint64_t realtime_anchor_ns = 0;
        uint64_t monotonic_anchor_ns = 0;
        if (read_clock_anchor(&realtime_anchor_ns, &monotonic_anchor_ns) != 0)
            return -1;
        address_text(key, true, local_address);
        address_text(key, false, remote_address);
        json_process_name(key->process_name, process_name);
        read_health(health_fd, health);
        const char *protocol = key->protocol == IPPROTO_TCP ? "tcp" : "udp";
        const char *direction = key->direction == CHALLENGER_DIRECTION_EGRESS ? "outbound"
            : key->direction == CHALLENGER_DIRECTION_INGRESS ? "inbound" : "unknown";
        const char *attribution_source = key->reserved == 1 ? "current_task" : key->reserved == 2 ? "recent_socket_owner" : "unattributed";
        int written = snprintf(frame, sizeof(frame),
            "{\"schema_version\":1,\"helper_version\":\"%s\",\"epoch\":\"%s\",\"sequence\":%llu,"
            "\"type\":\"flow\",\"event_code\":\"%s\",\"family\":%u,\"protocol\":\"%s\",\"direction\":\"%s\","
            "\"local_ip\":\"%s\",\"local_port\":%u,\"remote_ip\":\"%s\",\"remote_port\":%u,"
            "\"process_id\":%u,\"user_id\":%u,\"process_name\":\"%s\",\"attribution_source\":\"%s\",\"first_seen_unix_ns\":%llu,\"last_seen_unix_ns\":%llu,"
            "\"packet_count_delta\":%llu,\"byte_count_delta\":%llu,\"tcp_flags_mask\":%u,"
            "\"parse_failures\":%llu,\"unsupported_headers\":%llu,\"flow_map_full\":%llu,"
            "\"owner_misses\":%llu,\"ring_losses\":%llu,\"ipc_send_failures\":%llu}",
            HELPER_VERSION, epoch, (unsigned long long)(*sequence), event_code, key->family, protocol, direction,
            local_address, key->local_port, remote_address, key->remote_port,
            key->process_id, key->user_id, process_name, attribution_source,
            (unsigned long long)challenger_realtime_from_monotonic(
                tracked->first_seen_ns, realtime_anchor_ns, monotonic_anchor_ns),
            (unsigned long long)challenger_realtime_from_monotonic(
                tracked->last_seen_ns, realtime_anchor_ns, monotonic_anchor_ns),
            (unsigned long long)tracked->packet_count, (unsigned long long)tracked->byte_count, tracked->tcp_flags,
            (unsigned long long)health[CHALLENGER_COUNTER_PARSE_FAILURE],
            (unsigned long long)health[CHALLENGER_COUNTER_UNSUPPORTED_HEADER],
            (unsigned long long)health[CHALLENGER_COUNTER_FLOW_MAP_FULL],
            (unsigned long long)health[CHALLENGER_COUNTER_OWNER_MISS],
            (unsigned long long)health[CHALLENGER_COUNTER_RING_LOSS],
            (unsigned long long)ipc_send_failures);
        if (written <= 0 || written >= (int)sizeof(frame)) {
            errno = EMSGSIZE;
            return -1;
        }
        if (send_frame(client, frame) != 0)
            return -1;
        (*sequence)++;
        tracked->started_emitted = true;
        tracked->last_emitted_ns = now_ns;
        tracked->packet_count = 0;
        tracked->byte_count = 0;
        tracked->tcp_flags = 0;
        if (strcmp(event_code, "network_flow_closed") == 0)
            memset(tracked, 0, sizeof(*tracked));
        return 0;
}

static int emit_tracked_flows(
    int client,
    int health_fd,
    const char *epoch,
    uint64_t *sequence,
    uint64_t now_ns)
{
    int emitted = 0;
    size_t inspected = 0;
    while (inspected < CHALLENGER_FLOW_MAP_ENTRIES && emitted < CHALLENGER_MAX_DRAIN_RECORDS) {
        size_t index = tracked_cursor++ & (CHALLENGER_FLOW_MAP_ENTRIES - 1);
        inspected++;
        struct tracked_flow *tracked = &tracked_flows[index];
        if (!tracked->occupied)
            continue;
        if (now_ns >= tracked->last_seen_ns && now_ns - tracked->last_seen_ns >= ACTIVE_SUMMARY_NS)
            tracked->close_requested = true;
        const char *event_code = NULL;
        if (!tracked->started_emitted)
            event_code = "network_flow_started";
        else if (tracked->close_requested)
            event_code = "network_flow_closed";
        else if (tracked->packet_count > 0 && now_ns >= tracked->last_emitted_ns
            && now_ns - tracked->last_emitted_ns >= ACTIVE_SUMMARY_NS)
            event_code = "network_flow_sample";
        if (!event_code)
            continue;
        if (send_tracked_flow(client, health_fd, epoch, sequence, tracked, event_code, now_ns) != 0)
            return -1;
        emitted++;
    }
    return emitted;
}

static int send_health(int client, int health_fd, const char *epoch, uint64_t sequence)
{
    char frame[1024] = {};
    uint64_t health[CHALLENGER_COUNTER_MAX] = {};
    read_health(health_fd, health);
    int written = snprintf(frame, sizeof(frame),
        "{\"schema_version\":1,\"helper_version\":\"%s\",\"epoch\":\"%s\",\"sequence\":%llu,"
        "\"type\":\"health\",\"payload_capture\":false,\"parse_failures\":%llu,"
        "\"unsupported_headers\":%llu,\"flow_map_full\":%llu,\"owner_misses\":%llu,"
        "\"ring_losses\":%llu,\"ipc_send_failures\":%llu}",
        HELPER_VERSION, epoch, (unsigned long long)sequence,
        (unsigned long long)health[CHALLENGER_COUNTER_PARSE_FAILURE],
        (unsigned long long)health[CHALLENGER_COUNTER_UNSUPPORTED_HEADER],
        (unsigned long long)health[CHALLENGER_COUNTER_FLOW_MAP_FULL],
        (unsigned long long)health[CHALLENGER_COUNTER_OWNER_MISS],
        (unsigned long long)health[CHALLENGER_COUNTER_RING_LOSS],
        (unsigned long long)ipc_send_failures);
    if (written <= 0 || written >= (int)sizeof(frame)) {
        errno = EMSGSIZE;
        return -1;
    }
    return send_frame(client, frame);
}

static int send_hello(int client, const char *epoch, uint64_t sequence)
{
    char frame[1024] = {};
    snprintf(frame, sizeof(frame),
        "{\"schema_version\":1,\"helper_version\":\"%s\",\"epoch\":\"%s\",\"sequence\":%llu,"
        "\"type\":\"hello\",\"payload_capture\":false,\"flow_capacity\":%d,\"owner_capacity\":%d,"
        "\"ring_bytes\":%d,\"drain_seconds\":10,\"max_records_per_drain\":%d}",
        HELPER_VERSION, epoch, (unsigned long long)sequence, CHALLENGER_FLOW_MAP_ENTRIES,
        CHALLENGER_OWNER_MAP_ENTRIES, CHALLENGER_RING_BYTES, CHALLENGER_MAX_DRAIN_RECORDS);
    return send_frame(client, frame);
}

struct fixed_program {
    const char *name;
    const char *section;
    bool cgroup;
    enum bpf_attach_type attach_type;
};

static const struct fixed_program fixed_programs[] = {
    {"challenger_connect4", "cgroup/connect4", true, BPF_CGROUP_INET4_CONNECT},
    {"challenger_connect6", "cgroup/connect6", true, BPF_CGROUP_INET6_CONNECT},
    {"challenger_sendmsg4", "cgroup/sendmsg4", true, BPF_CGROUP_UDP4_SENDMSG},
    {"challenger_sendmsg6", "cgroup/sendmsg6", true, BPF_CGROUP_UDP6_SENDMSG},
    {"challenger_recvmsg4", "cgroup/recvmsg4", true, BPF_CGROUP_UDP4_RECVMSG},
    {"challenger_recvmsg6", "cgroup/recvmsg6", true, BPF_CGROUP_UDP6_RECVMSG},
    {"challenger_bind4", "cgroup/bind4", true, BPF_CGROUP_INET4_BIND},
    {"challenger_bind6", "cgroup/bind6", true, BPF_CGROUP_INET6_BIND},
    {"challenger_socket_create", "cgroup/sock_create", true, BPF_CGROUP_INET_SOCK_CREATE},
    {"challenger_sockops", "sockops", true, BPF_CGROUP_SOCK_OPS},
    {"challenger_accept_close_trace", "raw_tracepoint/inet_sock_set_state", false, BPF_CGROUP_INET_INGRESS},
    {"challenger_egress", "cgroup_skb/egress", true, BPF_CGROUP_INET_EGRESS},
    {"challenger_ingress", "cgroup_skb/ingress", true, BPF_CGROUP_INET_INGRESS},
};

struct fixed_link {
    struct bpf_link *managed;
    int fd;
};

static int attach_fixed_programs(
    struct bpf_object *object,
    int cgroup_fd,
    struct fixed_link links[],
    size_t maximum_links,
    size_t *link_count)
{
    size_t actual_count = 0;
    struct bpf_program *program = NULL;
    bpf_object__for_each_program(program, object) actual_count++;
    if (actual_count != sizeof(fixed_programs) / sizeof(fixed_programs[0])
        || actual_count > maximum_links)
        return -1;

    for (size_t index = 0; index < actual_count; index++) {
        const struct fixed_program *expected = &fixed_programs[index];
        program = bpf_object__find_program_by_name(object, expected->name);
        if (!program || strcmp(bpf_program__section_name(program), expected->section) != 0)
            return -1;
        if (expected->cgroup) {
            LIBBPF_OPTS(bpf_link_create_opts, options);
            int fd = bpf_link_create(
                bpf_program__fd(program),
                cgroup_fd,
                expected->attach_type,
                &options);
            if (fd < 0) {
                fprintf(stderr, "fixed multi-attach failed for %s\n", expected->name);
                return -1;
            }
            links[*link_count].fd = fd;
        } else {
            struct bpf_link *link = bpf_program__attach(program);
            if (!link || libbpf_get_error(link)) {
                fprintf(stderr, "fixed link attach failed for %s\n", expected->name);
                return -1;
            }
            links[*link_count].managed = link;
            links[*link_count].fd = -1;
        }
        (*link_count)++;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *cgroup_path = DEFAULT_CGROUP;
    if (argc == 3 && strcmp(argv[1], "--cgroup") == 0)
        cgroup_path = argv[2];
    else if (argc != 1) {
        fprintf(stderr, "usage: challenger-siem-ebpf-helper [--cgroup /sys/fs/cgroup]\n");
        return 2;
    }
    if (strcmp(cgroup_path, DEFAULT_CGROUP) != 0) {
        fprintf(stderr, "only the host cgroup v2 root is supported\n");
        return 2;
    }
    int listener = inherited_listener();
    if (listener < 0) {
        fprintf(stderr, "one systemd SOCK_SEQPACKET listener is required\n");
        return 1;
    }
    int listener_flags = fcntl(listener, F_GETFL, 0);
    if (listener_flags < 0 || fcntl(listener, F_SETFL, listener_flags | O_NONBLOCK) != 0) {
        fprintf(stderr, "systemd listener could not be made nonblocking\n");
        return 1;
    }
    uid_t client_uid = 0;
    if (expected_client_uid(&client_uid) != 0) {
        fprintf(stderr, "the dedicated unprivileged agent identity is unavailable\n");
        return 1;
    }
    int cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (cgroup_fd < 0) {
        perror("open cgroup root");
        return 1;
    }
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    const void *object_bytes = _binary_challenger_network_bpf_o_start;
    size_t object_length = (size_t)(_binary_challenger_network_bpf_o_end - _binary_challenger_network_bpf_o_start);
    struct bpf_object *object = bpf_object__open_mem(object_bytes, object_length, NULL);
    if (!object || libbpf_get_error(object)) {
        fprintf(stderr, "embedded BPF object could not be opened\n");
        close(cgroup_fd);
        return 1;
    }
    if (bpf_object__load(object) != 0) {
        fprintf(stderr, "embedded BPF object could not be loaded\n");
        bpf_object__close(object);
        close(cgroup_fd);
        return 1;
    }
    struct fixed_link links[32] = {};
    size_t link_count = 0;
    if (attach_fixed_programs(object, cgroup_fd, links, sizeof(links) / sizeof(links[0]), &link_count) != 0) {
        fprintf(stderr, "the embedded fixed BPF hook catalog could not be validated and attached with multi-attach semantics\n");
        stopping = 1;
    }
    int flow_fd = bpf_object__find_map_fd_by_name(object, "flow_map");
    int health_fd = bpf_object__find_map_fd_by_name(object, "health_counters");
    int ring_fd = bpf_object__find_map_fd_by_name(object, "flow_notices");
    struct ring_buffer *ring = ring_fd >= 0 ? ring_buffer__new(ring_fd, discard_notice, NULL, NULL) : NULL;
    if (stopping || flow_fd < 0 || health_fd < 0 || !ring) {
        fprintf(stderr, "fixed BPF maps or ring buffer are unavailable\n");
        stopping = 1;
    }

    char epoch[33] = {};
    format_epoch(epoch);
    uint64_t sequence = 1;
    while (!stopping) {
        int client = accept_client(listener, client_uid);
        if (client < 0) {
            if (errno == EINTR) continue;
            sleep(1);
            continue;
        }
        if (send_hello(client, epoch, sequence) != 0) {
            close(client);
            continue;
        }
        while (!stopping) {
            for (int tick = 0; tick < 10 && !stopping; tick++) {
                ring_buffer__poll(ring, 0);
                struct pollfd descriptor = { .fd = client, .events = POLLHUP | POLLERR };
                int poll_result = poll(&descriptor, 1, 1000);
                if (poll_result > 0 && descriptor.revents) goto disconnected;
                if (poll_result < 0 && errno != EINTR) goto disconnected;
            }
            if (collect_flows(flow_fd, health_fd) < 0)
                goto disconnected;
            struct timespec now = {};
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
                goto disconnected;
            uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
            if (emit_tracked_flows(client, health_fd, epoch, &sequence, now_ns) < 0)
                goto disconnected;
            if (send_health(client, health_fd, epoch, sequence) < 0)
                goto disconnected;
            sequence++;
        }
disconnected:
        close(client);
    }

    if (ring) ring_buffer__free(ring);
    for (size_t index = link_count; index > 0; index--) {
        struct fixed_link *link = &links[index - 1];
        if (link->managed)
            bpf_link__destroy(link->managed);
        else if (link->fd >= 0)
            close(link->fd);
    }
    bpf_object__close(object);
    close(cgroup_fd);
    return stopping ? 0 : 1;
}
