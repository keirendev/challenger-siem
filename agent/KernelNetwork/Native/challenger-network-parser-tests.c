#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "challenger_network_drain.h"
#include "challenger_network_parser.h"
#include "challenger_network_time.h"
#include "challenger_network_shared.h"
#include "challenger_network_tracking.h"

static void ipv4_tcp_and_udp(void)
{
    __u8 header[20] = {0x45};
    struct challenger_parsed_ip parsed = {};
    header[9] = 6;
    header[12] = 192; header[13] = 0; header[14] = 2; header[15] = 10;
    header[16] = 198; header[17] = 51; header[18] = 100; header[19] = 20;
    assert(challenger_parse_ipv4(header, &parsed) == CHALLENGER_PARSE_OK);
    assert(parsed.family == 4 && parsed.protocol == 6 && parsed.layer4_offset == 20);
    assert(parsed.source_address[0] == 192 && parsed.destination_address[0] == 198);
    header[9] = 17;
    assert(challenger_parse_ipv4(header, &parsed) == CHALLENGER_PARSE_OK);
    assert(parsed.protocol == 17);
}

static void ipv4_fragments_and_malformed_headers_are_rejected(void)
{
    __u8 header[20] = {0x45};
    struct challenger_parsed_ip parsed = {};
    header[9] = 6;
    header[6] = 0x20;
    assert(challenger_parse_ipv4(header, &parsed) == CHALLENGER_PARSE_UNSUPPORTED);
    header[6] = 0;
    header[0] = 0x44;
    assert(challenger_parse_ipv4(header, &parsed) == CHALLENGER_PARSE_MALFORMED);
}

static void ipv6_tcp_udp_and_extensions(void)
{
    __u8 header[40] = {0x60};
    struct challenger_parsed_ip parsed = {};
    header[6] = 6;
    header[8] = 0x20; header[9] = 0x01; header[24] = 0x20; header[25] = 0x01;
    assert(challenger_parse_ipv6(header, &parsed) == CHALLENGER_PARSE_OK);
    assert(parsed.family == 6 && parsed.protocol == 6 && parsed.layer4_offset == 40);
    header[6] = 17;
    assert(challenger_parse_ipv6(header, &parsed) == CHALLENGER_PARSE_OK);
    header[6] = 44;
    assert(challenger_parse_ipv6(header, &parsed) == CHALLENGER_PARSE_EXTENSION);
    header[6] = 58;
    assert(challenger_parse_ipv6(header, &parsed) == CHALLENGER_PARSE_NOT_TCP_UDP);

    __u8 prefix[8] = {17, 0};
    __u8 next_protocol = 0;
    __u16 header_length = 0;
    assert(challenger_parse_ipv6_extension(0, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_OK);
    assert(next_protocol == 17 && header_length == 8);
    prefix[1] = 1;
    assert(challenger_parse_ipv6_extension(43, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_OK);
    assert(header_length == 16);
    memset(prefix, 0, sizeof(prefix));
    prefix[0] = 6;
    assert(challenger_parse_ipv6_extension(44, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_OK);
    assert(next_protocol == 6 && header_length == 8);
    prefix[3] = 8;
    assert(challenger_parse_ipv6_extension(44, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_UNSUPPORTED);
    assert(challenger_parse_ipv6_extension(50, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_UNSUPPORTED);
    memset(prefix, 0, sizeof(prefix));
    prefix[0] = 6;
    assert(challenger_parse_ipv6_extension(51, prefix, &next_protocol, &header_length) == CHALLENGER_PARSE_OK);
    assert(header_length == 8);
}

static void direction_limits_and_payload_exclusion(void)
{
    struct {
        __u8 header[40];
        char payload_canary[32];
    } packet = {};
    memcpy(packet.payload_canary, "SYNTHETIC_PAYLOAD_MUST_NOT_COPY", 31);
    packet.header[0] = 0x45;
    packet.header[9] = 17;
    packet.header[12] = 192;
    packet.header[16] = 198;
    struct challenger_parsed_ip parsed = {};
    assert(challenger_parse_ipv4(packet.header, &parsed) == CHALLENGER_PARSE_OK);
    __u8 local[16] = {};
    __u8 remote[16] = {};
    challenger_normalize_addresses(&parsed, 1, local, remote);
    assert(local[0] == 192 && remote[0] == 198);
    challenger_normalize_addresses(&parsed, 0, local, remote);
    assert(local[0] == 198 && remote[0] == 192);
    assert(memmem(&parsed, sizeof(parsed), "SYNTHETIC_PAYLOAD_MUST_NOT_COPY", 31) == NULL);
    assert(CHALLENGER_FLOW_MAP_ENTRIES == 262144);
    assert(CHALLENGER_TRACKED_FLOW_ENTRIES == 524288);
    assert(CHALLENGER_OWNER_MAP_ENTRIES == 32768);
    assert(CHALLENGER_RING_BYTES == 32 * 1024 * 1024);
    assert(CHALLENGER_RING_BYTES
        >= CHALLENGER_FLOW_MAP_ENTRIES * ((sizeof(struct challenger_ring_notice) + 15) & ~7));
    assert(CHALLENGER_MAX_KERNEL_DRAIN_RECORDS == 32768);
    assert(CHALLENGER_MAX_OUTPUT_RECORDS == 4096);
    assert(CHALLENGER_MAX_KERNEL_RECORDS_PER_HEALTH_INTERVAL >= CHALLENGER_FLOW_MAP_ENTRIES);
    assert(CHALLENGER_TRACKED_FLOW_ENTRIES >= CHALLENGER_FLOW_MAP_ENTRIES * 2);
    assert(challenger_select_flow_event(false, true, 1, 1, 0, 2, 60) == CHALLENGER_FLOW_EVENT_CLOSED);
    assert(challenger_select_flow_event(false, false, 1, 1, 0, 2, 60) == CHALLENGER_FLOW_EVENT_STARTED);
    assert(challenger_select_flow_event(true, false, 1, 1, 1, 61, 60) == CHALLENGER_FLOW_EVENT_SAMPLE);
    uint64_t pending = 120000;
    int catch_up_intervals = 0;
    while (pending > 0) {
        uint64_t emitted = pending < CHALLENGER_MAX_OUTPUT_RECORDS
            ? pending : CHALLENGER_MAX_OUTPUT_RECORDS;
        pending -= emitted;
        catch_up_intervals++;
    }
    assert(catch_up_intervals == 30);
    assert(catch_up_intervals * CHALLENGER_HEALTH_INTERVAL_SECONDS <= 6 * 60);
}

int main(void)
{
    ipv4_tcp_and_udp();
    ipv4_fragments_and_malformed_headers_are_rejected();
    ipv6_tcp_udp_and_extensions();
    direction_limits_and_payload_exclusion();
    const uint64_t realtime_anchor = 1800000000000000000ULL;
    const uint64_t monotonic_anchor = 500000000000ULL;
    assert(challenger_realtime_from_monotonic(
        monotonic_anchor - 1000, realtime_anchor, monotonic_anchor) == realtime_anchor - 1000);
    assert(challenger_realtime_from_monotonic(
        monotonic_anchor, realtime_anchor, monotonic_anchor) == realtime_anchor);
    assert(challenger_realtime_from_monotonic(
        monotonic_anchor + 1000, realtime_anchor, monotonic_anchor) == realtime_anchor);
    uint64_t equal_observation = monotonic_anchor - 5000;
    uint64_t first_seen = challenger_realtime_from_monotonic(
        equal_observation, realtime_anchor, monotonic_anchor);
    uint64_t last_seen = challenger_realtime_from_monotonic(
        equal_observation, realtime_anchor, monotonic_anchor);
    assert(first_seen == last_seen);

    struct challenger_kernel_drain_diagnostics diagnostics = {};
    challenger_begin_kernel_drain_interval(&diagnostics);
    for (int tick = 0; tick < CHALLENGER_HEALTH_INTERVAL_SECONDS; tick++)
        challenger_record_kernel_drain_tick(&diagnostics, CHALLENGER_MAX_KERNEL_DRAIN_RECORDS, true, tick == 0);
    assert(diagnostics.interval_records == CHALLENGER_MAX_KERNEL_RECORDS_PER_HEALTH_INTERVAL);
    assert(diagnostics.high_water_interval_records == CHALLENGER_MAX_KERNEL_RECORDS_PER_HEALTH_INTERVAL);
    assert(diagnostics.capped_ticks == CHALLENGER_HEALTH_INTERVAL_SECONDS);
    assert(diagnostics.backlog_ticks == 1);
    assert(diagnostics.interval_backlog);
    challenger_begin_kernel_drain_interval(&diagnostics);
    challenger_record_kernel_drain_tick(&diagnostics, 7, false, false);
    assert(diagnostics.interval_records == 7);
    assert(diagnostics.high_water_interval_records == CHALLENGER_MAX_KERNEL_RECORDS_PER_HEALTH_INTERVAL);
    assert(diagnostics.capped_ticks == CHALLENGER_HEALTH_INTERVAL_SECONDS);
    assert(diagnostics.backlog_ticks == 1);
    assert(!diagnostics.interval_backlog);

    puts("native parser tests passed");
    return 0;
}
