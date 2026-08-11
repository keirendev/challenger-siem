#ifndef CHALLENGER_NETWORK_TRACKING_H
#define CHALLENGER_NETWORK_TRACKING_H

#include <stdbool.h>
#include <stdint.h>

enum challenger_flow_event_kind {
    CHALLENGER_FLOW_EVENT_NONE = 0,
    CHALLENGER_FLOW_EVENT_STARTED = 1,
    CHALLENGER_FLOW_EVENT_SAMPLE = 2,
    CHALLENGER_FLOW_EVENT_CLOSED = 3,
};

static inline enum challenger_flow_event_kind challenger_select_flow_event(
    bool started_emitted,
    bool close_requested,
    uint64_t packet_count,
    uint64_t last_seen_ns,
    uint64_t last_emitted_ns,
    uint64_t now_ns,
    uint64_t active_summary_ns)
{
    if (close_requested)
        return CHALLENGER_FLOW_EVENT_CLOSED;
    if (!started_emitted)
        return CHALLENGER_FLOW_EVENT_STARTED;
    if (packet_count > 0
        && now_ns >= last_emitted_ns
        && now_ns - last_emitted_ns >= active_summary_ns)
        return CHALLENGER_FLOW_EVENT_SAMPLE;
    (void)last_seen_ns;
    return CHALLENGER_FLOW_EVENT_NONE;
}

#endif
