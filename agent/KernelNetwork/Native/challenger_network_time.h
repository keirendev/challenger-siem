#ifndef CHALLENGER_NETWORK_TIME_H
#define CHALLENGER_NETWORK_TIME_H

#include <stdint.h>

static inline uint64_t challenger_realtime_from_monotonic(
    uint64_t observed_monotonic_ns,
    uint64_t realtime_anchor_ns,
    uint64_t monotonic_anchor_ns)
{
    if (observed_monotonic_ns >= monotonic_anchor_ns)
        return realtime_anchor_ns;
    uint64_t age_ns = monotonic_anchor_ns - observed_monotonic_ns;
    return age_ns > realtime_anchor_ns ? 0 : realtime_anchor_ns - age_ns;
}

#endif
