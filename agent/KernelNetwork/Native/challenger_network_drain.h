#ifndef CHALLENGER_NETWORK_DRAIN_H
#define CHALLENGER_NETWORK_DRAIN_H

#include <stdbool.h>
#include <stdint.h>
#include "challenger_network_shared.h"

struct challenger_kernel_drain_diagnostics {
    uint64_t interval_records;
    uint64_t high_water_interval_records;
    uint64_t capped_ticks;
    uint64_t backlog_ticks;
    bool interval_backlog;
};

static inline uint64_t challenger_saturating_add_u64(uint64_t left, uint64_t right)
{
    return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static inline void challenger_begin_kernel_drain_interval(
    struct challenger_kernel_drain_diagnostics *diagnostics)
{
    diagnostics->interval_records = 0;
    diagnostics->interval_backlog = false;
}

static inline void challenger_record_kernel_drain_tick(
    struct challenger_kernel_drain_diagnostics *diagnostics,
    uint64_t records,
    bool capped,
    bool backlog)
{
    diagnostics->interval_records = challenger_saturating_add_u64(
        diagnostics->interval_records,
        records);
    if (diagnostics->interval_records > diagnostics->high_water_interval_records)
        diagnostics->high_water_interval_records = diagnostics->interval_records;
    if (capped)
        diagnostics->capped_ticks = challenger_saturating_add_u64(diagnostics->capped_ticks, 1);
    if (backlog) {
        diagnostics->backlog_ticks = challenger_saturating_add_u64(diagnostics->backlog_ticks, 1);
        diagnostics->interval_backlog = true;
    }
}

#endif
