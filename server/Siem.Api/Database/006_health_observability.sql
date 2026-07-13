begin;

-- Additive bounded health/observability state. Existing Windows rows remain valid and null where agents do not report newer metrics.
alter table agent_heartbeats add column if not exists resource_metrics jsonb null;

alter table source_health add column if not exists observed_at timestamptz null;
alter table source_health add column if not exists silence_seconds bigint null;
alter table source_health add column if not exists event_rate_per_minute numeric(12,3) null;
alter table source_health add column if not exists gap_count bigint null;
alter table source_health add column if not exists permission_denied_since timestamptz null;
alter table source_health add column if not exists recovered_at timestamptz null;
alter table source_health add column if not exists transition_state text null;
alter table source_health add column if not exists transitioned_at timestamptz null;
alter table source_health add column if not exists dropped_events bigint null;
alter table source_health add column if not exists poison_events bigint null;

do $$ begin
    if not exists (select 1 from pg_constraint where conrelid = 'source_health'::regclass and conname = 'ck_source_health_observability_nonnegative') then
        alter table source_health add constraint ck_source_health_observability_nonnegative check (
            (lag_seconds is null or lag_seconds >= 0) and
            (silence_seconds is null or silence_seconds >= 0) and
            (event_rate_per_minute is null or (event_rate_per_minute >= 0 and event_rate_per_minute <= 1000000)) and
            (gap_count is null or gap_count >= 0) and
            (dropped_events is null or dropped_events >= 0) and
            (poison_events is null or poison_events >= 0)
        ) not valid;
    end if;
end $$;
alter table source_health validate constraint ck_source_health_observability_nonnegative;

do $$ begin
    if not exists (select 1 from pg_constraint where conrelid = 'source_health'::regclass and conname = 'ck_source_health_transition_state') then
        alter table source_health add constraint ck_source_health_transition_state check (
            transition_state is null or transition_state in ('unknown', 'healthy', 'degraded', 'recovering', 'recovered')
        ) not valid;
    end if;
end $$;
alter table source_health validate constraint ck_source_health_transition_state;

create index if not exists idx_source_health_transition_state on source_health(transition_state) where transition_state is not null;
create index if not exists idx_source_health_observed_at on source_health(observed_at desc) where observed_at is not null;

commit;
