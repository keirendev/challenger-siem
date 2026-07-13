create table if not exists managed_retention_runs (
    run_id uuid primary key,
    mode text not null,
    status text not null,
    trigger text not null,
    started_at timestamptz not null,
    completed_at timestamptz null,
    retention_cutoff timestamptz not null,
    rows_removed bigint not null default 0,
    event_rows_removed bigint not null default 0,
    estimated_removed_bytes bigint not null default 0,
    details jsonb not null default '{}'::jsonb,
    constraint ck_managed_retention_runs_mode check (mode in ('dry_run', 'execute')),
    constraint ck_managed_retention_runs_status check (status in ('completed', 'bounded_incomplete', 'disabled', 'lock_not_acquired', 'failed')),
    constraint ck_managed_retention_runs_trigger check (trigger in ('scheduled', 'emergency'))
);

create index if not exists idx_managed_retention_runs_started on managed_retention_runs(started_at desc);
create index if not exists idx_managed_retention_runs_status on managed_retention_runs(status, started_at desc);

create table if not exists managed_retention_removed_events (
    agent_id text not null,
    event_id uuid not null,
    event_time timestamptz not null,
    category text not null,
    removed_at timestamptz not null default now(),
    run_id uuid null,
    primary key (agent_id, event_id)
);

create index if not exists idx_managed_retention_removed_events_time on managed_retention_removed_events(event_time desc);
create index if not exists idx_managed_retention_removed_events_removed on managed_retention_removed_events(removed_at desc);
