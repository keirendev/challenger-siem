create table if not exists agents (
    agent_id text primary key,
    hostname text not null,
    machine_guid text null,
    os_version text not null,
    agent_version text not null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    status text not null default 'active',
    api_token_hash text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_agents_agent_id_length check (length(agent_id) between 1 and 128),
    constraint ck_agents_status check (status in ('active', 'disabled'))
);

create table if not exists events (
    id bigserial primary key,
    event_id uuid not null,
    agent_id text not null references agents(agent_id),
    hostname text not null,
    source text not null,
    channel text not null,
    provider text not null,
    windows_event_id integer not null,
    record_id bigint not null,
    event_time timestamptz not null,
    ingest_time timestamptz not null default now(),
    severity text not null,
    message text not null,
    raw_json jsonb not null,
    constraint uq_events_agent_event unique (agent_id, event_id),
    constraint ck_events_windows_event_id check (windows_event_id >= 0 and windows_event_id <= 65535),
    constraint ck_events_source check (source = 'windows_event_log'),
    constraint ck_events_severity check (severity in ('verbose', 'information', 'warning', 'error', 'critical', 'audit_success', 'audit_failure'))
);

create index if not exists idx_events_agent_id on events(agent_id);
create index if not exists idx_events_hostname on events(hostname);
create index if not exists idx_events_event_time on events(event_time desc);
create index if not exists idx_events_windows_event_id on events(windows_event_id);
create index if not exists idx_events_channel on events(channel);
create index if not exists idx_events_provider on events(provider);
create index if not exists idx_events_raw_json on events using gin(raw_json);

create table if not exists agent_heartbeats (
    id bigserial primary key,
    agent_id text not null references agents(agent_id),
    heartbeat_time timestamptz not null default now(),
    hostname text not null,
    agent_version text not null,
    os text not null,
    last_event_time timestamptz null,
    queue_depth integer not null,
    cpu_percent numeric(6, 2) null,
    memory_mb integer null,
    constraint ck_heartbeats_queue_depth check (queue_depth >= 0),
    constraint ck_heartbeats_cpu_percent check (cpu_percent is null or cpu_percent >= 0),
    constraint ck_heartbeats_memory_mb check (memory_mb is null or memory_mb >= 0)
);

create index if not exists idx_agent_heartbeats_agent_id on agent_heartbeats(agent_id);
create index if not exists idx_agent_heartbeats_time on agent_heartbeats(heartbeat_time desc);

create table if not exists ingestion_errors (
    id bigserial primary key,
    agent_id text null,
    batch_id uuid null,
    event_id uuid null,
    error_time timestamptz not null default now(),
    error_code text not null,
    error_message text not null,
    payload jsonb null
);

create index if not exists idx_ingestion_errors_agent_id on ingestion_errors(agent_id);
create index if not exists idx_ingestion_errors_time on ingestion_errors(error_time desc);
