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

alter table events add column if not exists event_category text null;
alter table events add column if not exists event_action text null;
alter table events add column if not exists normalized_json jsonb null;
alter table events add column if not exists user_name text null;
alter table events add column if not exists target_user_name text null;
alter table events add column if not exists process_image text null;
alter table events add column if not exists process_command_line text null;
alter table events add column if not exists source_ip text null;
alter table events add column if not exists destination_ip text null;
alter table events add column if not exists service_name text null;
alter table events add column if not exists file_path text null;
alter table events add column if not exists registry_key text null;
create index if not exists idx_events_event_category on events(event_category);
create index if not exists idx_events_event_action on events(event_action);
create index if not exists idx_events_user_name on events(user_name);
create index if not exists idx_events_process_image on events(process_image);
create index if not exists idx_events_destination_ip on events(destination_ip);

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

alter table agent_heartbeats add column if not exists config_hash text null;
alter table agent_heartbeats add column if not exists queue_metrics jsonb null;
alter table agent_heartbeats add column if not exists source_manifest jsonb null;
alter table agent_heartbeats add column if not exists source_health_summary jsonb null;
alter table agent_heartbeats add column if not exists tamper_checks jsonb null;

create table if not exists source_health (
    agent_id text not null references agents(agent_id),
    source_id text not null,
    display_name text not null,
    channel text not null,
    coverage_level text not null,
    status text not null,
    required_source boolean not null default false,
    enabled boolean not null default true,
    last_event_time timestamptz null,
    last_record_id bigint null,
    oldest_record_id bigint null,
    newest_record_id bigint null,
    log_size_bytes bigint null,
    retention_days integer null,
    lag_seconds bigint null,
    error_code text null,
    error_message text null,
    gap_detected boolean not null default false,
    cleared_detected boolean not null default false,
    bookmark_gap_detected boolean not null default false,
    config_hash text null,
    source_version text null,
    details jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now(),
    primary key (agent_id, source_id),
    constraint ck_source_health_status check (status in ('healthy', 'missing', 'disabled', 'stale', 'error', 'not_applicable', 'excepted')),
    constraint ck_source_health_level check (coverage_level in ('L0', 'L1', 'L2', 'L3', 'L4'))
);
create index if not exists idx_source_health_status on source_health(status);
create index if not exists idx_source_health_agent on source_health(agent_id);

create table if not exists coverage_exceptions (
    id bigserial primary key,
    agent_id text null references agents(agent_id),
    hostname text null,
    source_id text not null,
    reason text not null,
    approved_by text not null,
    expires_at timestamptz null,
    created_at timestamptz not null default now()
);
create index if not exists idx_coverage_exceptions_source on coverage_exceptions(source_id);

create table if not exists asset_inventory_snapshots (
    id bigserial primary key,
    agent_id text not null references agents(agent_id),
    hostname text not null,
    snapshot_type text not null,
    collected_at timestamptz not null,
    items jsonb not null,
    summary jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
create index if not exists idx_asset_inventory_agent_type on asset_inventory_snapshots(agent_id, snapshot_type, collected_at desc);

create table if not exists detection_rules (
    rule_id text not null,
    version integer not null,
    name text not null,
    description text not null,
    severity text not null,
    confidence text not null,
    category text not null,
    required_sources text[] not null default '{}',
    required_fields text[] not null default '{}',
    mitre_attack text[] not null default '{}',
    enabled boolean not null default true,
    created_at timestamptz not null default now(),
    primary key (rule_id, version)
);
create index if not exists idx_detection_rules_category on detection_rules(category);

create table if not exists alerts (
    alert_id uuid primary key,
    rule_id text not null,
    rule_version integer not null,
    title text not null,
    severity text not null,
    confidence text not null,
    status text not null default 'new',
    agent_id text null references agents(agent_id),
    hostname text null,
    created_at timestamptz not null default now(),
    summary text not null,
    affected_entities jsonb not null default '[]'::jsonb,
    constraint ck_alert_status check (status in ('new', 'triaged', 'closed', 'suppressed'))
);
create index if not exists idx_alerts_status on alerts(status);
create index if not exists idx_alerts_agent on alerts(agent_id);
create index if not exists idx_alerts_created on alerts(created_at desc);

create table if not exists alert_evidence (
    id bigserial primary key,
    alert_id uuid not null references alerts(alert_id) on delete cascade,
    agent_id text not null,
    event_id uuid not null,
    event_time timestamptz null,
    channel text null,
    windows_event_id integer null,
    summary text not null,
    created_at timestamptz not null default now()
);
create index if not exists idx_alert_evidence_alert on alert_evidence(alert_id);

create table if not exists soc_agent_turns (
    id bigserial primary key,
    created_at timestamptz not null default now(),
    provider text not null,
    model text not null,
    question text not null,
    answer text not null,
    tool_runs jsonb not null default '[]'::jsonb,
    citations jsonb not null default '[]'::jsonb,
    context_agent_id text null,
    context_event_id uuid null
);
create index if not exists idx_soc_agent_turns_created on soc_agent_turns(created_at desc);
create index if not exists idx_soc_agent_turns_context_agent on soc_agent_turns(context_agent_id);

create table if not exists soc_agent_sessions (
    session_id uuid primary key,
    title text not null,
    provider text not null,
    model text not null,
    status text not null default 'open',
    context_agent_id text null,
    context_event_id uuid null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_soc_agent_sessions_status check (status in ('open', 'error', 'closed'))
);
create index if not exists idx_soc_agent_sessions_updated on soc_agent_sessions(updated_at desc);
create index if not exists idx_soc_agent_sessions_context_agent on soc_agent_sessions(context_agent_id);

create table if not exists soc_agent_messages (
    id bigserial primary key,
    session_id uuid not null references soc_agent_sessions(session_id) on delete cascade,
    role text not null,
    content text not null,
    provider text null,
    model text null,
    tool_runs jsonb not null default '[]'::jsonb,
    citations jsonb not null default '[]'::jsonb,
    error_code text null,
    created_at timestamptz not null default now(),
    constraint ck_soc_agent_messages_role check (role in ('operator', 'soc_agent', 'system'))
);
create index if not exists idx_soc_agent_messages_session on soc_agent_messages(session_id, created_at asc, id asc);

create table if not exists investigation_graphs (
    graph_id uuid primary key,
    title text not null,
    description text null,
    status text not null default 'active',
    owner text null,
    tags text[] not null default '{}',
    version integer not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_investigation_graph_status check (status in ('active', 'archived')),
    constraint ck_investigation_graph_title check (length(title) between 1 and 160)
);
create index if not exists idx_investigation_graphs_status_updated on investigation_graphs(status, updated_at desc);
create index if not exists idx_investigation_graphs_tags on investigation_graphs using gin(tags);

create table if not exists investigation_graph_nodes (
    node_id uuid not null,
    graph_id uuid not null references investigation_graphs(graph_id),
    node_type text not null,
    label text not null,
    reference_kind text null,
    reference_id text null,
    link_url text null,
    notes text null,
    metadata jsonb not null default '{}'::jsonb,
    x numeric(10, 2) null,
    y numeric(10, 2) null,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (node_id),
    unique (graph_id, node_id),
    constraint ck_investigation_graph_node_status check (status in ('active', 'archived')),
    constraint ck_investigation_graph_node_label check (length(label) between 1 and 200)
);
create index if not exists idx_investigation_graph_nodes_graph on investigation_graph_nodes(graph_id, status);
create index if not exists idx_investigation_graph_nodes_reference on investigation_graph_nodes(reference_kind, reference_id);

create table if not exists investigation_graph_edges (
    edge_id uuid not null,
    graph_id uuid not null references investigation_graphs(graph_id),
    source_node_id uuid not null,
    target_node_id uuid not null,
    edge_type text not null,
    label text null,
    notes text null,
    metadata jsonb not null default '{}'::jsonb,
    status text not null default 'active',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (edge_id),
    foreign key (graph_id, source_node_id) references investigation_graph_nodes(graph_id, node_id),
    foreign key (graph_id, target_node_id) references investigation_graph_nodes(graph_id, node_id),
    constraint ck_investigation_graph_edge_status check (status in ('active', 'archived'))
);
create index if not exists idx_investigation_graph_edges_graph on investigation_graph_edges(graph_id, status);

create table if not exists investigation_graph_proposals (
    proposal_id uuid primary key,
    graph_id uuid not null references investigation_graphs(graph_id),
    status text not null default 'pending',
    instruction text not null,
    rationale text not null,
    proposed_nodes jsonb not null default '[]'::jsonb,
    proposed_edges jsonb not null default '[]'::jsonb,
    created_by text null,
    approved_by text null,
    created_at timestamptz not null default now(),
    applied_at timestamptz null,
    constraint ck_investigation_graph_proposal_status check (status in ('pending', 'applied', 'rejected'))
);
create index if not exists idx_investigation_graph_proposals_graph on investigation_graph_proposals(graph_id, status, created_at desc);

create table if not exists investigation_graph_audit (
    id bigserial primary key,
    graph_id uuid not null references investigation_graphs(graph_id),
    action text not null,
    actor text null,
    summary text not null,
    created_at timestamptz not null default now()
);
create index if not exists idx_investigation_graph_audit_graph on investigation_graph_audit(graph_id, created_at desc);

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
