create table schema_metadata (
    schema_name text primary key,
    schema_version integer not null,
    created_at timestamptz not null default now()
);
insert into schema_metadata(schema_name, schema_version) values ('challenger-siem-linux', 2);

create table agents (
    agent_id text primary key,
    hostname text not null,
    os_version text not null,
    agent_version text not null,
    platform text not null default 'linux' check (platform = 'linux'),
    host_id text not null,
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    status text not null default 'active' check (status in ('active','disabled')),
    api_token_hash text not null,
    host_timezone jsonb null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table events (
    id bigserial primary key,
    event_id uuid not null,
    agent_id text not null references agents(agent_id),
    hostname text not null,
    source text not null check (source in ('linux_journal','linux_audit','inventory_diff','agent_health')),
    platform text not null default 'linux' check (platform = 'linux'),
    source_id text not null,
    event_code text null,
    facility text null,
    unit text null,
    checkpoint_json jsonb not null,
    deduplication_json jsonb not null,
    data_handling_json jsonb not null,
    event_time timestamptz not null,
    ingest_time timestamptz not null default now(),
    host_timezone jsonb null,
    severity text not null check (severity in ('verbose','information','warning','error','critical','audit_success','audit_failure')),
    message text not null,
    raw_json jsonb not null,
    event_category text null,
    event_action text null,
    normalized_json jsonb null,
    user_name text null,
    target_user_name text null,
    process_image text null,
    process_command_line text null,
    source_ip text null,
    destination_ip text null,
    service_name text null,
    file_path text null,
    registry_key text null,
    unique(agent_id,event_id)
);
create index idx_events_event_time on events(event_time desc);
create index idx_events_agent_source_time on events(agent_id,source,event_time desc);
create index idx_events_source_id_time on events(source_id,event_time desc);
create index idx_events_event_code_time on events(event_code,event_time desc) where event_code is not null;
create index idx_events_normalized_json on events using gin(normalized_json) where normalized_json is not null;
create index idx_events_raw_json on events using gin(raw_json);

create table agent_heartbeats (
    id bigserial primary key,
    agent_id text not null references agents(agent_id),
    heartbeat_time timestamptz not null default now(),
    hostname text not null,
    agent_version text not null,
    os text not null,
    last_event_time timestamptz null,
    queue_depth integer not null check (queue_depth >= 0),
    cpu_percent numeric(6,2) null,
    memory_mb integer null,
    resource_metrics jsonb null,
    config_hash text null,
    queue_metrics jsonb null,
    source_manifest jsonb null,
    source_health_summary jsonb null,
    tamper_checks jsonb null,
    host_timezone jsonb null
);
create index idx_agent_heartbeats_agent_time on agent_heartbeats(agent_id,heartbeat_time desc);

create table source_health (
    agent_id text not null references agents(agent_id),
    source_id text not null,
    display_name text not null,
    platform text not null default 'linux' check (platform = 'linux'),
    source_kind text not null,
    source_namespace text null,
    facility text null,
    unit text null,
    applicability text null,
    applicability_reason text null,
    coverage_level text not null check (coverage_level in ('L0','L1','L2','L3','L4')),
    status text not null check (status in ('healthy','missing','disabled','stale','degraded','permission_denied','unsupported','error','not_applicable','excepted')),
    required_source boolean not null default false,
    enabled boolean not null default true,
    last_event_time timestamptz null,
    observed_at timestamptz null,
    log_size_bytes bigint null,
    retention_days integer null,
    lag_seconds bigint null,
    silence_seconds bigint null,
    event_rate_per_minute numeric(12,3) null,
    error_code text null,
    error_message text null,
    gap_detected boolean not null default false,
    cleared_detected boolean not null default false,
    bookmark_gap_detected boolean not null default false,
    gap_count bigint null,
    permission_denied_since timestamptz null,
    recovered_at timestamptz null,
    transition_state text null,
    transitioned_at timestamptz null,
    dropped_events bigint null,
    poison_events bigint null,
    config_hash text null,
    source_version text null,
    requirement_kind text null,
    applicable_roles jsonb null,
    prerequisite_statuses jsonb null,
    event_family_statuses jsonb null,
    collected_checkpoint jsonb null,
    acknowledged_checkpoint jsonb null,
    details jsonb not null default '{}'::jsonb,
    host_timezone jsonb null,
    updated_at timestamptz not null default now(),
    primary key(agent_id,source_id)
);
create index idx_source_health_status on source_health(status);
create index idx_source_health_source on source_health(source_id);

create table coverage_exceptions (
    id bigserial primary key,
    agent_id text null references agents(agent_id), hostname text null, source_id text not null,
    reason text not null, approved_by text not null, expires_at timestamptz null, created_at timestamptz not null default now()
);

create table asset_inventory_snapshots (
    id bigserial primary key, agent_id text not null references agents(agent_id), hostname text not null,
    snapshot_type text not null, collected_at timestamptz not null, host_timezone jsonb null,
    items jsonb not null, summary jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
create index idx_asset_inventory_agent_type on asset_inventory_snapshots(agent_id,snapshot_type,collected_at desc);

create table detection_rules (
    rule_id text not null, version integer not null, name text not null, description text not null,
    severity text not null, confidence text not null, category text not null,
    required_sources text[] not null default '{}', required_fields text[] not null default '{}', mitre_attack text[] not null default '{}',
    tactics text[] not null default '{}', correlation_window_seconds integer not null default 0,
    suppression_keys text[] not null default '{}', false_positive_notes text not null default '', response_guidance text not null default '',
    enabled boolean not null default true, created_at timestamptz not null default now(), primary key(rule_id,version)
);

create table alerts (
    alert_id uuid primary key, rule_id text not null, rule_version integer not null, title text not null,
    severity text not null, confidence text not null, status text not null default 'new', agent_id text null references agents(agent_id),
    hostname text null, created_at timestamptz not null default now(), summary text not null, affected_entities jsonb not null default '[]'::jsonb,
    owner text null, version integer not null default 1, updated_at timestamptz not null default now(), acknowledged_at timestamptz null,
    triaged_at timestamptz null, suppressed_at timestamptz null, suppressed_until timestamptz null, suppression_reason text null,
    disposition text null, closed_at timestamptz null, closure_summary text null, reopened_at timestamptz null,
    last_activity_at timestamptz not null default now(), last_actor text null, last_action text null
);
create index idx_alerts_status on alerts(status,created_at desc);
create index idx_alerts_rule_agent on alerts(rule_id,agent_id,created_at desc);

create table alert_evidence (
    id bigserial primary key, alert_id uuid not null references alerts(alert_id) on delete cascade,
    agent_id text not null, event_id uuid not null, event_time timestamptz null, host_timezone jsonb null,
    summary text not null, created_at timestamptz not null default now(), unique(alert_id,agent_id,event_id)
);

create table alert_activities (
    activity_id uuid primary key, alert_id uuid not null references alerts(alert_id) on delete cascade,
    occurred_at timestamptz not null default now(), actor text null, action text not null, from_status text null, to_status text null,
    summary text not null, details jsonb not null default '{}'::jsonb, idempotency_key text null
);
create unique index uq_alert_activities_idempotency on alert_activities(alert_id,idempotency_key) where idempotency_key is not null;

create table investigation_graphs (
    graph_id uuid primary key, title text not null, description text null, status text not null default 'active', owner text null,
    tags text[] not null default '{}', version integer not null default 1, created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table investigation_graph_nodes (
    node_id uuid primary key, graph_id uuid not null references investigation_graphs(graph_id), node_type text not null, label text not null,
    reference_kind text null, reference_id text null, link_url text null, notes text null, metadata jsonb not null default '{}'::jsonb,
    x numeric(10,2) null, y numeric(10,2) null, status text not null default 'active', created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique(graph_id,node_id)
);
create table investigation_graph_edges (
    edge_id uuid primary key, graph_id uuid not null references investigation_graphs(graph_id), source_node_id uuid not null, target_node_id uuid not null,
    edge_type text not null, label text null, notes text null, metadata jsonb not null default '{}'::jsonb, status text not null default 'active',
    created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
    foreign key(graph_id,source_node_id) references investigation_graph_nodes(graph_id,node_id),
    foreign key(graph_id,target_node_id) references investigation_graph_nodes(graph_id,node_id)
);
create table investigation_graph_proposals (
    proposal_id uuid primary key, graph_id uuid not null references investigation_graphs(graph_id), status text not null default 'pending',
    instruction text not null, rationale text not null, proposed_nodes jsonb not null default '[]'::jsonb, proposed_edges jsonb not null default '[]'::jsonb,
    created_by text null, approved_by text null, created_at timestamptz not null default now(), applied_at timestamptz null
);
create table investigation_graph_audit (
    id bigserial primary key, graph_id uuid not null references investigation_graphs(graph_id), action text not null, actor text null, summary text not null, created_at timestamptz not null default now()
);

create table cases (
    case_id uuid primary key, case_key text not null unique, title text not null, description text null, owner text null,
    severity text not null default 'medium', priority text not null default 'normal', status text not null default 'open', disposition text null,
    closure_summary text null, closure_criteria text null, coverage_gap_acknowledged boolean not null default false, version integer not null default 1,
    created_at timestamptz not null default now(), updated_at timestamptz not null default now(), closed_at timestamptz null, reopened_at timestamptz null,
    last_activity_at timestamptz not null default now(), idempotency_key text null, last_actor text null, last_action text null
);
create unique index uq_cases_idempotency on cases(idempotency_key) where idempotency_key is not null;
create table case_alerts (case_id uuid not null references cases(case_id) on delete cascade, alert_id uuid not null references alerts(alert_id), relationship text not null default 'primary', created_at timestamptz not null default now(), created_by text null, primary key(case_id,alert_id));
create table case_entities (case_entity_id uuid primary key, case_id uuid not null references cases(case_id) on delete cascade, entity_type text not null, entity_value text not null, relationship text not null default 'related', created_at timestamptz not null default now(), created_by text null);
create table case_graphs (case_id uuid not null references cases(case_id) on delete cascade, graph_id uuid not null references investigation_graphs(graph_id), relationship text not null default 'investigation', created_at timestamptz not null default now(), created_by text null, primary key(case_id,graph_id));
create table case_evidence (case_evidence_id uuid primary key, case_id uuid not null references cases(case_id) on delete cascade, alert_id uuid null references alerts(alert_id), agent_id text not null, event_id uuid not null, event_time timestamptz null, host_timezone jsonb null, evidence_kind text not null default 'event', summary text not null, context jsonb not null default '{}'::jsonb, created_at timestamptz not null default now(), created_by text null, unique(case_id,agent_id,event_id));
create table case_notes (note_id uuid primary key, case_id uuid not null references cases(case_id) on delete cascade, body text not null, created_at timestamptz not null default now(), created_by text null);
create table case_activities (activity_id uuid primary key, case_id uuid not null references cases(case_id) on delete cascade, occurred_at timestamptz not null default now(), actor text null, action text not null, from_status text null, to_status text null, summary text not null, details jsonb not null default '{}'::jsonb, idempotency_key text null);
create unique index uq_case_activities_idempotency on case_activities(case_id,idempotency_key) where idempotency_key is not null;

create table ingestion_errors (id bigserial primary key, agent_id text null, batch_id uuid null, event_id uuid null, error_time timestamptz not null default now(), error_code text not null, error_message text not null, payload jsonb null);
create table security_audit_events (audit_id bigserial primary key, occurred_at timestamptz not null default now(), actor_id uuid null, actor_name text null, action text not null, outcome text not null, target_type text null, target_id text null, request_id text null, remote_address_hash text null, details jsonb not null default '{}'::jsonb);

create table managed_retention_runs (run_id uuid primary key, mode text not null, status text not null, trigger text not null, started_at timestamptz not null, completed_at timestamptz null, retention_cutoff timestamptz not null, rows_removed bigint not null default 0, event_rows_removed bigint not null default 0, estimated_removed_bytes bigint not null default 0, details jsonb not null default '{}'::jsonb);
create table managed_retention_removed_events (agent_id text not null, event_id uuid not null, event_time timestamptz not null, category text not null, removed_at timestamptz not null default now(), run_id uuid null, primary key(agent_id,event_id));

create table saved_event_searches (saved_search_id uuid primary key, owner_username text not null default 'service', name text not null, description text null, visibility text not null default 'shared', version integer not null default 1, query_json jsonb not null, columns_json jsonb not null default '[]'::jsonb, created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create unique index uq_saved_event_searches_name on saved_event_searches(lower(name));

create table detection_rule_management (rule_id text not null, version integer not null, enabled boolean not null default true, lifecycle_state text not null default 'active', validation_status text not null default 'synthetic_passed', tuning_notes text not null default '', suppression_notes text not null default '', updated_by text null, updated_at timestamptz not null default now(), settings_version integer not null default 1, primary key(rule_id,version), foreign key(rule_id,version) references detection_rules(rule_id,version));
create table detection_rule_management_history (history_id bigserial primary key, rule_id text not null, version integer not null, changed_at timestamptz not null default now(), changed_by text null, action text not null, previous_settings jsonb null, new_settings jsonb not null);
create table source_review_settings (source_id text primary key, display_name text not null, review_note text not null default '', muted_until timestamptz null, updated_by text null, updated_at timestamptz not null default now(), version integer not null default 1);
create table server_config_settings (setting_key text primary key, setting_value text not null, updated_by text null, updated_at timestamptz not null default now(), version integer not null default 1);
