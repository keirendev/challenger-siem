begin;

create extension if not exists pg_trgm;

create table if not exists saved_event_searches (
    saved_search_id uuid primary key,
    owner_operator_id uuid not null references operators(operator_id) on delete cascade,
    owner_username text not null,
    name text not null,
    description text null,
    visibility text not null default 'private',
    version integer not null default 1,
    query_json jsonb not null,
    columns_json jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_saved_event_searches_name check (length(name) between 1 and 80),
    constraint ck_saved_event_searches_description check (description is null or length(description) <= 500),
    constraint ck_saved_event_searches_visibility check (visibility in ('private', 'shared')),
    constraint ck_saved_event_searches_version check (version >= 1),
    constraint ck_saved_event_searches_query_object check (jsonb_typeof(query_json) = 'object'),
    constraint ck_saved_event_searches_columns_array check (jsonb_typeof(columns_json) = 'array')
);

create index if not exists idx_saved_event_searches_owner on saved_event_searches(owner_operator_id, updated_at desc);
create index if not exists idx_saved_event_searches_shared on saved_event_searches(updated_at desc) where visibility = 'shared';
create unique index if not exists uq_saved_event_searches_owner_name on saved_event_searches(owner_operator_id, lower(name));

create index if not exists idx_events_provider_time on events(provider, event_time desc) where provider is not null;
create index if not exists idx_events_facility_time on events(facility, event_time desc) where facility is not null;
create index if not exists idx_events_unit_time on events(unit, event_time desc) where unit is not null;
create index if not exists idx_events_severity_time on events(severity, event_time desc);
create index if not exists idx_events_outcome_time on events((normalized_json->>'outcome'), event_time desc) where normalized_json ? 'outcome';
create index if not exists idx_events_process_command_line_trgm on events using gin(process_command_line gin_trgm_ops) where process_command_line is not null;
create index if not exists idx_events_file_path_trgm on events using gin(file_path gin_trgm_ops) where file_path is not null;
create index if not exists idx_events_registry_key_trgm on events using gin(registry_key gin_trgm_ops) where registry_key is not null;
create index if not exists idx_events_service_name_time on events(service_name, event_time desc) where service_name is not null;
create index if not exists idx_events_source_ip_time on events(source_ip, event_time desc) where source_ip is not null;
create index if not exists idx_events_destination_ip_time on events(destination_ip, event_time desc) where destination_ip is not null;
create index if not exists idx_events_normalized_json_gin on events using gin(normalized_json jsonb_path_ops) where normalized_json is not null;
create index if not exists idx_alert_evidence_agent_event on alert_evidence(agent_id, event_id);
create index if not exists idx_alerts_rule_id on alerts(rule_id);

commit;
