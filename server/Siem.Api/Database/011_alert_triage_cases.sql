-- Additive alert triage and case-management schema for mature analyst lifecycle workflows.

alter table alerts add column if not exists owner text null;
alter table alerts add column if not exists version integer not null default 1;
alter table alerts add column if not exists updated_at timestamptz not null default now();
alter table alerts add column if not exists acknowledged_at timestamptz null;
alter table alerts add column if not exists triaged_at timestamptz null;
alter table alerts add column if not exists suppressed_at timestamptz null;
alter table alerts add column if not exists suppressed_until timestamptz null;
alter table alerts add column if not exists suppression_reason text null;
alter table alerts add column if not exists disposition text null;
alter table alerts add column if not exists closed_at timestamptz null;
alter table alerts add column if not exists closure_summary text null;
alter table alerts add column if not exists reopened_at timestamptz null;
alter table alerts add column if not exists last_activity_at timestamptz not null default now();
alter table alerts add column if not exists last_actor text null;
alter table alerts add column if not exists last_action text null;

alter table alerts drop constraint if exists ck_alert_status;
alter table alerts add constraint ck_alert_status check (status in ('new', 'acknowledged', 'triaged', 'investigating', 'escalated', 'contained', 'resolved', 'closed', 'suppressed'));

do $$
begin
    if not exists (select 1 from pg_constraint where conname = 'ck_alert_owner_length') then
        alter table alerts add constraint ck_alert_owner_length check (owner is null or length(owner) between 1 and 96);
    end if;
    if not exists (select 1 from pg_constraint where conname = 'ck_alert_disposition') then
        alter table alerts add constraint ck_alert_disposition check (disposition is null or disposition in ('true_positive', 'false_positive', 'duplicate', 'benign', 'authorized_activity', 'retention_limited', 'unknown'));
    end if;
    if not exists (select 1 from pg_constraint where conname = 'ck_alert_suppression_reason_length') then
        alter table alerts add constraint ck_alert_suppression_reason_length check (suppression_reason is null or length(suppression_reason) between 8 and 1000);
    end if;
    if not exists (select 1 from pg_constraint where conname = 'ck_alert_closure_summary_length') then
        alter table alerts add constraint ck_alert_closure_summary_length check (closure_summary is null or length(closure_summary) between 8 and 2000);
    end if;
end $$;

create index if not exists idx_alerts_owner_status on alerts(owner, status, updated_at desc);
create index if not exists idx_alerts_last_activity on alerts(last_activity_at desc);

create table if not exists alert_activities (
    activity_id uuid primary key,
    alert_id uuid not null references alerts(alert_id) on delete cascade,
    occurred_at timestamptz not null default now(),
    actor text null,
    action text not null,
    from_status text null,
    to_status text null,
    summary text not null,
    details jsonb not null default '{}'::jsonb,
    idempotency_key text null,
    constraint ck_alert_activity_action check (length(action) between 1 and 96),
    constraint ck_alert_activity_summary check (length(summary) between 1 and 1000),
    constraint ck_alert_activity_idempotency check (idempotency_key is null or length(idempotency_key) between 8 and 128)
);
create index if not exists idx_alert_activities_alert on alert_activities(alert_id, occurred_at desc);
create unique index if not exists uq_alert_activities_idempotency on alert_activities(alert_id, idempotency_key) where idempotency_key is not null;

create table if not exists cases (
    case_id uuid primary key,
    case_key text not null unique,
    title text not null,
    description text null,
    owner text null,
    severity text not null default 'medium',
    priority text not null default 'normal',
    status text not null default 'open',
    disposition text null,
    closure_summary text null,
    closure_criteria text null,
    coverage_gap_acknowledged boolean not null default false,
    version integer not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    closed_at timestamptz null,
    reopened_at timestamptz null,
    last_activity_at timestamptz not null default now(),
    idempotency_key text null,
    last_actor text null,
    last_action text null,
    constraint ck_cases_title check (length(title) between 1 and 160),
    constraint ck_cases_description check (description is null or length(description) <= 4000),
    constraint ck_cases_owner check (owner is null or length(owner) between 1 and 96),
    constraint ck_cases_severity check (severity in ('informational', 'low', 'medium', 'high', 'critical')),
    constraint ck_cases_priority check (priority in ('low', 'normal', 'high', 'urgent')),
    constraint ck_cases_status check (status in ('draft', 'open', 'investigating', 'pending_external', 'contained', 'resolved', 'closed')),
    constraint ck_cases_disposition check (disposition is null or disposition in ('true_positive', 'false_positive', 'duplicate', 'benign', 'authorized_activity', 'retention_limited', 'unknown')),
    constraint ck_cases_closure_summary check (closure_summary is null or length(closure_summary) between 8 and 4000),
    constraint ck_cases_closure_criteria check (closure_criteria is null or length(closure_criteria) <= 4000)
);
create index if not exists idx_cases_status_updated on cases(status, updated_at desc);
create index if not exists idx_cases_owner_status on cases(owner, status, updated_at desc);
alter table cases add column if not exists idempotency_key text null;
create unique index if not exists uq_cases_idempotency_key on cases(idempotency_key) where idempotency_key is not null;
create index if not exists idx_cases_last_activity on cases(last_activity_at desc);

create table if not exists case_alerts (
    case_id uuid not null references cases(case_id) on delete cascade,
    alert_id uuid not null references alerts(alert_id) on delete restrict,
    relationship text not null default 'primary',
    created_at timestamptz not null default now(),
    created_by text null,
    primary key (case_id, alert_id),
    constraint ck_case_alert_relationship check (relationship in ('primary', 'related', 'duplicate_of', 'derived_from'))
);
create index if not exists idx_case_alerts_alert on case_alerts(alert_id, created_at desc);

create table if not exists case_entities (
    case_entity_id uuid primary key,
    case_id uuid not null references cases(case_id) on delete cascade,
    entity_type text not null,
    entity_value text not null,
    relationship text not null default 'related',
    created_at timestamptz not null default now(),
    created_by text null,
    constraint ck_case_entity_type check (length(entity_type) between 1 and 64),
    constraint ck_case_entity_value check (length(entity_value) between 1 and 512),
    constraint ck_case_entity_relationship check (length(relationship) between 1 and 64)
);
create index if not exists idx_case_entities_case on case_entities(case_id, created_at desc);

create table if not exists case_graphs (
    case_id uuid not null references cases(case_id) on delete cascade,
    graph_id uuid not null references investigation_graphs(graph_id) on delete restrict,
    relationship text not null default 'investigation',
    created_at timestamptz not null default now(),
    created_by text null,
    primary key (case_id, graph_id),
    constraint ck_case_graph_relationship check (length(relationship) between 1 and 64)
);
create index if not exists idx_case_graphs_graph on case_graphs(graph_id, created_at desc);

create table if not exists case_evidence (
    case_evidence_id uuid primary key,
    case_id uuid not null references cases(case_id) on delete cascade,
    alert_id uuid null references alerts(alert_id) on delete set null,
    agent_id text not null,
    event_id uuid not null,
    event_time timestamptz null,
    host_timezone jsonb null,
    evidence_kind text not null default 'event',
    summary text not null,
    context jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    created_by text null,
    constraint ck_case_evidence_kind check (evidence_kind in ('event', 'alert_evidence', 'external_reference')),
    constraint ck_case_evidence_summary check (length(summary) between 1 and 1000)
);
create index if not exists idx_case_evidence_case on case_evidence(case_id, created_at desc);
create index if not exists idx_case_evidence_event on case_evidence(agent_id, event_id);
create unique index if not exists uq_case_evidence_case_agent_event on case_evidence(case_id, agent_id, event_id);

create table if not exists case_notes (
    note_id uuid primary key,
    case_id uuid not null references cases(case_id) on delete cascade,
    body text not null,
    created_at timestamptz not null default now(),
    created_by text null,
    constraint ck_case_note_body check (length(body) between 1 and 4000)
);
create index if not exists idx_case_notes_case on case_notes(case_id, created_at desc);

create table if not exists case_activities (
    activity_id uuid primary key,
    case_id uuid not null references cases(case_id) on delete cascade,
    occurred_at timestamptz not null default now(),
    actor text null,
    action text not null,
    from_status text null,
    to_status text null,
    summary text not null,
    details jsonb not null default '{}'::jsonb,
    idempotency_key text null,
    constraint ck_case_activity_action check (length(action) between 1 and 96),
    constraint ck_case_activity_summary check (length(summary) between 1 and 1000),
    constraint ck_case_activity_idempotency check (idempotency_key is null or length(idempotency_key) between 8 and 128)
);
create index if not exists idx_case_activities_case on case_activities(case_id, occurred_at desc);
create unique index if not exists uq_case_activities_idempotency on case_activities(case_id, idempotency_key) where idempotency_key is not null;

create or replace function reject_case_activity_mutation() returns trigger language plpgsql as $$
begin
    raise exception 'case and alert activity records are append-only';
end;
$$;
drop trigger if exists alert_activities_immutable on alert_activities;
create trigger alert_activities_immutable before update or delete on alert_activities for each row execute function reject_case_activity_mutation();
drop trigger if exists case_activities_immutable on case_activities;
create trigger case_activities_immutable before update or delete on case_activities for each row execute function reject_case_activity_mutation();
drop trigger if exists case_notes_immutable on case_notes;
create trigger case_notes_immutable before update or delete on case_notes for each row execute function reject_case_activity_mutation();
drop trigger if exists alert_evidence_immutable on alert_evidence;
create trigger alert_evidence_immutable before update or delete on alert_evidence for each row execute function reject_case_activity_mutation();
drop trigger if exists case_evidence_immutable on case_evidence;
create trigger case_evidence_immutable before update or delete on case_evidence for each row execute function reject_case_activity_mutation();
