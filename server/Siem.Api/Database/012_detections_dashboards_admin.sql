-- Additive detection management, saved dashboard layout, and safe administration metadata.

create table if not exists detection_rule_management (
    rule_id text not null,
    version integer not null,
    enabled boolean not null default true,
    lifecycle_state text not null default 'active',
    validation_status text not null default 'synthetic_passed',
    tuning_notes text not null default '',
    suppression_notes text not null default '',
    updated_by text null,
    updated_at timestamptz not null default now(),
    settings_version integer not null default 1,
    primary key (rule_id, version),
    foreign key (rule_id, version) references detection_rules(rule_id, version),
    constraint ck_detection_rule_management_lifecycle check (lifecycle_state in ('catalog', 'draft', 'review', 'test_failed', 'test_passed', 'staged', 'active', 'deprecated', 'disabled')),
    constraint ck_detection_rule_management_validation check (validation_status in ('not_run', 'synthetic_passed', 'synthetic_failed', 'skipped_with_reason')),
    constraint ck_detection_rule_management_version check (settings_version >= 1),
    constraint ck_detection_rule_management_notes check (length(tuning_notes) <= 2000 and length(suppression_notes) <= 2000)
);
create index if not exists idx_detection_rule_management_lifecycle on detection_rule_management(lifecycle_state, updated_at desc);

create table if not exists detection_rule_management_history (
    history_id bigserial primary key,
    rule_id text not null,
    version integer not null,
    changed_at timestamptz not null default now(),
    changed_by text null,
    action text not null,
    previous_settings jsonb null,
    new_settings jsonb not null,
    constraint ck_detection_rule_management_history_action check (length(action) between 1 and 96)
);
create index if not exists idx_detection_rule_management_history_rule on detection_rule_management_history(rule_id, version, changed_at desc);

create table if not exists dashboard_layouts (
    layout_id uuid primary key,
    owner_operator_id uuid not null references operators(operator_id),
    name text not null,
    visibility text not null default 'private',
    time_range_hours integer not null default 24,
    refresh_minutes integer not null default 15,
    layout_json jsonb not null default '{}'::jsonb,
    version integer not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_dashboard_layouts_name check (length(name) between 1 and 96),
    constraint ck_dashboard_layouts_visibility check (visibility in ('private', 'shared')),
    constraint ck_dashboard_layouts_time_range check (time_range_hours between 1 and 168),
    constraint ck_dashboard_layouts_refresh check (refresh_minutes between 1 and 1440),
    constraint ck_dashboard_layouts_version check (version >= 1)
);
create index if not exists idx_dashboard_layouts_owner_updated on dashboard_layouts(owner_operator_id, updated_at desc);
create index if not exists idx_dashboard_layouts_shared_updated on dashboard_layouts(updated_at desc) where visibility = 'shared';

create table if not exists source_review_settings (
    source_id text primary key,
    display_name text not null,
    review_note text not null default '',
    muted_until timestamptz null,
    updated_by text null,
    updated_at timestamptz not null default now(),
    version integer not null default 1,
    constraint ck_source_review_settings_source check (length(source_id) between 1 and 128),
    constraint ck_source_review_settings_note check (length(review_note) <= 1000),
    constraint ck_source_review_settings_version check (version >= 1)
);

create table if not exists server_config_settings (
    setting_key text primary key,
    setting_value text not null,
    updated_by text null,
    updated_at timestamptz not null default now(),
    version integer not null default 1,
    constraint ck_server_config_settings_key check (setting_key in ('retention.target_days', 'retention.managed_capacity_bytes', 'retention.max_batches_per_run')),
    constraint ck_server_config_settings_value check (length(setting_value) between 1 and 64),
    constraint ck_server_config_settings_version check (version >= 1)
);
