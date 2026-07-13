begin;

-- Preserve registered platform identity for platform-specific host-coverage evaluation.
alter table agents add column if not exists platform text null;
alter table agents add column if not exists host_id text null;

do $$ begin
    if not exists (select 1 from pg_constraint where conrelid = 'agents'::regclass and conname = 'ck_agents_platform') then
        alter table agents add constraint ck_agents_platform check (platform is null or platform in ('windows', 'linux')) not valid;
    end if;
end $$;
alter table agents validate constraint ck_agents_platform;
create index if not exists idx_agents_platform on agents(platform) where platform is not null;

-- Additive Linux L2 requirement and evidence metadata. Existing Windows rows remain null.
alter table source_health add column if not exists requirement_kind text null;
alter table source_health add column if not exists applicable_roles jsonb null;
alter table source_health add column if not exists prerequisite_statuses jsonb null;
alter table source_health add column if not exists event_family_statuses jsonb null;

alter table source_health drop constraint if exists ck_source_health_status;
alter table source_health add constraint ck_source_health_status check (
    status in ('healthy', 'missing', 'disabled', 'stale', 'degraded', 'permission_denied', 'unsupported', 'error', 'not_applicable', 'excepted')
);

do $$ begin
    if not exists (select 1 from pg_constraint where conrelid = 'source_health'::regclass and conname = 'ck_source_health_requirement') then
        alter table source_health add constraint ck_source_health_requirement check (
            requirement_kind is null or requirement_kind in ('mandatory', 'optional', 'role_specific')
        ) not valid;
    end if;
end $$;
alter table source_health validate constraint ck_source_health_requirement;
create index if not exists idx_source_health_requirement on source_health(requirement_kind) where requirement_kind is not null;
create index if not exists idx_events_package_name on events((normalized_json->>'package_name'))
    where normalized_json ? 'package_name';

commit;
