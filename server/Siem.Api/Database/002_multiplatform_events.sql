begin;

alter table events drop constraint if exists ck_events_source;
alter table events drop constraint if exists ck_events_windows_event_id;
alter table events alter column channel drop not null;
alter table events alter column provider drop not null;
alter table events alter column windows_event_id drop not null;
alter table events alter column record_id drop not null;

alter table events add column if not exists platform text null;
alter table events add column if not exists source_id text null;
alter table events add column if not exists event_code text null;
alter table events add column if not exists facility text null;
alter table events add column if not exists unit text null;
alter table events add column if not exists checkpoint_json jsonb null;
alter table events add column if not exists deduplication_json jsonb null;
alter table events add column if not exists data_handling_json jsonb null;

do $$ begin
    if not exists (select 1 from pg_constraint where conrelid = 'events'::regclass and conname = 'ck_events_source') then
        alter table events add constraint ck_events_source check (source in ('windows_event_log', 'linux_journal', 'linux_audit', 'inventory_diff', 'agent_health')) not valid;
    end if;
    if not exists (select 1 from pg_constraint where conrelid = 'events'::regclass and conname = 'ck_events_platform') then
        alter table events add constraint ck_events_platform check (platform is null or platform in ('windows', 'linux')) not valid;
    end if;
    if not exists (select 1 from pg_constraint where conrelid = 'events'::regclass and conname = 'ck_events_windows_identity') then
        alter table events add constraint ck_events_windows_identity check (
            (source = 'windows_event_log' and channel is not null and provider is not null and windows_event_id between 0 and 65535 and record_id is not null)
            or
            (source <> 'windows_event_log' and platform is not null and source_id is not null and channel is null and provider is null and windows_event_id is null and record_id is null)
        ) not valid;
    end if;
end $$;
alter table events validate constraint ck_events_source;
alter table events validate constraint ck_events_platform;
alter table events validate constraint ck_events_windows_identity;

create index if not exists idx_events_source_time on events(source, event_time desc);
create index if not exists idx_events_source_id_time on events(source_id, event_time desc) where source_id is not null;
create index if not exists idx_events_event_code_time on events(event_code, event_time desc) where event_code is not null;
create index if not exists idx_events_agent_source_time on events(agent_id, source, event_time desc);

commit;
