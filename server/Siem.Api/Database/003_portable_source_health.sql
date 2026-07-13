-- Additive portable source-health persistence for Linux/native and platform-neutral v1 sources.
alter table source_health alter column channel drop not null;
alter table source_health add column if not exists platform text null;
alter table source_health add column if not exists source_kind text null;
alter table source_health add column if not exists source_namespace text null;
alter table source_health add column if not exists facility text null;
alter table source_health add column if not exists unit text null;
alter table source_health add column if not exists applicability text null;
alter table source_health add column if not exists applicability_reason text null;
alter table source_health add column if not exists collected_checkpoint jsonb null;
alter table source_health add column if not exists acknowledged_checkpoint jsonb null;
create index if not exists idx_source_health_portable_source on source_health(platform, source_kind, source_id);
