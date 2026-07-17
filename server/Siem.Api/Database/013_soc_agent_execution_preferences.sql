-- Additive per-session preference and per-turn execution metadata for allowlisted model controls.

alter table soc_agent_turns add column if not exists reasoning_effort text null;
alter table soc_agent_sessions add column if not exists reasoning_effort text null;
alter table soc_agent_messages add column if not exists reasoning_effort text null;
