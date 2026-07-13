-- Additive Linux detection execution metadata and duplicate-safe alert evidence.

alter table detection_rules add column if not exists tactics text[] not null default '{}';
alter table detection_rules add column if not exists correlation_window_seconds integer not null default 0;
alter table detection_rules add column if not exists suppression_keys text[] not null default '{}';
alter table detection_rules add column if not exists false_positive_notes text not null default '';
alter table detection_rules add column if not exists response_guidance text not null default '';

create index if not exists idx_detection_rules_tactics on detection_rules using gin(tactics);

create unique index if not exists uq_alert_evidence_alert_agent_event on alert_evidence(alert_id, agent_id, event_id);

create index if not exists idx_events_linux_auth_correlation
    on events(agent_id, source_id, event_time desc, source_ip, target_user_name)
    where platform = 'linux'
      and event_category = 'authentication'
      and event_action = 'authenticate';

create index if not exists idx_alerts_rule_agent_created on alerts(rule_id, agent_id, created_at desc);
