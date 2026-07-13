create table if not exists operators (
    operator_id uuid primary key,
    username text not null,
    normalized_username text not null unique,
    display_name text not null,
    role text not null,
    password_hash text not null,
    api_token_hash text null unique,
    enabled boolean not null default true,
    failed_login_count integer not null default 0,
    locked_until timestamptz null,
    password_changed_at timestamptz not null default now(),
    credentials_changed_at timestamptz not null default now(),
    last_login_at timestamptz null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint ck_operators_role check (role in ('viewer', 'analyst', 'detection-engineer', 'admin')),
    constraint ck_operators_username check (length(username) between 3 and 64),
    constraint ck_operators_display_name check (length(display_name) between 1 and 128),
    constraint ck_operators_failed_login_count check (failed_login_count >= 0)
);

create table if not exists operator_sessions (
    session_id uuid primary key,
    operator_id uuid not null references operators(operator_id),
    token_hash text not null unique,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    last_seen_at timestamptz not null default now(),
    revoked_at timestamptz null,
    revoke_reason text null,
    constraint ck_operator_sessions_expiry check (expires_at > created_at)
);
create index if not exists idx_operator_sessions_operator on operator_sessions(operator_id, expires_at desc);
create index if not exists idx_operator_sessions_active on operator_sessions(token_hash) where revoked_at is null;

create table if not exists security_audit_events (
    audit_id bigserial primary key,
    occurred_at timestamptz not null default now(),
    operator_id uuid null references operators(operator_id),
    actor_username text null,
    action text not null,
    outcome text not null,
    target_type text null,
    target_id text null,
    request_id text null,
    remote_address_hash text null,
    details jsonb not null default '{}'::jsonb,
    constraint ck_security_audit_action check (length(action) between 1 and 96),
    constraint ck_security_audit_outcome check (outcome in ('success', 'failure', 'denied'))
);
create index if not exists idx_security_audit_occurred on security_audit_events(occurred_at desc);
create index if not exists idx_security_audit_operator on security_audit_events(operator_id, occurred_at desc);

create or replace function reject_security_audit_mutation() returns trigger language plpgsql as $$
begin
    raise exception 'security_audit_events is append-only';
end;
$$;
drop trigger if exists security_audit_events_immutable on security_audit_events;
create trigger security_audit_events_immutable
before update or delete on security_audit_events
for each row execute function reject_security_audit_mutation();
