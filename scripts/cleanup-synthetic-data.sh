#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env && -z "${ConnectionStrings__SiemDatabase:-}" ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi

: "${ConnectionStrings__SiemDatabase:?ConnectionStrings__SiemDatabase is required}"

python3 - "$@" <<'PY'
import argparse
import csv
import os
import shutil
import subprocess
import sys
from io import StringIO

CONFIRM_PHRASE = "DELETE-SYNTHETIC-DATA"
DEFAULT_AGENT_IDS = ["win11-test-001"]
DEFAULT_PREFIXES = ["web-smoke-"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Dry-run or delete allowlisted synthetic/test SIEM data without printing secrets, chat text, or raw telemetry. Immutable alert evidence is preserved."
    )
    parser.add_argument("--agent-id", action="append", default=[], help="Exact synthetic agent ID to include. May be repeated.")
    parser.add_argument("--agent-prefix", action="append", default=[], help="Tight synthetic agent ID prefix to include. May be repeated.")
    parser.add_argument("--soc-agent-session-id", action="append", default=[], help="Exact synthetic soc-agent session UUID to include. May be repeated.")
    parser.add_argument("--soc-agent-title-prefix", action="append", default=[], help="Synthetic soc-agent session title prefix to include. May be repeated.")
    parser.add_argument("--soc-agent-turn-id", action="append", default=[], help="Exact synthetic one-shot soc-agent turn numeric ID to include. May be repeated.")
    parser.add_argument("--graph-id", action="append", default=[], help="Exact synthetic investigation graph UUID to include. May be repeated.")
    parser.add_argument("--graph-title-prefix", action="append", default=[], help="Synthetic investigation graph title prefix to include. May be repeated.")
    parser.add_argument("--no-defaults", action="store_true", help="Do not include the built-in win11-test-001 and web-smoke-* selectors.")
    parser.add_argument("--execute", action="store_true", help="Delete matching records. Without this flag, the script only reports counts and rolls back.")
    parser.add_argument("--confirm", default="", help=f"Required confirmation phrase for --execute: {CONFIRM_PHRASE}")
    return parser.parse_args()


def parse_dotnet_connection_string(value):
    parts = {}
    for item in value.split(";"):
        if not item.strip() or "=" not in item:
            continue
        key, raw = item.split("=", 1)
        parts[key.strip().lower().replace(" ", "")] = raw.strip()
    env = {
        "PGHOST": parts.get("host") or parts.get("server") or "localhost",
        "PGPORT": parts.get("port", "5432"),
        "PGDATABASE": parts.get("database") or parts.get("dbname") or "",
        "PGUSER": parts.get("username") or parts.get("userid") or parts.get("user") or "",
        "PGPASSWORD": parts.get("password") or parts.get("pwd") or "",
        "PGCONNECT_TIMEOUT": "10",
    }
    search_path = parts.get("searchpath") or parts.get("search_path")
    if search_path:
        env["PGOPTIONS"] = f"-c search_path={search_path}"
    return env


def sql_literal(value):
    return "'" + value.replace("'", "''") + "'"


def int_literal(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"Invalid --soc-agent-turn-id value: {value!r}") from exc
    if parsed < 1:
        raise SystemExit("--soc-agent-turn-id values must be positive integers.")
    return str(parsed)


def escape_like_prefix(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def like_clause(column, prefix):
    return f"{column} like {sql_literal(escape_like_prefix(prefix) + '%')} escape '\\'"


def in_text_clause(column, values):
    return f"{column} in (" + ", ".join(sql_literal(item) for item in values) + ")"


def in_int_clause(column, values):
    return f"{column} in (" + ", ".join(int_literal(item) for item in values) + ")"


def build_agent_where(agent_ids, prefixes):
    clauses = []
    if agent_ids:
        clauses.append(in_text_clause("a.agent_id", agent_ids))
    clauses.extend(like_clause("a.agent_id", prefix) for prefix in prefixes)
    return " or ".join(clauses) if clauses else "false"


def build_session_where(session_ids, title_prefixes):
    clauses = ["s.context_agent_id in (select agent_id from cleanup_target_agents)"]
    if session_ids:
        clauses.append(in_text_clause("s.session_id::text", session_ids))
    clauses.extend(like_clause("s.title", prefix) for prefix in title_prefixes)
    return " or ".join(clauses)


def build_turn_where(turn_ids):
    clauses = ["t.context_agent_id in (select agent_id from cleanup_target_agents)"]
    if turn_ids:
        clauses.append(in_int_clause("t.id", turn_ids))
    return " or ".join(clauses)


def build_graph_where(graph_ids, title_prefixes):
    clauses = [
        "exists (select 1 from investigation_graph_nodes n where n.graph_id = g.graph_id and n.reference_kind = 'agent' and n.reference_id in (select agent_id from cleanup_target_agents))",
        "exists (select 1 from investigation_graph_nodes n where n.graph_id = g.graph_id and n.reference_kind = 'event' and n.reference_id in (select event_id::text from events where agent_id in (select agent_id from cleanup_target_agents)))",
        "exists (select 1 from investigation_graph_nodes n where n.graph_id = g.graph_id and n.reference_kind = 'alert' and n.reference_id in (select alert_id::text from alerts where agent_id in (select agent_id from cleanup_target_agents)))",
    ]
    if graph_ids:
        clauses.append(in_text_clause("g.graph_id::text", graph_ids))
    clauses.extend(like_clause("g.title", prefix) for prefix in title_prefixes)
    return " or ".join(clauses)


def build_sql(agent_where, session_where, turn_where, graph_where, execute):
    finish = "commit;" if execute else "rollback;"
    delete_sql = "" if not execute else """
-- Delete dependent rows first, then target agents. Rows are scoped only through cleanup target tables.
delete from investigation_graph_proposals
where graph_id in (select graph_id from cleanup_target_graphs);

delete from investigation_graph_audit
where graph_id in (select graph_id from cleanup_target_graphs);

delete from investigation_graph_edges
where graph_id in (select graph_id from cleanup_target_graphs);

delete from investigation_graph_nodes
where graph_id in (select graph_id from cleanup_target_graphs);

delete from investigation_graphs
where graph_id in (select graph_id from cleanup_target_graphs);

delete from events
where agent_id in (select agent_id from cleanup_target_agents);

delete from agent_heartbeats
where agent_id in (select agent_id from cleanup_target_agents);

delete from source_health
where agent_id in (select agent_id from cleanup_target_agents);

delete from asset_inventory_snapshots
where agent_id in (select agent_id from cleanup_target_agents);

delete from coverage_exceptions
where agent_id in (select agent_id from cleanup_target_agents);

delete from ingestion_errors
where agent_id in (select agent_id from cleanup_target_agents);

delete from soc_agent_messages
where session_id in (select session_id from cleanup_target_soc_sessions);

delete from soc_agent_sessions
where session_id in (select session_id from cleanup_target_soc_sessions);

delete from soc_agent_turns
where id in (select id from cleanup_target_soc_turns);

-- Alert evidence is append-only. Preserve alerts/evidence and retain their agent
-- identity as a disabled registration instead of bypassing immutable-history guards.
update agents a
set status = 'disabled', updated_at = now()
where a.agent_id in (select agent_id from cleanup_target_agents)
  and exists (select 1 from alerts protected where protected.agent_id = a.agent_id);

delete from agents a
where a.agent_id in (select agent_id from cleanup_target_agents)
  and not exists (select 1 from alerts protected where protected.agent_id = a.agent_id);
"""
    return f"""
begin;
create temp table cleanup_target_agents(agent_id text primary key) on commit drop;
create temp table cleanup_target_soc_sessions(session_id uuid primary key) on commit drop;
create temp table cleanup_target_soc_turns(id bigint primary key) on commit drop;
create temp table cleanup_target_graphs(graph_id uuid primary key) on commit drop;

insert into cleanup_target_agents(agent_id)
select a.agent_id
from agents a
where {agent_where}
on conflict do nothing;

insert into cleanup_target_soc_sessions(session_id)
select s.session_id
from soc_agent_sessions s
where {session_where}
on conflict do nothing;

insert into cleanup_target_soc_turns(id)
select t.id
from soc_agent_turns t
where {turn_where}
on conflict do nothing;

insert into cleanup_target_graphs(graph_id)
select g.graph_id
from investigation_graphs g
where {graph_where}
on conflict do nothing;

copy (
    select 0 as sort_order, 'target_agents' as table_name, count(*)::bigint as row_count from cleanup_target_agents
    union all select 1, 'target_soc_agent_sessions', count(*)::bigint from cleanup_target_soc_sessions
    union all select 2, 'target_soc_agent_turns', count(*)::bigint from cleanup_target_soc_turns
    union all select 3, 'target_investigation_graphs', count(*)::bigint from cleanup_target_graphs
    union all select 4, 'investigation_graph_proposals', count(*)::bigint from investigation_graph_proposals where graph_id in (select graph_id from cleanup_target_graphs)
    union all select 5, 'investigation_graph_audit', count(*)::bigint from investigation_graph_audit where graph_id in (select graph_id from cleanup_target_graphs)
    union all select 6, 'investigation_graph_edges', count(*)::bigint from investigation_graph_edges where graph_id in (select graph_id from cleanup_target_graphs)
    union all select 7, 'investigation_graph_nodes', count(*)::bigint from investigation_graph_nodes where graph_id in (select graph_id from cleanup_target_graphs)
    union all select 8, 'investigation_graphs', count(*)::bigint from investigation_graphs where graph_id in (select graph_id from cleanup_target_graphs)
    union all select 9, 'protected_alert_evidence', count(*)::bigint from alert_evidence where agent_id in (select agent_id from cleanup_target_agents) or alert_id in (select alert_id from alerts where agent_id in (select agent_id from cleanup_target_agents))
    union all select 10, 'protected_alerts', count(*)::bigint from alerts where agent_id in (select agent_id from cleanup_target_agents)
    union all select 11, 'events', count(*)::bigint from events where agent_id in (select agent_id from cleanup_target_agents)
    union all select 12, 'agent_heartbeats', count(*)::bigint from agent_heartbeats where agent_id in (select agent_id from cleanup_target_agents)
    union all select 13, 'source_health', count(*)::bigint from source_health where agent_id in (select agent_id from cleanup_target_agents)
    union all select 14, 'asset_inventory_snapshots', count(*)::bigint from asset_inventory_snapshots where agent_id in (select agent_id from cleanup_target_agents)
    union all select 15, 'coverage_exceptions', count(*)::bigint from coverage_exceptions where agent_id in (select agent_id from cleanup_target_agents)
    union all select 16, 'ingestion_errors', count(*)::bigint from ingestion_errors where agent_id in (select agent_id from cleanup_target_agents)
    union all select 17, 'soc_agent_messages', count(*)::bigint from soc_agent_messages where session_id in (select session_id from cleanup_target_soc_sessions)
    union all select 18, 'soc_agent_sessions', count(*)::bigint from soc_agent_sessions where session_id in (select session_id from cleanup_target_soc_sessions)
    union all select 19, 'soc_agent_turns', count(*)::bigint from soc_agent_turns where id in (select id from cleanup_target_soc_turns)
    union all select 20, 'agents', count(*)::bigint from agents where agent_id in (select agent_id from cleanup_target_agents)
    union all select 21, 'agents_retained_for_alerts', count(*)::bigint from agents a where a.agent_id in (select agent_id from cleanup_target_agents) and exists (select 1 from alerts protected where protected.agent_id = a.agent_id)
    order by sort_order
) to stdout with csv header;

{delete_sql}
{finish}
"""


def main():
    args = parse_args()
    if args.execute and args.confirm != CONFIRM_PHRASE:
        raise SystemExit(f"--execute requires --confirm {CONFIRM_PHRASE!r}.")

    if shutil.which("psql") is None:
        raise SystemExit("psql was not found on PATH; install PostgreSQL client tools or run this script where psql is available.")

    agent_ids = [] if args.no_defaults else list(DEFAULT_AGENT_IDS)
    prefixes = [] if args.no_defaults else list(DEFAULT_PREFIXES)
    agent_ids.extend(item.strip() for item in args.agent_id if item.strip())
    prefixes.extend(item.strip() for item in args.agent_prefix if item.strip())
    session_ids = [item.strip() for item in args.soc_agent_session_id if item.strip()]
    session_title_prefixes = [item.strip() for item in args.soc_agent_title_prefix if item.strip()]
    turn_ids = [item.strip() for item in args.soc_agent_turn_id if item.strip()]
    graph_ids = [item.strip() for item in args.graph_id if item.strip()]
    graph_title_prefixes = [item.strip() for item in args.graph_title_prefix if item.strip()]

    agent_ids = sorted(set(agent_ids))
    prefixes = sorted(set(prefixes))
    session_ids = sorted(set(session_ids))
    session_title_prefixes = sorted(set(session_title_prefixes))
    turn_ids = sorted(set(turn_ids), key=int) if turn_ids else []
    graph_ids = sorted(set(graph_ids))
    graph_title_prefixes = sorted(set(graph_title_prefixes))

    if not any([agent_ids, prefixes, session_ids, session_title_prefixes, turn_ids, graph_ids, graph_title_prefixes]):
        raise SystemExit("No cleanup selectors were provided. Add an exact/prefix selector or omit --no-defaults.")

    agent_where = build_agent_where(agent_ids, prefixes)
    session_where = build_session_where(session_ids, session_title_prefixes)
    turn_where = build_turn_where(turn_ids)
    graph_where = build_graph_where(graph_ids, graph_title_prefixes)
    sql = build_sql(agent_where, session_where, turn_where, graph_where, args.execute)
    env = os.environ.copy()
    env.update(parse_dotnet_connection_string(os.environ["ConnectionStrings__SiemDatabase"]))

    result = subprocess.run(
        ["psql", "-v", "ON_ERROR_STOP=1", "-q"],
        input=sql,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write("Synthetic cleanup failed. psql reported an error without printing connection secrets.\n")
        sys.stderr.write(result.stderr)
        return result.returncode

    rows = list(csv.DictReader(StringIO(result.stdout)))
    mode = "execute" if args.execute else "dry-run"
    print(f"mode={mode}")
    print(f"selectors_exact={len(agent_ids)}")
    print(f"selectors_prefix={len(prefixes)}")
    print(f"selectors_soc_agent_session_exact={len(session_ids)}")
    print(f"selectors_soc_agent_title_prefix={len(session_title_prefixes)}")
    print(f"selectors_soc_agent_turn_exact={len(turn_ids)}")
    print(f"selectors_graph_exact={len(graph_ids)}")
    print(f"selectors_graph_title_prefix={len(graph_title_prefixes)}")
    for row in rows:
        table = row.get("table_name", "unknown")
        count = row.get("row_count", "0")
        print(f"{table}={count}")
    print("append_only_alert_records_preserved=true")
    if not args.execute:
        print("dry_run_only=true")
        print(f"execute_requires=--execute --confirm {CONFIRM_PHRASE}")
    return 0


raise SystemExit(main())
PY
