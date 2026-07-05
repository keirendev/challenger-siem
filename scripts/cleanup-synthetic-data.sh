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
TABLE_ORDER = [
    "target_agents",
    "alert_evidence",
    "alerts",
    "events",
    "agent_heartbeats",
    "source_health",
    "asset_inventory_snapshots",
    "coverage_exceptions",
    "ingestion_errors",
    "soc_agent_turns",
    "soc_agent_sessions",
    "soc_agent_messages",
    "agents",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Dry-run or delete allowlisted synthetic/test SIEM data without printing secrets or raw telemetry."
    )
    parser.add_argument("--agent-id", action="append", default=[], help="Exact synthetic agent ID to include. May be repeated.")
    parser.add_argument("--agent-prefix", action="append", default=[], help="Tight synthetic agent ID prefix to include. May be repeated.")
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
        parts[key.strip().lower()] = raw.strip()
    return {
        "PGHOST": parts.get("host", "localhost"),
        "PGPORT": parts.get("port", "5432"),
        "PGDATABASE": parts.get("database", ""),
        "PGUSER": parts.get("username") or parts.get("user") or "",
        "PGPASSWORD": parts.get("password", ""),
        "PGCONNECT_TIMEOUT": "10",
    }


def sql_literal(value):
    return "'" + value.replace("'", "''") + "'"


def escape_like_prefix(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_target_where(agent_ids, prefixes):
    clauses = []
    if agent_ids:
        clauses.append("a.agent_id in (" + ", ".join(sql_literal(item) for item in agent_ids) + ")")
    for prefix in prefixes:
        clauses.append("a.agent_id like " + sql_literal(escape_like_prefix(prefix) + "%") + " escape '\\'")
    if not clauses:
        raise SystemExit("No cleanup selectors were provided. Add --agent-id, --agent-prefix, or omit --no-defaults.")
    return " or ".join(clauses)


def build_sql(where_clause, execute):
    finish = "commit;" if execute else "rollback;"
    delete_sql = "" if not execute else """
-- Delete dependent rows first, then target agents. Rows are scoped only through cleanup_target_agents.
delete from alert_evidence
where agent_id in (select agent_id from cleanup_target_agents)
   or alert_id in (select alert_id from alerts where agent_id in (select agent_id from cleanup_target_agents));

delete from alerts
where agent_id in (select agent_id from cleanup_target_agents);

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

delete from soc_agent_turns
where context_agent_id in (select agent_id from cleanup_target_agents);

delete from soc_agent_sessions
where context_agent_id in (select agent_id from cleanup_target_agents);

delete from agents
where agent_id in (select agent_id from cleanup_target_agents);
"""
    return f"""
begin;
create temp table cleanup_target_agents(agent_id text primary key) on commit drop;
insert into cleanup_target_agents(agent_id)
select a.agent_id
from agents a
where {where_clause}
on conflict do nothing;

copy (
    select 0 as sort_order, 'target_agents' as table_name, count(*)::bigint as row_count from cleanup_target_agents
    union all select 1, 'alert_evidence', count(*)::bigint from alert_evidence where agent_id in (select agent_id from cleanup_target_agents) or alert_id in (select alert_id from alerts where agent_id in (select agent_id from cleanup_target_agents))
    union all select 2, 'alerts', count(*)::bigint from alerts where agent_id in (select agent_id from cleanup_target_agents)
    union all select 3, 'events', count(*)::bigint from events where agent_id in (select agent_id from cleanup_target_agents)
    union all select 4, 'agent_heartbeats', count(*)::bigint from agent_heartbeats where agent_id in (select agent_id from cleanup_target_agents)
    union all select 5, 'source_health', count(*)::bigint from source_health where agent_id in (select agent_id from cleanup_target_agents)
    union all select 6, 'asset_inventory_snapshots', count(*)::bigint from asset_inventory_snapshots where agent_id in (select agent_id from cleanup_target_agents)
    union all select 7, 'coverage_exceptions', count(*)::bigint from coverage_exceptions where agent_id in (select agent_id from cleanup_target_agents)
    union all select 8, 'ingestion_errors', count(*)::bigint from ingestion_errors where agent_id in (select agent_id from cleanup_target_agents)
    union all select 9, 'soc_agent_turns', count(*)::bigint from soc_agent_turns where context_agent_id in (select agent_id from cleanup_target_agents)
    union all select 10, 'soc_agent_sessions', count(*)::bigint from soc_agent_sessions where context_agent_id in (select agent_id from cleanup_target_agents)
    union all select 11, 'soc_agent_messages', count(*)::bigint from soc_agent_messages where session_id in (select session_id from soc_agent_sessions where context_agent_id in (select agent_id from cleanup_target_agents))
    union all select 12, 'agents', count(*)::bigint from agents where agent_id in (select agent_id from cleanup_target_agents)
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
    agent_ids = sorted(set(agent_ids))
    prefixes = sorted(set(prefixes))

    where_clause = build_target_where(agent_ids, prefixes)
    sql = build_sql(where_clause, args.execute)
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
    for row in rows:
        table = row.get("table_name", "unknown")
        count = row.get("row_count", "0")
        print(f"{table}={count}")
    if not args.execute:
        print(f"dry_run_only=true")
        print(f"execute_requires=--execute --confirm {CONFIRM_PHRASE}")
    return 0


raise SystemExit(main())
PY
