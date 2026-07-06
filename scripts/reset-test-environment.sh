#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .local/dev.env && -z "${ConnectionStrings__SiemDatabase:-}" && -z "${CHALLENGER_SIEM_DATABASE:-}" ]]; then
  # shellcheck disable=SC1091
  source .local/dev.env
fi
if [[ -n "${ConnectionStrings__SiemDatabase:-}" ]]; then
  export ConnectionStrings__SiemDatabase
fi
if [[ -n "${CHALLENGER_SIEM_DATABASE:-}" ]]; then
  export CHALLENGER_SIEM_DATABASE
fi

python3 - "$@" <<'PY'
import argparse
import csv
import os
import re
import shutil
import signal
import subprocess
import sys
from io import StringIO
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

CONFIRM_PHRASE = "RESET-TEST-ENVIRONMENT"
ALLOW_ENV = "CHALLENGER_SIEM_ALLOW_FULL_RESET"
ROOT = Path.cwd().resolve()

RESET_TABLES = [
    "alert_evidence",
    "alerts",
    "events",
    "agent_heartbeats",
    "source_health",
    "asset_inventory_snapshots",
    "coverage_exceptions",
    "ingestion_errors",
    "soc_agent_messages",
    "soc_agent_sessions",
    "soc_agent_turns",
    "investigation_graph_audit",
    "investigation_graph_proposals",
    "investigation_graph_edges",
    "investigation_graph_nodes",
    "investigation_graphs",
    "agents",
]

COUNT_TABLES = RESET_TABLES + ["detection_rules"]
REQUIRED_TABLES = COUNT_TABLES
REQUIRED_INDEXES = [
    "idx_events_agent_id",
    "idx_events_hostname",
    "idx_events_event_time",
    "idx_events_windows_event_id",
    "idx_events_channel",
    "idx_events_provider",
    "idx_events_raw_json",
    "idx_events_event_category",
    "idx_events_event_action",
    "idx_events_user_name",
    "idx_events_process_image",
    "idx_events_destination_ip",
    "idx_agent_heartbeats_agent_id",
    "idx_agent_heartbeats_time",
    "idx_source_health_status",
    "idx_source_health_agent",
    "idx_coverage_exceptions_source",
    "idx_asset_inventory_agent_type",
    "idx_detection_rules_category",
    "idx_alerts_status",
    "idx_alerts_agent",
    "idx_alerts_created",
    "idx_alert_evidence_alert",
    "idx_soc_agent_turns_created",
    "idx_soc_agent_turns_context_agent",
    "idx_soc_agent_sessions_updated",
    "idx_soc_agent_sessions_context_agent",
    "idx_soc_agent_messages_session",
    "idx_investigation_graphs_status_updated",
    "idx_investigation_graphs_tags",
    "idx_investigation_graph_nodes_graph",
    "idx_investigation_graph_nodes_reference",
    "idx_investigation_graph_edges_graph",
    "idx_investigation_graph_proposals_graph",
    "idx_investigation_graph_audit_graph",
    "idx_ingestion_errors_agent_id",
    "idx_ingestion_errors_time",
]

SAFE_NAME_MARKERS = ("test", "tests", "dev", "development", "local", "sandbox", "scratch", "disposable", "challenger_siem")
UNSAFE_NAME_MARKERS = ("prod", "production", "live", "client", "customer", "shared")
LOCAL_HOSTS = ("", "localhost", "127.0.0.1", "::1", "[::1]")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run or execute a guarded fresh-start reset for a local/disposable Challenger SIEM "
            "test environment. Output is aggregate-only and never prints connection strings, tokens, "
            "raw telemetry, chat text, cookies, or local secret contents."
        )
    )
    parser.add_argument("--execute", action="store_true", help="Perform the reset. Without this flag, only aggregate dry-run information is reported.")
    parser.add_argument("--confirm", default="", help=f"Required exact confirmation phrase for --execute: {CONFIRM_PHRASE}")
    parser.add_argument("--i-understand-this-deletes-test-data", action="store_true", help="Required with --execute unless CHALLENGER_SIEM_ALLOW_FULL_RESET=1 is set.")
    parser.add_argument("--skip-database", action="store_true", help="Do not inspect or reset the PostgreSQL database.")
    parser.add_argument("--database-only", action="store_true", help="Inspect/reset only the database and skip local artifact reporting.")
    parser.add_argument("--local-artifacts-only", action="store_true", help="Report or clean only known local generated artifacts; no database connection is required.")
    parser.add_argument("--include-local-artifacts", action="store_true", help="With --execute, remove known ignored smoke/browser/platform/test outputs after safety checks.")
    parser.add_argument("--include-platform-logs", action="store_true", help="Include .local/platform/*.log files in local artifact cleanup. Logs are preserved by default.")
    parser.add_argument("--include-generated-agent-files", action="store_true", help="Include generated dist/ agent packages/settings. These may contain test API tokens and are preserved by default.")
    parser.add_argument("--no-schema-validation", action="store_true", help="Skip the post-reset schema sanity check after database execute mode.")
    return parser.parse_args()


def fail(message, code=2):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def parse_connection_string(value):
    if value.startswith("postgres://") or value.startswith("postgresql://"):
        parsed = urlparse(value)
        query = parse_qs(parsed.query)
        database = unquote(parsed.path[1:]) if parsed.path.startswith("/") else ""
        return {
            "host": parsed.hostname or "localhost",
            "port": str(parsed.port or 5432),
            "database": database,
            "user": unquote(parsed.username or ""),
            "password": unquote(parsed.password or ""),
            "sslmode": query.get("sslmode", [""])[0],
        }

    parts = {}
    for item in value.split(";"):
        if not item.strip() or "=" not in item:
            continue
        key, raw = item.split("=", 1)
        parts[key.strip().lower().replace(" ", "")] = raw.strip()

    return {
        "host": parts.get("host") or parts.get("server") or "localhost",
        "port": parts.get("port", "5432"),
        "database": parts.get("database") or parts.get("dbname") or "",
        "user": parts.get("username") or parts.get("userid") or parts.get("user") or "",
        "password": parts.get("password") or parts.get("pwd") or "",
        "sslmode": parts.get("sslmode", ""),
        "search_path": parts.get("searchpath") or parts.get("search_path") or "",
    }


def psql_env(parsed):
    env = os.environ.copy()
    env.update({
        "PGHOST": parsed.get("host") or "localhost",
        "PGPORT": parsed.get("port") or "5432",
        "PGDATABASE": parsed.get("database") or "",
        "PGUSER": parsed.get("user") or "",
        "PGPASSWORD": parsed.get("password") or "",
        "PGCONNECT_TIMEOUT": "10",
    })
    if parsed.get("sslmode"):
        env["PGSSLMODE"] = parsed["sslmode"]
    if parsed.get("search_path"):
        env["PGOPTIONS"] = f"-c search_path={parsed['search_path']}"
    return env


def marker_found(name, markers):
    lowered = name.lower()
    for marker in markers:
        if lowered == marker:
            return marker
        if re.search(rf"(^|[_\-.]){re.escape(marker)}($|[_\-.])", lowered):
            return marker
    return ""


def classify_target(parsed):
    environment = os.environ.get("ASPNETCORE_ENVIRONMENT", "")
    if environment.lower() == "production":
        return False, "ASPNETCORE_ENVIRONMENT is Production"

    host = (parsed.get("host") or "localhost").strip().lower()
    database = (parsed.get("database") or "").strip()
    if not database:
        return False, "database name is missing"

    if host not in LOCAL_HOSTS and not host.startswith("/"):
        return False, "database host is not local"

    unsafe = marker_found(database, UNSAFE_NAME_MARKERS)
    if unsafe:
        return False, f"database name contains unsafe marker {unsafe!r}"

    if not marker_found(database, SAFE_NAME_MARKERS):
        return False, "database name does not look disposable/test/local"

    return True, "local_disposable"


def run_psql(sql, env):
    if shutil.which("psql") is None:
        fail("psql was not found on PATH; install PostgreSQL client tools before database reset validation.")

    result = subprocess.run(
        ["psql", "-v", "ON_ERROR_STOP=1", "-q"],
        input=sql,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(
            "Fresh-start database reset failed. psql reported an error; details are suppressed "
            "to avoid printing connection metadata or secret-adjacent local configuration.\n"
        )
        raise SystemExit(result.returncode)
    return result.stdout


def count_sql():
    selects = []
    for order, table in enumerate(COUNT_TABLES):
        label = "preserved_detection_rules" if table == "detection_rules" else table
        selects.append(f"select {order} as sort_order, '{label}' as table_name, count(*)::bigint as row_count from {table}")
    return "copy (\n" + "\nunion all ".join(selects) + "\norder by sort_order\n) to stdout with csv header;\n"


def truncate_sql():
    tables = ",\n    ".join(RESET_TABLES)
    return f"""
begin;
truncate table
    {tables}
restart identity;
commit;
"""


def validation_sql():
    table_values = ", ".join(f"('{table}')" for table in REQUIRED_TABLES)
    index_values = ", ".join(f"('{index}')" for index in REQUIRED_INDEXES)
    return f"""
with required_tables(name) as (
    values {table_values}
), missing_tables as (
    select 'missing table ' || name as problem
    from required_tables
    where to_regclass('public.' || name) is null
), required_indexes(name) as (
    values {index_values}
), missing_indexes as (
    select 'missing index ' || name as problem
    from required_indexes
    where to_regclass('public.' || name) is null
), missing_constraints as (
    select 'missing unique constraint uq_events_agent_event' as problem
    where not exists (
        select 1
        from pg_constraint
        where conname = 'uq_events_agent_event'
          and conrelid = 'public.events'::regclass
    )
)
copy (
    select problem from missing_tables
    union all select problem from missing_indexes
    union all select problem from missing_constraints
    order by problem
) to stdout with csv header;
"""


def print_database_report(env, execute, validate_schema):
    rows = list(csv.DictReader(StringIO(run_psql(count_sql(), env))))
    print("database_reset=execute" if execute else "database_reset=dry-run")
    print("database_target=local_disposable")
    for row in rows:
        print(f"{row.get('table_name', 'unknown')}={row.get('row_count', '0')}")

    if execute:
        run_psql(truncate_sql(), env)
        print("database_rows_removed=true")
        if validate_schema:
            problems = list(csv.DictReader(StringIO(run_psql(validation_sql(), env))))
            if problems:
                print("schema_validation=failed", file=sys.stderr)
                for problem in problems:
                    print(problem.get("problem", "schema validation problem"), file=sys.stderr)
                raise SystemExit(1)
            print("schema_validation=passed")


def relative(path):
    return path.relative_to(ROOT).as_posix()


def candidate_paths(include_logs, include_generated):
    categories = {
        "smoke_outputs": list(ROOT.glob(".local/smoke-*")),
        "web_smoke_outputs": list(ROOT.glob(".local/web-smoke-*")),
        "browser_artifacts": (
            list(ROOT.glob(".local/playwright"))
            + list(ROOT.glob(".local/playwright-*"))
            + list(ROOT.glob(".local/browser-*"))
            + list(ROOT.glob(".local/*-trace*"))
            + [ROOT / "TestResults", ROOT / "coverage"]
        ),
        "platform_state": [ROOT / ".local/platform/platform.pid", ROOT / ".local/platform/platform.state"],
    }
    if include_logs:
        categories["platform_logs"] = list(ROOT.glob(".local/platform/*.log"))
    if include_generated:
        categories["generated_agent_files"] = [
            ROOT / "dist/WindowsAgent.exe",
            ROOT / "dist/windows-agent-copy",
            ROOT / "dist/windows-agent-win-x64",
        ]
    return {name: sorted({path.resolve() for path in paths if path.exists()}) for name, paths in categories.items()}


def path_size(path):
    if not path.exists() and not path.is_symlink():
        return 0
    if path.is_symlink() or path.is_file():
        return path.lstat().st_size
    total = 0
    for child in path.rglob("*"):
        if child.is_symlink() or child.is_file():
            try:
                total += child.lstat().st_size
            except FileNotFoundError:
                continue
    return total


def remove_path(path):
    try:
        path.relative_to(ROOT)
    except ValueError:
        fail("Refusing local artifact cleanup outside the repository root.", code=1)

    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def platform_pid_alive():
    pid_file = ROOT / ".local/platform/platform.pid"
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
    except (ValueError, OSError, FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    return True


def print_artifact_report(execute, delete_artifacts, include_logs, include_generated):
    categories = candidate_paths(include_logs, include_generated)
    action = "remove" if execute and delete_artifacts else "dry-run"
    print(f"local_artifacts={action}")
    for name, paths in categories.items():
        count = len(paths)
        total_bytes = sum(path_size(path) for path in paths)
        print(f"artifact_{name}_count={count}")
        print(f"artifact_{name}_bytes={total_bytes}")

    print("artifact_secret_config_preserved=true")
    print("artifact_platform_logs_preserved=" + ("false" if include_logs else "true"))
    print("artifact_generated_agent_files_preserved=" + ("false" if include_generated else "true"))

    if execute and delete_artifacts:
        if platform_pid_alive() and (categories.get("platform_state") or categories.get("platform_logs")):
            fail("Refusing local artifact cleanup while the local platform PID appears live; run ./scripts/platform.sh stop first.", code=1)
        for paths in categories.values():
            for path in paths:
                remove_path(path)
        print("local_artifacts_removed=true")


def main():
    args = parse_args()
    if args.database_only and args.local_artifacts_only:
        fail("Choose only one of --database-only or --local-artifacts-only.")
    if args.skip_database and args.database_only:
        fail("Choose only one of --skip-database or --database-only.")

    database_enabled = not args.skip_database and not args.local_artifacts_only
    artifact_report_enabled = not args.database_only
    delete_artifacts = args.local_artifacts_only or args.include_local_artifacts or args.include_generated_agent_files

    if args.execute:
        if args.confirm != CONFIRM_PHRASE:
            fail(f"--execute requires --confirm {CONFIRM_PHRASE!r}.")
        if not args.i_understand_this_deletes_test_data and os.environ.get(ALLOW_ENV) != "1":
            fail(f"--execute requires --i-understand-this-deletes-test-data or {ALLOW_ENV}=1.")
        if not database_enabled and not delete_artifacts:
            fail("--execute would not delete anything; select database reset or local artifact cleanup.")

    print("mode=execute" if args.execute else "mode=dry-run")

    if database_enabled:
        connection_string = os.environ.get("ConnectionStrings__SiemDatabase") or os.environ.get("CHALLENGER_SIEM_DATABASE") or ""
        if not connection_string:
            fail("ConnectionStrings__SiemDatabase is required for database reset. Set it in an ignored local env file or use --local-artifacts-only.")
        parsed = parse_connection_string(connection_string)
        safe, reason = classify_target(parsed)
        if not safe:
            fail(f"Refusing full reset: target database is not classified as local/disposable ({reason}).")
        print_database_report(psql_env(parsed), args.execute, not args.no_schema_validation)
    else:
        print("database_reset=skipped")

    if artifact_report_enabled:
        print_artifact_report(args.execute, delete_artifacts, args.include_platform_logs, args.include_generated_agent_files)
    else:
        print("local_artifacts=skipped")

    if not args.execute:
        print("dry_run_only=true")
        print(f"execute_requires=--execute --confirm {CONFIRM_PHRASE} --i-understand-this-deletes-test-data")
    return 0


raise SystemExit(main())
PY
