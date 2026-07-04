#!/usr/bin/env python3
"""Project-local WinRM helper for Challenger SIEM lab operations.

Credentials are intentionally read from environment variables or an ignored
`.local/winrm.env` file. Do not pass passwords on the command line.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off"}
DEFAULT_PASSWORD_ENV = "CHALLENGER_WINRM_PASSWORD"


def find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / "Challenger.Siem.sln").exists() or (candidate / ".git").exists():
            return candidate
    return start


def parse_bool(value: object, *, default: Optional[bool] = None) -> bool:
    if value is None:
        if default is None:
            raise ValueError("boolean value is required")
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return parse_bool(value, default=default)


def resolve_local_path(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    return (base / path).resolve()


def strip_optional_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise SystemExit(f"Invalid env file line {line_number} in {path}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"Invalid env file line {line_number} in {path}: empty key")
        os.environ.setdefault(key, strip_optional_quotes(value))


def import_client():
    try:
        from pypsrp.client import Client
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing Python package 'pypsrp'. Install it in the Pi host environment "
            "using an operator-approved package source before using WinRM."
        ) from exc
    return Client


def add_common_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", help="WinRM host/IP. Default: CHALLENGER_WINRM_HOST")
    parser.add_argument("--user", help="WinRM username. Default: CHALLENGER_WINRM_USER")
    parser.add_argument(
        "--password-env",
        help=f"Environment variable containing the WinRM password. Default: CHALLENGER_WINRM_PASSWORD_ENV or {DEFAULT_PASSWORD_ENV}",
    )
    parser.add_argument(
        "--password-file",
        help="File containing the WinRM password. Default: CHALLENGER_WINRM_PASSWORD_FILE if set",
    )
    parser.add_argument("--port", type=int, help="WinRM port. Default: 5986 for SSL, otherwise 5985")
    parser.add_argument(
        "--ssl",
        choices=sorted(TRUE_VALUES | FALSE_VALUES),
        help="Use HTTPS WinRM. Default: CHALLENGER_WINRM_SSL or true",
    )
    parser.add_argument(
        "--cert-validation",
        choices=sorted(TRUE_VALUES | FALSE_VALUES),
        help="Validate HTTPS certificates. Default: CHALLENGER_WINRM_CERT_VALIDATION or true",
    )
    parser.add_argument(
        "--auth",
        help="WinRM auth mechanism: negotiate, ntlm, kerberos, basic, credssp, certificate. Default: CHALLENGER_WINRM_AUTH or negotiate",
    )
    parser.add_argument("--connection-timeout", type=int, help="HTTP connection timeout seconds")
    parser.add_argument("--read-timeout", type=int, help="HTTP read timeout seconds")
    parser.add_argument("--operation-timeout", type=int, help="WSMan operation timeout seconds")
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Ignore proxy environment variables for WinRM connections",
    )
    parser.add_argument(
        "--env-file",
        help="Env file to load before connecting. Default: .local/winrm.env when present. Use 'none' to disable.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run authorized WinRM operations against the configured Windows lab host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    add_common_connection_args(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("test", help="Test connectivity and print basic remote host identity")

    ps_parser = subparsers.add_parser("ps", help="Run a PowerShell script remotely")
    ps_input = ps_parser.add_mutually_exclusive_group()
    ps_input.add_argument("--script", help="PowerShell script text to run")
    ps_input.add_argument("--file", help="Local PowerShell script file; contents are run remotely")

    cmd_parser = subparsers.add_parser("cmd", help="Run a cmd.exe command remotely")
    cmd_parser.add_argument("--command", required=True, help="Command line to execute with cmd.exe")

    copy_parser = subparsers.add_parser("copy", help="Copy one local file to the remote Windows host")
    copy_parser.add_argument("local_path", help="Local file path")
    copy_parser.add_argument("remote_path", help="Remote destination path, for example C:\\Temp\\file.txt")

    fetch_parser = subparsers.add_parser("fetch", help="Fetch one remote file from the Windows host")
    fetch_parser.add_argument("remote_path", help="Remote source path")
    fetch_parser.add_argument("local_path", help="Local destination path")

    return parser


def load_default_env(args: argparse.Namespace, repo_root: Path) -> None:
    if args.env_file == "none":
        return
    env_file = resolve_local_path(args.env_file, repo_root) if args.env_file else repo_root / ".local" / "winrm.env"
    load_env_file(env_file)


def get_password(args: argparse.Namespace, repo_root: Path) -> tuple[Optional[str], str]:
    password_env = args.password_env or os.environ.get("CHALLENGER_WINRM_PASSWORD_ENV", DEFAULT_PASSWORD_ENV)
    password = os.environ.get(password_env)
    if password:
        return password, password_env

    password_file_value = args.password_file or os.environ.get("CHALLENGER_WINRM_PASSWORD_FILE")
    if not password_file_value:
        return None, password_env

    password_file = resolve_local_path(password_file_value, repo_root)
    try:
        return password_file.read_text(encoding="utf-8").strip("\r\n"), password_env
    except OSError as exc:
        raise SystemExit(f"Unable to read password file {password_file}: {exc}") from exc


def build_client(args: argparse.Namespace, repo_root: Path):
    Client = import_client()

    host = args.host or os.environ.get("CHALLENGER_WINRM_HOST")
    user = args.user or os.environ.get("CHALLENGER_WINRM_USER")
    password, password_env = get_password(args, repo_root)

    missing = []
    if not host:
        missing.append("CHALLENGER_WINRM_HOST")
    if not user:
        missing.append("CHALLENGER_WINRM_USER")
    if not password:
        missing.append(password_env)
    if missing:
        raise SystemExit(
            "Missing WinRM connection setting(s): "
            + ", ".join(missing)
            + ". Put lab-only values in .local/winrm.env or export them before use."
        )

    ssl = parse_bool(args.ssl, default=env_bool("CHALLENGER_WINRM_SSL", True))
    cert_validation = parse_bool(
        args.cert_validation,
        default=env_bool("CHALLENGER_WINRM_CERT_VALIDATION", True),
    )
    auth = args.auth or os.environ.get("CHALLENGER_WINRM_AUTH", "negotiate")
    port = args.port or int(os.environ.get("CHALLENGER_WINRM_PORT") or (5986 if ssl else 5985))
    connection_timeout = args.connection_timeout or int(os.environ.get("CHALLENGER_WINRM_CONNECTION_TIMEOUT", "30"))
    read_timeout = args.read_timeout or int(os.environ.get("CHALLENGER_WINRM_READ_TIMEOUT", "30"))
    operation_timeout = args.operation_timeout or int(os.environ.get("CHALLENGER_WINRM_OPERATION_TIMEOUT", "20"))
    no_proxy = args.no_proxy or env_bool("CHALLENGER_WINRM_NO_PROXY", False)

    return Client(
        host,
        username=user,
        password=password,
        ssl=ssl,
        port=port,
        auth=auth,
        cert_validation=cert_validation,
        connection_timeout=connection_timeout,
        read_timeout=read_timeout,
        operation_timeout=operation_timeout,
        no_proxy=no_proxy,
    )


def print_ps_streams(streams) -> None:
    for stream_name in ("error", "warning", "verbose", "debug", "information"):
        records = getattr(streams, stream_name, [])
        for record in records:
            text = str(record).rstrip()
            if not text:
                continue
            target = sys.stderr if stream_name == "error" else sys.stdout
            print(f"[{stream_name}] {text}", file=target)


def run_test(client) -> int:
    script = r"""
$ErrorActionPreference = 'Stop'
[pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  User = (whoami)
  PSVersion = $PSVersionTable.PSVersion.ToString()
  OS = (Get-CimInstance Win32_OperatingSystem).Caption
} | ConvertTo-Json -Compress
""".strip()
    output, streams, had_errors = client.execute_ps(script)
    if output:
        print(output.rstrip())
    print_ps_streams(streams)
    return 1 if had_errors else 0


def run_ps(client, args: argparse.Namespace, repo_root: Path) -> int:
    if args.script is not None:
        script = args.script
    elif args.file is not None:
        script_path = resolve_local_path(args.file, repo_root)
        script = script_path.read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        script = sys.stdin.read()
    else:
        raise SystemExit("PowerShell input required: pass --script, --file, or pipe script text on stdin")

    output, streams, had_errors = client.execute_ps(script)
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    print_ps_streams(streams)
    return 1 if had_errors else 0


def run_cmd(client, args: argparse.Namespace) -> int:
    stdout, stderr, return_code = client.execute_cmd(args.command)
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
    return return_code


def run_copy(client, args: argparse.Namespace, repo_root: Path) -> int:
    local_path = resolve_local_path(args.local_path, repo_root)
    if not local_path.is_file():
        raise SystemExit(f"copy supports one file at a time; local path is not a file: {local_path}")
    result_path = client.copy(str(local_path), args.remote_path)
    print(f"copied {local_path} -> {result_path}")
    return 0


def run_fetch(client, args: argparse.Namespace, repo_root: Path) -> int:
    local_path = resolve_local_path(args.local_path, repo_root)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    client.fetch(args.remote_path, str(local_path))
    print(f"fetched {args.remote_path} -> {local_path}")
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    repo_root = find_repo_root(Path.cwd().resolve())
    load_default_env(args, repo_root)
    client = build_client(args, repo_root)

    try:
        if args.command == "test":
            return run_test(client)
        if args.command == "ps":
            return run_ps(client, args, repo_root)
        if args.command == "cmd":
            return run_cmd(client, args)
        if args.command == "copy":
            return run_copy(client, args, repo_root)
        if args.command == "fetch":
            return run_fetch(client, args, repo_root)
        raise SystemExit(f"Unknown command: {args.command}")
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            close()


if __name__ == "__main__":
    raise SystemExit(main())
