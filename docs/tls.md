# HTTPS/TLS deployment path

Challenger SIEM treats HTTPS as required outside local development and the explicitly authorized lab callback path.

## Local development

Acceptable local-only HTTP endpoints:

- `http://127.0.0.1:<port>` for same-host smoke tests.
- `http://192.168.122.1:4444` for the authorized Windows lab VM callback path documented in this repository.

These HTTP endpoints are for development/lab validation only. They must not be used for production endpoint enrollment or telemetry.

## Production options

Use one of these deployment shapes:

1. **Reverse proxy terminates TLS**
   - Run Kestrel on a private loopback or internal interface.
   - Terminate HTTPS in a maintained reverse proxy such as nginx, Apache, IIS, or a platform load balancer.
   - Forward only the required application paths to the API process.
   - Keep private keys in the proxy/platform secret store, not in this repository.

2. **Kestrel terminates TLS directly**
   - Configure `ASPNETCORE_URLS=https://0.0.0.0:443` or equivalent Kestrel endpoints.
   - Provide certificates with ASP.NET Core configuration or the host certificate store.
   - Protect certificate private keys with OS permissions and never commit them.

## Agent trust expectations

Windows agents must trust the server certificate chain used by `ServerBaseUrl`.

- For public certificates, use a CA chain trusted by the Windows endpoint.
- For private/internal PKI, install the issuing CA certificate through normal endpoint management.
- Do not disable certificate validation in production.
- Keep `ServerBaseUrl` as `https://...` for production registration, ingest, and heartbeat.

## Server enforcement

In non-Development ASP.NET Core environments the API rejects plain HTTP requests with `https_required`. `UseHttpsRedirection` is also enabled. Ensure reverse proxies set the forwarded-proto configuration appropriate for the hosting environment before exposing the API publicly.

## Secret handling

TLS private keys, enrollment tokens, review tokens, database passwords, generated agent settings, and raw telemetry stay in ignored local files or external secret stores. They must not be committed, pasted into issue comments, or included in release artifacts.
