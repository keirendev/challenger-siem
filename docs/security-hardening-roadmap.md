# Security hardening roadmap

This roadmap covers the full-coverage security design items that are not yet production account-management features.

## Raw/script/command-line redaction policy

Default policy:

- Do not expose provider secrets, API tokens, enrollment tokens, passwords, private keys, connection strings, cookies, or authorization headers in logs, prompts, docs, issue comments, or PR text.
- Treat raw JSON, command lines, PowerShell script blocks, URLs, file paths, registry values, and usernames as potentially sensitive.
- Store normalized fields for search, but pass only bounded/redacted fields to external tools or future `soc-agent` providers.
- Cap script blocks to 4096 characters and command lines to 2048 characters before tool/model sharing unless an operator explicitly approves a larger local-only review.
- Redact query strings, bearer tokens, basic-auth fragments, and common key/value secret patterns.

## Operator RBAC and field-level access control design

Future operator accounts should support these roles:

- `viewer`: dashboard, agent inventory, event metadata, alert list.
- `analyst`: event detail, alert triage, investigation notes, read-only `soc-agent` tools.
- `detection_engineer`: detection draft/backtest/proposal management.
- `admin`: provider configuration, token rotation, approvals, and sensitive mutations.

Field-level policy should allow hiding or redacting raw payloads, script blocks, command lines, usernames, IP addresses, and file paths by role. MVP operator-credential auth maps to an implicit admin-like local operator only for development; production should not assume every authenticated user may mutate state.

## mTLS readiness for agent transport

The current v1 transport remains bearer-token compatible. mTLS readiness requires:

- certificate enrollment/rotation design that does not put private keys in source control;
- server trust-store configuration and certificate revocation plan;
- agent configuration for client certificate path or Windows certificate store thumbprint;
- telemetry showing certificate identity in heartbeat/audit records;
- backwards-compatible rollout where bearer-token auth remains available until all agents can upgrade.

## Tamper checks

Agent heartbeat supports configuration hash and tamper summary fields. Production hardening should add:

- binary hash/signature verification;
- config/state/queue ACL verification;
- protected token storage with DPAPI or an equivalent host-bound mechanism;
- source-health alerts for event-log clear/truncation/bookmark gaps;
- audit events when the running binary/config hash changes unexpectedly.
