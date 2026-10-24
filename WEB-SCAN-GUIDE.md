# API and authenticated web checks

On Target Management, expand **Web scan settings — next ZAP or Full scan**. Supply a JSON object, then start ZAP or Full Scan for the intended target. `{}` enables public exposure checks and discovery at common OpenAPI locations. Settings apply once and are cleared from the form when the scan starts. Use dedicated test accounts and known resources.

```json
{
  "openapi_path": "/openapi.json",
  "paths": ["/api/profile", "/api/search?q=example"],
  "query_checks": ["/api/search?q=example"],
  "accounts": [
    {
      "login": {
        "path": "/api/login",
        "json": {"email": "account-a@example.test", "password": "REPLACE"},
        "token_field": "authentication.token"
      },
      "verify_path": "/api/profile",
      "verify_marker": "account-a@example.test"
    },
    {
      "headers": {"Authorization": "Bearer REPLACE_WITH_ACCOUNT_B_TOKEN"},
      "verify_path": "/api/profile",
      "verify_marker": "account-b@example.test"
    }
  ],
  "authorization_checks": [
    {
      "path_a": "/api/private-objects/101",
      "path_b": "/api/private-objects/202",
      "marker_a": "unique-private-object-a",
      "marker_b": "unique-private-object-b"
    }
  ]
}
```

Account headers support `Authorization` and `Cookie`. JSON login extracts a token using the dotted `token_field` and sends it as Bearer authentication. Each account must pass its verification request, and the anonymous response must not contain that account's verification marker. For cookie-based login without a JSON token, provide a test session through the Cookie header.

The authorization case requires two distinct sessions, correctly identified owned resources, anonymous denial (401/403/404), and account A receiving B's resource marker. Use resources expected to be private to their owners. Public resources, denied cross-account requests and inconclusive checks are not reported as confirmed cross-account access. Findings retain the normal manual-review workflow.

OpenAPI JSON/YAML and JSON definitions embedded in standard Swagger UI initialization scripts are supported. Server hosts in the definition are ignored; all requests stay on the selected target. GET operations without unresolved path placeholders are read, with query examples/defaults where available. External `$ref` documents and write operations are not executed. Supply concrete paths for parameterized resources. A UI HTML page is not accepted as an OpenAPI definition.

Query checks send bounded syntax probes to configured GET query parameters and look for HTTP 5xx responses with database error signatures. They report error disclosure, not proof of exploitable SQL injection or authentication bypass. Public exposure checks look for Prometheus output, directory indexes and documents containing confidentiality markers; document visibility still needs review.

By default, authenticated checks are direct SentinelX requests. Enable `authenticated_zap: true` with a JSON login for account 1 to also run ZAP's spider and active scanner as that user. This creates a unique context, JSON authentication method and header session, then removes the context after the run. Login requests and tokens can appear in ZAP's own history; use a dedicated test instance and account. Header-only token/cookie accounts support direct checks. Full browser authentication, MFA and automatic user-object discovery remain outside this implementation.

The visual settings form supports these options without editing JSON. `scan_mode` is `focused` (lower active attack strength) or `comprehensive` (ZAP's default policy). Focused mode trades probe volume for speed; neither mode guarantees completeness. An isolated policy is removed afterward; global scanner settings are not modified.

Jobs report their current stage and progress. Cancel a queued job immediately, or request cancellation of a running job. ZAP stops its own scan at the next poll. Other integrations finish their current step; Full Scan checks cancellation before starting another tool. Completed findings remain available. Progress describes workflow steps, not vulnerability coverage.

The findings page groups similar records while preserving individual scan/location links, and shows confidence separately from review status. PDF reports explicitly identify incomplete scans.

## Local startup and encrypted backups

`start_local.ps1` starts local services without replacing processes already listening. The per-user `SentinelX Local Startup` scheduled task runs `start_local.ps1 -Quiet` with limited privileges after Windows sign-in. `register_startup.ps1` registers that task and exports/disables the known legacy SentinelX tasks. MySQL must be running as its existing Windows service. Files under `.local` contain service logs and encrypted backup archives. Startup attempts a backup if the most recent one is older than 24 hours; backups defer while scans are active.

Run `start_local.ps1 -Action backup` for an encrypted database, configuration, upload and report snapshot. The archive is stored under `.local/backups`; its separate decryption key is `%LOCALAPPDATA%/SentinelX/backup.key`. Preserve that key separately: an archive cannot be recovered without it. `start_local.ps1 -Action verify -Archive PATH` decrypts the archive and restores the database into a new temporary SQLite file, compares every row, then removes only that temporary file. Verification never overwrites MySQL. A tested SQLite round trip is not a full MySQL disaster-recovery rehearsal or automatic production restore. Archive size is limited to 100 MiB; backups are not automatically pruned.

Queued account settings are encrypted using a key derived from the deployment SECRET_KEY, and removed on completion, failure or recovery of an interrupted running job. Keep that deployment secret stable and private. Settings are never returned by the job API. Requests use independent explicit authentication headers, no ambient proxy, no redirects, a 1 MiB response limit and a bounded time budget. Login bodies and tokens are excluded from exported results.

If a ZAP scan times out, it remains failed/incomplete. Successfully collected partial findings are retained in scan history, rather than being discarded or presented as a clean result.

## Protocol detection and scan coverage

Web scanner URLs use detected TLS/HTTP support, including HTTPS on nonstandard ports and plain HTTP on port 443. Detection is cached only for the current job/request. If detection is unavailable, individual web scans retain the conventional port-based fallback and their scanner result still determines success/failure. Protocol detection is not certificate validation and does not follow redirects.

Full scans run Nmap, and run web/TLS tools only when their protocol was confirmed or detection was unavailable. A confirmed unreachable port skips those tools. Skipped tools have an explicit reason, no successful scan record is fabricated, and the full job remains incomplete (`partial` when at least one tool completed). An unconfirmed protocol is not proof that the service is absent. A new scan retries detection; old successful risk results are not erased by a failed or skipped attempt.

Backup verification supports archives created before new additive tables existed by creating those tables empty. It rejects unknown tables instead of dropping them. It still compares restored rows and never modifies the live MySQL database. Keep the encrypted archive, its separate encryption key and the matching application source version available for disaster recovery.

## Optional JSON login injection checks

`login_injection_checks` defaults to false. Enable **Check JSON login injection** only with a dedicated JSON login test account in slot 1, an `email` or `username` field, a `password` field, a dotted token response field, and a private verification resource with a distinctive marker. Header-only accounts cannot enable this check.

The detector first verifies normal authentication and anonymous denial. It then uses independently invalid credentials and at most two paired false/true login predicates, with a random invalid password. HTTP 200 or token-shaped text alone is insufficient: a returned token must retrieve the configured private resource and marker. A successful pair creates a **potential** CWE-89 authentication-bypass finding, using POST and the mutated field name. It still requires manual review. Returned tokens, login bodies and private marker contents are not exported as evidence.

Rate limits, server errors, public verification resources, or accepted invalid/false controls produce an incomplete API result rather than a clean result or a SQL-injection claim. The checks consume the existing bounded API scan budget, do not follow redirects, and can trigger target-side login limits. They are not a comprehensive login or injection assessment; session-cookie/HTML login flows and other database/query patterns are outside this detector's scope. The option is available for the next ZAP/Full scan and remediation recheck settings; transient settings follow the existing encrypted queue lifecycle.

## Selecting the Ruby runtime

`RUBY_PATH` optionally selects the same executable for WhatWeb readiness and scans. Leave it unset to use Ruby from PATH. A configured executable that cannot run is reported unavailable; the application does not silently switch to another Ruby. The 2026-10-23 local repair uses a verified vendor Ruby 4.0.7 portable runtime owned by the project, with the required WhatWeb gem versions. It leaves system Ruby and Windows application-control settings unchanged. See `INSTALL-WINDOWS.md` for the source/hash and dependencies.
