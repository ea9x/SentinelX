# Security policy

SentinelX is experimental. No release is certified secure or supported for public multi-tenant deployment. Review the current main branch and reproduce issues on a disposable installation.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** private reporting option if the repository owner has enabled it. If it is unavailable, contact the owner using a private channel they explicitly publish. Do not post exploit details, credentials, private targets, reports or database dumps in public issues. There is no invented security contact address or response-time guarantee.

Include the affected commit/version, installation method, minimal reproduction on a local fixture, expected and observed behavior, and impact. Redact secrets and personal data.

## Deployment boundaries

Only scan systems you own or have explicit authorization to test. Scanning private/local targets is an intended capability; the app does not prove network authorization or enforce a comprehensive egress allowlist. Do not expose it as an unrestricted scanning proxy. Install tools separately from official sources and follow their terms.

Never commit `.env`, reports, uploads, database files/dumps, private keys, backups or local logs. If a secret ever reached Git history, rotate it; deleting the working-tree file is insufficient.
