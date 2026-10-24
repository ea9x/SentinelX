# SentinelX

[![Source checks](https://github.com/ea9x/SentinelX/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/ea9x/SentinelX/actions/workflows/checks.yml)

A local security assessment workspace for authorized analysts. SentinelX queues scans, retains evidence, groups findings, tracks manual review and remediation, compares completed scans, and exports PDF reports.

**Status: experimental, single-service/single-operator deployment.** Do not treat automated findings, a successful scan, or an empty result as proof that a target is secure. This repository is not a certified penetration-testing product or a public multi-tenant scanning service.

## Features

- React interface in English and Arabic, including right-to-left layout.
- Nmap, WhatWeb, OWASP ZAP, Nuclei and SSLyze integrations; scanner binaries are installed separately.
- Persistent serial scan queue, progress, cancellation, explicit partial/failed coverage and retained history.
- Owner-scoped targets, findings, reports and remediation tasks.
- Cookie-based JWT authentication with CSRF protection, session revocation and optional email-link password recovery.
- Manual finding review, revision history, conservative comparison and PDF reports.
- Local encrypted backups with isolated restore verification.

## Screenshots

These screenshots use a synthetic local TLS target and a disposable test account. They show real SSLyze observations in an isolated workflow; no customer targets or production findings are shown. The test database was SQLite; the historical sidebar's MySQL label identifies the integration and does not establish the fixture database engine.

### Compare scans

A controlled certificate replacement removes the expiration observation while the separate self-signed trust warning persists. An absent finding is shown as **not observed**, without automatically marking it fixed.

![English scan comparison showing one observation no longer detected and one persistent observation](docs/images/scan-comparison-en.png)

### Remediation in Arabic

The original occurrence was manually reviewed after the recheck, and its task was then marked completed. New scan occurrences require their own review.

![Arabic remediation page showing a manually fixed certificate occurrence and completed task](docs/images/remediation-ar.png)

## Windows setup

Install **Python 3.12** (including the Windows Python launcher) and **Node.js 24**, extract the source, and double-click **Install SentinelX.cmd**.

The guided setup checks these runtimes, creates the Python environment, installs locked dependencies, builds the frontend, creates private configuration only when absent, and prompts for the first administrator. It does not create a default account or overwrite existing configuration.

Choose one database mode:

- **SQLite local trial (default):** creates a local database under `.local/`; no separate MySQL service is needed. Use this for a first local evaluation. This mode has isolated workflow validation, not a multi-user/load certification.
- **Existing MySQL:** provide a dedicated database/user you have already created. The setup does not request database root credentials or provision a server.

Scanner runtimes are separate prerequisites. Missing tools remain unavailable; PATH discovery is not a successful scan or proof that a tool is executable. Configure Nmap, Ruby/WhatWeb, Nuclei, SSLyze and ZAP using [Windows installation](INSTALL-WINDOWS.md). Login does not depend on SMTP; password recovery does.

For a read-only setup check:

```powershell
py -3.12 scripts/setup_windows.py --check-only
```

For guided setup without starting services automatically:

```powershell
py -3.12 scripts/setup_windows.py
```

The installer may need network access for Python/npm dependencies. Review any installation error before retrying. Start an existing configured installation with `start_local.ps1`, then open `http://127.0.0.1:8088/login`.

Python 3.15 is not a supported fresh-install target. Existing functioning installations retain their current database and environment. [Docker](DOCKER-SETUP.md) remains experimental without complete end-to-end build/run validation.

## Tests

Backend tests use a disposable SQLite database and mocked scanner processes or local HTTP fixtures. They do not scan your saved targets or connect to your MySQL database. Run from `backend`:

```powershell
venv\Scripts\python.exe -B -m unittest discover -s tests
```

From the repository root:

```powershell
npm run test:i18n --prefix frontend
npm run build --prefix frontend
python scripts/check_release.py
```

The GitHub workflow runs these checks on Windows and Linux. A workflow file is not evidence of a successful hosted run; inspect the actual Actions results after pushing.

## Operational boundaries

The local launcher starts a background Windows frontend/backend supervisor. It restarts a backend or frontend only when its port is closed; it never kills a process occupying a port. Interrupted scans are marked failed and require an explicit new scan. [Operations](docs/OPERATIONS.md) explains stopping supervision and troubleshooting.

Local HTTP serving uses Flask development serving and Vite preview. Keep it on loopback. TLS termination, Secure cookies, a production server, destination restrictions, scanner isolation, monitoring and independent review are required before internet deployment. Docker binds its frontend to loopback by default.

## Documentation

- [Web scans, accounts and coverage](WEB-SCAN-GUIDE.md)
- [Security policy](SECURITY.md) and [review scope](SECURITY-REVIEW.md)
- [Contributing](CONTRIBUTING.md)
- [Publishing checklist](docs/PUBLISHING.md)
- [Third-party components](THIRD_PARTY_NOTICES.md)
- [Draft v0.1.0 preview notes](docs/releases/v0.1.0.md)

## Rights and license

No open-source license has been selected for SentinelX yet. Public visibility does not grant a general license to use, modify or redistribute this project's original code. The owner must select a license before advertising it as open source. Third-party components retain their own licenses. Do not add a license to code you do not own.
