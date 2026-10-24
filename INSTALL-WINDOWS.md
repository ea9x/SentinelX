# Local Windows installation and recovery

The clean installation rehearsal used Python 3.12.14, Node 24.19.0, and a separate MySQL 8.0.46 instance on the existing Windows host. It is not a clean-machine/VM certification. Python 3.15 failed to build PyYAML during the clean installation test; use the tested Python 3.12 environment for a new install. An existing functioning environment does not need to be replaced.

## Guided installation

Install Python 3.12 with the Windows launcher and Node.js 24, extract the source into a writable folder, then open **Install SentinelX.cmd**. It installs Python/npm dependencies, builds the frontend, creates configuration only if absent and guides first-administrator creation. Existing configuration and accounts are retained.

Choose **SQLite local trial** to evaluate the application without manually provisioning MySQL. The database stays in `.local/sentinelx.sqlite`. This option does not install scanner runtimes and is not certified for concurrent/multi-user operation. Choose **MySQL** only after creating a dedicated database/user; enter its password in the hidden prompt. No database root password is requested.

A setup preflight is available as `py -3.12 scripts/setup_windows.py --check-only`; it changes no configuration or services. The normal Python setup command omits service startup; the double-click launcher passes `--start`. Unattended `--mode sqlite --non-interactive` deliberately leaves the first administrator unprovisioned and does not start services.

If Windows blocks a script under your device policy, use an allowed terminal workflow or consult the device administrator; do not disable protection to install this application.

## Manual MySQL installation

1. Install Python 3.12, Node 24, MySQL and the required scanners from their official distributions. Keep scanner listeners on loopback. Nmap, Ruby/WhatWeb, Nuclei and SSLyze must be executable by the user; file presence alone does not establish that Windows permits execution.
2. From the project folder, create the environment with `py -3.12 -m venv backend\venv`, then run `backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt` and `npm ci --prefix frontend`.
3. Run `py -3.12 scripts/configure_local.py` to generate local private signing/ZAP keys without overwriting existing configuration. Create a dedicated database and database user. Put its credentials in `backend/.env`: `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`. Set a private random `SECRET_KEY`, `PUBLIC_APP_URL=http://127.0.0.1:8088`, `ALLOW_REGISTRATION=false`, and a private `ZAP_API_KEY` matching the local ZAP instance. Do not copy credentials from another person's installation or commit this file. Optional scanner paths are `NUCLEI_PATH`, `WHATWEB_PATH`, `SSLYZE_PATH`; configure `ZAP_API_URL` if it differs from the default loopback port 8080.
4. In `backend`, run `venv\Scripts\python.exe -m flask --app app create-initial-admin`. The local command prompts for username/email and a hidden password with confirmation. It creates only the first account on an empty installation, and refuses to change existing accounts. Do not pass the password in shell arguments or enable public registration to bootstrap an administrator.
5. Run `npm run build --prefix frontend`, then `start_local.ps1` from the project folder. Open `http://127.0.0.1:8088/login`. Run `register_startup.ps1` if this user should start services automatically after Windows sign-in; legacy task replacement may require an administrator terminal.

## Updates

Wait for the scan queue to become idle, run `start_local.ps1 -Action backup`, preserve the original source files and encrypted archive/key, install the reviewed source update and build the frontend. Restart the single backend/worker only after checking the queue. Startup applies additive schema changes; never delete the database to apply an update. Refresh existing browser tabs after replacing the frontend build.

## Recovery verification

Use `start_local.ps1 -Action verify -Archive PATH` to validate an encrypted archive through an isolated SQLite restore. This command never overwrites the live MySQL database. Preserve the separate `%LOCALAPPDATA%\SentinelX\backup.key`; the encrypted archive alone is insufficient. A full MySQL restore should be rehearsed in a separate database/process before any live recovery. The synthetic MySQL rehearsal on 2026-10-23 compares all rows, task notes and large scan evidence after restore; its report states whether that rehearsal succeeded.

## Runtime blockers

If Windows Application Control blocks a Ruby native library, WhatWeb is unavailable even if the script exists. The application reports that condition. A verified official RubyInstaller **4.0.7-1 x64** patch release resolved the observed Ruby 4.0.6 `digest.so` blocker on the test machine, without changing Windows protections. This result does not guarantee that every device policy permits that runtime.

Set `RUBY_PATH` in `backend/.env` to a project-owned runtime's absolute `bin/ruby.exe` path when system Ruby should remain unchanged. Health checks and scans use the same configured executable; a broken explicit path does not silently fall back to a different runtime. An unset `RUBY_PATH` retains PATH-based Ruby discovery. For this WhatWeb version, the runtime was supplied with the lockfile's `addressable 2.9.0` and `public_suffix 7.0.5` dependencies.

Use the [official RubyInstaller release](https://github.com/oneclick/rubyinstaller2/releases/tag/RubyInstaller-4.0.7-1). The tested x64 portable archive SHA-256 is `7a9be96d3448ecbd9a81eccae1f619131dfcc761f2c98dded03ece6c05d0474f`. Verify the vendor artifact before installation. Do not copy a blocked library to another loader or turn off Windows protections to make a runtime work. If a supported official runtime remains blocked, review the installation and policy with the device administrator/vendor. Other scanner findings do not replace missing WhatWeb coverage.

For background supervision, deliberate shutdown and updates, see [Operations](docs/OPERATIONS.md). Source packages omit scanner tools: download WhatWeb, Nuclei and SSLyze from the official sources listed in [Third-party notices](THIRD_PARTY_NOTICES.md), then configure their executable paths. Do not copy an existing private installation into Git.
