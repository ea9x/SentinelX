# Experimental Docker setup

This stack defines frontend, backend, one scan worker, MySQL and ZAP services. A bounded Docker rehearsal on 2026-10-25 built the frontend and a backend with the WhatWeb runtime-gem fix below, and verified login, real SSLyze/WhatWeb jobs, PDF export and persistence across container recreation on a separate fixture stack. This is not a full scanner-coverage, load, security or production certification. [Windows installation](INSTALL-WINDOWS.md) remains available.

1. Install Docker Engine/Desktop and Compose from the vendor.
2. From the repository root run `python scripts/configure_local.py --docker`. It creates root `.env` with independent random keys/passwords and refuses to overwrite existing configuration.
3. Run `docker compose up --build -d`. The build downloads separate scanner components; review upstream licenses. Build output and resolved images are not shipped in the source package.
4. Create the first account: `docker compose exec backend flask --app app create-initial-admin`. No account is seeded.
5. Open `http://localhost:8088/login`. Frontend is bound to loopback; database and ZAP have no host port mapping. Only scan authorized targets. In containers, the host is reachable through `host.docker.internal`; `127.0.0.1` refers to each container.

Use `docker compose ps` and `docker compose logs backend worker frontend` to diagnose readiness. Initial schema creation and worker startup may wait for MySQL. Password recovery additionally requires SMTP variables and the actual `PUBLIC_APP_URL`; login does not depend on SMTP. The worker's scanner privileges do not make it safe to expose this as a public scanning service.

Stop with `docker compose down`. This preserves named volumes. **Do not use `down -v` unless you intend to destroy the database/reports volumes.** Preserve a database backup before updates. Changing a database password in `.env` does not rotate credentials inside an existing MySQL volume.

Local Windows encrypted backup commands and supervisor are not Docker backup/restore tooling. A full container-volume recovery requires a separate rehearsal. Image/runtime hardening, HTTPS, production cookie configuration, vulnerability scanning and end-to-end Docker validation remain release work. Docker has not been certified production-ready.

## SSLyze dependency isolation

The image installs SSLyze 6.3.1 into `/opt/sentinelx-scanners/sslyze`, separately from the application interpreter. SSLyze requires `cryptography>=43,<47`, while the backend requires `cryptography>=50,<51`; installing both in one environment fails dependency resolution. `SSLYZE_PATH` points at the dedicated scanner executable. Keep scanner dependencies in `backend/requirements-sslyze.txt` and backend dependencies in `backend/requirements-docker.txt`.

Build steps run `pip check` in both environments and verify that the scanner CLI starts. These checks do not replace a complete image build and an isolated TLS scan. A separate Linux/Python 3.13 fixture stack subsequently verified this separation at runtime: backend cryptography 50.0.2 and scanner cryptography 46.0.7. See the bounded validation notes below.

## Bounded Docker rehearsal (2026-10-25)

The backend build stalled resolving the upstream WhatWeb development/test Gemfile. The image now installs only its three declared required runtime gems (ipaddr 1.3.0, addressable 2.9.0, json 3.1.0), then checks `whatweb --version`. The pinned WhatWeb source and license files are retained. Optional Mongo logging, charset-detection and development gems are not installed.

Validation used a separate Compose project, MySQL volume, reports volume and frontend port 19088. Login and authenticated APIs passed. A real queued SSLyze scan found the deliberately expired/untrusted TLS certificate, missing HSTS and a TLS information record; a real WhatWeb job completed. PDF generation/download passed. Recreating the containers retained the account, two targets, two scans and a report with an identical PDF SHA256. Service health reported six integrations available; this does not mean all six performed end-to-end scans. Nmap, Nuclei and ZAP scan workflows, full container-volume backup/restore, load behavior and production hardening were not certified in this rehearsal.

The test stack uses the same application images with explicit fixture settings; it does not validate every setting or startup ordering of the supplied production-style Compose file. Docker Desktop recovery involved preserving stale runtime-socket directories, not factory-resetting or deleting container data. That local workaround is not a permanent Docker/Windows bug fix.
