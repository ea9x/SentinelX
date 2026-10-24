# Experimental Docker setup

This stack defines frontend, backend, one scan worker, MySQL and ZAP services. A complete Docker build/run has **not** been verified for this source release. Use [Windows installation](INSTALL-WINDOWS.md) for the rehearsed starting point.

1. Install Docker Engine/Desktop and Compose from the vendor.
2. From the repository root run `python scripts/configure_local.py --docker`. It creates root `.env` with independent random keys/passwords and refuses to overwrite existing configuration.
3. Run `docker compose up --build -d`. The build downloads separate scanner components; review upstream licenses. Build output and resolved images are not shipped in the source package.
4. Create the first account: `docker compose exec backend flask --app app create-initial-admin`. No account is seeded.
5. Open `http://localhost:8088/login`. Frontend is bound to loopback; database and ZAP have no host port mapping. Only scan authorized targets. In containers, the host is reachable through `host.docker.internal`; `127.0.0.1` refers to each container.

Use `docker compose ps` and `docker compose logs backend worker frontend` to diagnose readiness. Initial schema creation and worker startup may wait for MySQL. Password recovery additionally requires SMTP variables and the actual `PUBLIC_APP_URL`; login does not depend on SMTP. The worker's scanner privileges do not make it safe to expose this as a public scanning service.

Stop with `docker compose down`. This preserves named volumes. **Do not use `down -v` unless you intend to destroy the database/reports volumes.** Preserve a database backup before updates. Changing a database password in `.env` does not rotate credentials inside an existing MySQL volume.

Local Windows encrypted backup commands and supervisor are not Docker backup/restore tooling. A full container-volume recovery requires a separate rehearsal. Image/runtime hardening, HTTPS, production cookie configuration, vulnerability scanning and end-to-end Docker validation remain release work. Docker has not been certified production-ready.
