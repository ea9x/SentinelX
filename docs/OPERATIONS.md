# Local operations

Run `start_local.ps1` from the project directory. It waits for MySQL, starts the backend and frontend when their ports are closed, and starts one Windows frontend/backend supervisor guarded by a filesystem lock. `register_startup.ps1` optionally registers the launcher for the current user's Windows sign-in. It does not create a cloud job or publish the application.

The supervisor checks frontend HTML identity, backend JSON identity and their ports every 10 seconds in healthy operation. After a restart it backs off, up to 60 seconds. It starts a replacement only if the corresponding port is closed. A listening but unresponsive/unrecognized service requires investigation; the supervisor never terminates it. Its rotating log is `.local/supervisor.log`.

To stop supervision before intentional maintenance:

```powershell
New-Item -ItemType File -Force .local/stop-supervisor
```

Wait up to 60 seconds for the supervisor's stop log entry, then stop only the identified SentinelX service processes using your normal process/service management. The next explicit `start_local.ps1` removes the stop flag. Do not stop the backend or frontend alone while supervision is active and expect it to remain stopped.

If login shows an unavailable-service message, check `.local/backend.log`, `.local/frontend.log`, `.local/maintenance.log`, and `.local/supervisor.log`. Validate ports 5000 and 8088 and the dedicated database. Never share raw logs without redaction. A 401 when calling `/api/auth/me` without cookies means the backend is reachable, not that login failed.

## Backups and updates

Wait for an idle queue, then run `start_local.ps1 -Action backup`. Preserve the encrypted archive and the separate `%LOCALAPPDATA%/SentinelX/backup.key` in private storage. `start_local.ps1 -Action verify -Archive PATH` restores into a temporary SQLite database and compares rows; it does not overwrite MySQL or restore all files into a live install. Rehearse full recovery separately before touching production.

Before updates preserve the source, build and backup. Stop supervision, ensure the queue is idle, update reviewed source, install dependency changes and rebuild the frontend. Restart through `start_local.ps1` so runtime lifetime does not depend on a temporary terminal tool. Reload existing browser tabs. Interrupted scans become failed; no automatic replay occurs.

## SQLite local trial

Guided setup can select a SQLite database in `.local/sentinelx.sqlite`. Startup then skips the MySQL-port wait; existing MySQL configurations keep the MySQL path. Do not delete or overwrite the database to update the app. Preserve its encrypted backup and key. Switching an existing database engine is not performed automatically by setup. SQLite trial checks do not certify concurrent workloads.
