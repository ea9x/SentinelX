"""Create tables and apply the backwards-compatible scan-output upgrade."""

from sqlalchemy import inspect, text
from models import db


def ensure_schema():
    db.create_all()
    if not any(column['name'] == 'is_deleted' for column in inspect(db.engine).get_columns('targets')):
        with db.engine.begin() as connection:
            connection.execute(text('ALTER TABLE targets ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0'))
    job_columns = inspect(db.engine).get_columns("scan_jobs")
    for name, definition in {'cancel_requested':'BOOLEAN NOT NULL DEFAULT 0', 'progress':'INTEGER NOT NULL DEFAULT 0',
                             'stage':"VARCHAR(80) NOT NULL DEFAULT 'Queued'"}.items():
        if not any(column['name']==name for column in job_columns):
            with db.engine.begin() as connection:
                connection.execute(text(f'ALTER TABLE scan_jobs ADD COLUMN {name} {definition}'))
    if not any(column['name'] == 'encrypted_options' for column in job_columns):
        with db.engine.begin() as connection:
            connection.execute(text('ALTER TABLE scan_jobs ADD COLUMN encrypted_options TEXT NULL'))
    with db.engine.begin() as connection:
        connection.execute(text("UPDATE scan_jobs SET stage=CASE WHEN status='completed' THEN 'Completed' WHEN status='cancelled' THEN 'Cancelled' ELSE 'Incomplete' END, progress=CASE WHEN status='completed' THEN 100 ELSE progress END WHERE stage='Queued' AND status IN ('completed','failed','partial','cancelled')"))
    if db.engine.dialect.name not in {"mysql", "mariadb"}:
        return
    columns = inspect(db.engine).get_columns("scans")
    output = next(column for column in columns if column["name"] == "raw_output")
    if str(output["type"]).upper() != "LONGTEXT":
        # Widen only this nullable column; retain every existing result.
        with db.engine.begin() as connection:
            connection.execute(text("ALTER TABLE scans MODIFY COLUMN raw_output LONGTEXT NULL"))
