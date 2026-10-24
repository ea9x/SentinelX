import os
import time

from sqlalchemy import text

from app import app
from models import db
from schema import ensure_schema


def wait_for_database():
    attempts = int(os.getenv("DB_STARTUP_ATTEMPTS", "60"))

    for attempt in range(1, attempts + 1):
        try:
            with app.app_context():
                db.session.execute(text("SELECT 1"))
                ensure_schema()
            print("SentinelX database is ready.", flush=True)
            return
        except Exception as error:
            if attempt == attempts:
                raise
            print(
                f"Waiting for MySQL ({attempt}/{attempts}): {error}",
                flush=True,
            )
            time.sleep(2)


if __name__ == "__main__":
    wait_for_database()
