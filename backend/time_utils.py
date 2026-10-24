"""Database timestamps remain UTC-naive; API timestamps carry an explicit UTC offset."""
from datetime import datetime, timezone

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def iso_utc(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value else None
