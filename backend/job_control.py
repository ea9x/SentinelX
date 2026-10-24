"""Independent queue updates must never commit in-flight scan findings."""
from flask import g, has_app_context
from sqlalchemy import text
from models import db


class ScanCancelled(Exception):
    pass


def cancellation_requested():
    if not has_app_context() or not getattr(g, 'scan_job_id', None): return False
    with db.engine.connect() as connection:
        return bool(connection.execute(text('SELECT cancel_requested FROM scan_jobs WHERE id=:id'),
                                       {'id':g.scan_job_id}).scalar())


def check_cancelled():
    if cancellation_requested(): raise ScanCancelled('The scan was cancelled by its owner.')


def progress(stage, percent):
    if not has_app_context() or not getattr(g, 'scan_job_id', None): return
    value=int(getattr(g,'progress_base',0)+max(0,min(100,percent))*getattr(g,'progress_span',100)/100)
    with db.engine.begin() as connection:
        connection.execute(text("UPDATE scan_jobs SET stage=:stage, progress=:progress WHERE id=:id AND status='running'"),
                           {'stage':stage[:80],'progress':min(99,value),'id':g.scan_job_id})
