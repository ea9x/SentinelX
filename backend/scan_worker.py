from time_utils import utc_now
"""One serial worker per SentinelX deployment; jobs survive HTTP requests and restarts."""
import json
import time
from datetime import datetime
from flask import g
from models import db, Scan, ScanJob, User
from routes.scans import SCAN_HANDLERS
from scan_options import decrypt_options
from job_control import ScanCancelled, cancellation_requested, progress


def recover_interrupted_jobs(app):
    with app.app_context():
        now = utc_now()
        for job in ScanJob.query.filter_by(status="running").all():
            job.status = "failed"
            job.stage = 'Interrupted'
            job.encrypted_options = None
            job.result = json.dumps({"error": "The scan worker restarted. Run the scan again."})
            job.response_status = 503
            job.finished_at = now
        for scan in Scan.query.filter_by(status="running").all():
            scan.status = "failed"
            scan.finished_at = now
            scan.raw_output = "The scan worker restarted before this scan completed."
        db.session.commit()


def process_next_job(app):
    with app.app_context():
        job = ScanJob.query.filter_by(status="queued").order_by(ScanJob.created_at, ScanJob.id).first()
        if not job:
            return False
        job_id, user_id, target_id, tool = job.id, job.user_id, job.target_id, job.tool
        claimed = ScanJob.query.filter_by(id=job_id, status="queued").update({"status": "running"})
        db.session.commit()
        if not claimed:
            return True
        g.scan_user_id = user_id
        g.scan_job_id = job_id
        g.scan_job_tool = tool
        try:
            progress('Starting', 0)
            g.web_scan_options = decrypt_options(job.encrypted_options)
            user = db.session.get(User, user_id)
            if not user or not user.is_active:
                payload, status = {"error": "This account is disabled or unavailable."}, 403
            else:
                response = app.make_response(SCAN_HANDLERS[tool](target_id))
                payload, status = response.get_json(), response.status_code
        except ScanCancelled:
            db.session.rollback()
            for scan in Scan.query.filter_by(target_id=target_id, status='running').all():
                scan.status='failed';scan.finished_at=utc_now();scan.raw_output='Cancelled by the scan owner.'
            payload, status = {'status':'cancelled','message':'The scan was cancelled. Completed results remain in scan history.'}, 409
        except Exception:
            db.session.rollback()
            app.logger.exception("Scan job %s failed", job_id)
            # Unexpected parser failures must not leave a scan running forever.
            for scan in Scan.query.filter_by(target_id=target_id, status="running").all():
                scan.status = "failed"
                scan.finished_at = utc_now()
                scan.raw_output = "The scan failed unexpectedly. Check the worker log."
            payload, status = {"error": "The scan failed unexpectedly. Check the worker log."}, 500
        cancelled = cancellation_requested()
        job = db.session.get(ScanJob, job_id)
        db.session.refresh(job, ['cancel_requested'])
        job.encrypted_options = None
        job.result = json.dumps(payload)
        job.response_status = status
        job.status = 'cancelled' if cancelled else payload['status'] if payload.get('status') in {'partial','failed'} else "completed" if status < 400 else "failed"
        job.stage = 'Cancelled' if cancelled else 'Incomplete' if job.status in {'partial','failed'} else 'Completed'
        if job.status=='completed': job.progress=100
        job.finished_at = utc_now()
        db.session.commit()
        return True


def run_worker(app):
    recover_interrupted_jobs(app)
    while True:
        try:
            if not process_next_job(app):
                time.sleep(1)
        except Exception:
            app.logger.exception("Scan worker could not access the queue")
            time.sleep(3)


if __name__ == "__main__":
    from app import app
    from docker_entrypoint import wait_for_database
    wait_for_database()
    run_worker(app)
