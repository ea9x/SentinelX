from time_utils import iso_utc
import ipaddress
import re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Target, Scan, ScanJob, Vulnerability

targets_bp = Blueprint("targets", __name__)

def valid_hostname(value):
    if not value or len(value) > 100:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part)
                   for part in value.rstrip(".").split("."))

@targets_bp.route("/<int:target_id>", methods=["PUT"])
@targets_bp.route("/", methods=["POST"])
@jwt_required()
def add_target(target_id=None):
    owner = int(get_jwt_identity())
    target = Target.query.filter_by(id=target_id, added_by=owner, is_deleted=False).with_for_update().first() if target_id else None
    if target_id and not target:
        return jsonify({"error": "Target not found."}), 404
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    name = str(data.get("name") or "").strip()
    ip = str(data.get("ip_address") or "").strip()
    hostname = str(data.get("hostname") or "").strip()
    try:
        port = int(data.get("port", 80))
        if isinstance(data.get("port"), (bool, float)) or not 1 <= port <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({"error": "Port must be an integer between 1 and 65535."}), 400
    if not name or len(name) > 100:
        return jsonify({"error": "Target name must contain between 1 and 100 characters."}), 400
    if not ip and not hostname:
        return jsonify({"error": "An IP address or hostname is required."}), 400
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "Enter a valid IP address."}), 400
    if hostname and not valid_hostname(hostname):
        return jsonify({"error": "Enter a hostname without a scheme, path, or port."}), 400
    ip = str(ipaddress.ip_address(ip)) if ip else None
    hostname = hostname.lower().rstrip('.') or None
    candidates = Target.query.filter_by(added_by=owner, port=port, is_deleted=False).all()
    if any(item.id != target_id and ((hostname and (item.hostname or '').lower().rstrip('.') == hostname) or
           (ip and item.ip_address == ip)) for item in candidates):
        return jsonify({"error": "This address and port already exist in your targets."}), 409
    if target:
        changed = (target.ip_address, target.hostname, target.port) != (ip, hostname, port)
        if ScanJob.query.filter(ScanJob.target_id == target.id, ScanJob.status.in_(['queued','running'])).first():
            return jsonify({"error": "Wait for the active scan before editing this target."}), 409
        if changed and (Scan.query.filter_by(target_id=target.id).first() or ScanJob.query.filter_by(target_id=target.id).first()):
            return jsonify({"error": "Targets with scan history can be renamed only. Add a new target for a different address."}), 409
        target.name, target.ip_address, target.hostname, target.port = name, ip, hostname, port
    else:
        target = Target(name=name, ip_address=ip, hostname=hostname, port=port, added_by=owner, is_deleted=False)
        db.session.add(target)
    db.session.commit()
    return jsonify({"message": "Target updated successfully." if target_id else "Target added successfully.", "target": serialize(target)}), 200 if target_id else 201

def serialize(target):
    scans = Scan.query.filter_by(target_id=target.id).order_by(Scan.id.desc()).all()
    job = ScanJob.query.filter_by(target_id=target.id).order_by(ScanJob.created_at.desc()).first()
    latest = scans[0] if scans else None
    activity = {'status':latest.status,'tool':latest.tool_used,'date':iso_utc(latest.started_at)} if latest else None
    job_time = (job.finished_at or job.created_at) if job else None
    scan_time = (latest.finished_at or latest.started_at) if latest else None
    if job and (job.status in {'queued','running'} or not latest or job_time >= scan_time):
        activity = {'status':job.status,'tool':job.tool,'date':iso_utc(job.created_at),'job_id':job.id}
    counts = {key: 0 for key in ['Critical','High','Medium','Low','Info']}
    for finding in Vulnerability.query.filter_by(scan_id=latest.id).all() if latest else []:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {"id": target.id, "name": target.name, "ip_address": target.ip_address,
            "hostname": target.hostname, "port": target.port, "added_by": target.added_by,
            "has_history": bool(scans or job),
            "last_activity": activity,
            "last_scan": {"id": latest.id if latest else None,
                          "status": latest.status if latest else job.status,
                          "date": iso_utc(latest.started_at if latest else job.created_at),
                          "tool": latest.tool_used if latest else job.tool,
                          "findings": counts} if job or latest else None,
            "created_at": iso_utc(target.created_at) if target.created_at else None}

@targets_bp.route("/", methods=["GET"])
@jwt_required()
def get_targets():
    targets = Target.query.filter_by(added_by=int(get_jwt_identity()), is_deleted=False).order_by(Target.id.desc()).all()
    return jsonify([serialize(target) for target in targets]), 200

@targets_bp.route("/<int:target_id>", methods=["DELETE"])
@jwt_required()
def delete_target(target_id):
    target = Target.query.filter_by(id=target_id, added_by=int(get_jwt_identity()), is_deleted=False).first()
    if not target:
        return jsonify({"error": "Target not found."}), 404
    if ScanJob.query.filter(ScanJob.target_id == target.id, ScanJob.status.in_(['queued', 'running'])).first():
        return jsonify({"error": "Wait for the active scan before deleting this target."}), 409
    target.is_deleted = True
    db.session.commit()
    return jsonify({"message": "Target deleted successfully."}), 200


@targets_bp.route('/<int:target_id>/readiness', methods=['POST'])
@jwt_required()
def check_target_readiness(target_id):
    target=Target.query.filter_by(id=target_id,added_by=int(get_jwt_identity()),is_deleted=False).first()
    if not target: return jsonify(error='Target not found.'),404
    from readiness import inspect_target
    from routes.scans import _scanner_host
    return jsonify(inspect_target(_scanner_host(target),target.port or 80)),200
