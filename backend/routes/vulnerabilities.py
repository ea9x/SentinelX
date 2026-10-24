from time_utils import iso_utc
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Scan, Target, Vulnerability

vulnerabilities_bp = Blueprint('vulnerabilities', __name__)


@vulnerabilities_bp.route('/', methods=['GET'])
@jwt_required()
def get_all_vulnerabilities():
    rows = (
        Vulnerability.query
        .join(Scan, Vulnerability.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.added_by == int(get_jwt_identity()))
        .order_by(Vulnerability.created_at.desc(), Vulnerability.id.desc())
        .with_entities(Vulnerability, Scan, Target)
        .all()
    )

    result = []
    for vulnerability, scan, target in rows:
        result.append({
            "id": vulnerability.id,
            "scan_id": vulnerability.scan_id,
            "cve_id": vulnerability.cve_id,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "description": vulnerability.description,
            "ai_recommendation": vulnerability.ai_recommendation,
            "status": vulnerability.status,
            "affected_url": vulnerability.affected_url,
            "affected_path": vulnerability.affected_path,
            "affected_port": vulnerability.affected_port,
            "http_method": vulnerability.http_method,
            "parameter_name": vulnerability.parameter_name,
            "evidence": vulnerability.evidence,
            "source_tool": vulnerability.source_tool or scan.tool_used,
            "confidence": vulnerability.confidence or "Medium",
            "verification_status": (
                vulnerability.verification_status or "needs_review"
            ),
            "created_at": (
                iso_utc(vulnerability.created_at)
                if vulnerability.created_at else None
            ),
            "tool_used": scan.tool_used,
            "target": {
                "id": target.id,
                "name": target.name,
                "ip_address": target.ip_address,
                "hostname": target.hostname,
            },
        })

    return jsonify(result), 200


@vulnerabilities_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_vulnerability_stats():
    """
    Statistics for the dashboard charts.
    """
    vulns = (Vulnerability.query.join(Scan, Vulnerability.scan_id == Scan.id)
             .join(Target, Scan.target_id == Target.id)
             .filter(Target.added_by == int(get_jwt_identity())).all())

    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        if v.severity in stats:
            stats[v.severity] += 1

    return jsonify({
        "total": len(vulns),
        "by_severity": stats
    }), 200
