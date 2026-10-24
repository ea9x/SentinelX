from time_utils import iso_utc
from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required

from models import Report, Scan, Target, Vulnerability, db
from report_generator import REPORTS_DIRECTORY, generate_scan_report


reports_bp = Blueprint("reports", __name__)


def _current_user_id():
    return int(get_jwt_identity())


def _get_user_scan(scan_id):
    return (
        Scan.query
        .join(Target, Scan.target_id == Target.id)
        .filter(
            Scan.id == scan_id,
            Target.added_by == _current_user_id(),
        )
        .first()
    )


@reports_bp.route("/", methods=["GET"])
@jwt_required()
def get_reports():
    rows = (
        db.session.query(Report, Scan, Target)
        .join(Scan, Report.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(
            Report.generated_by == _current_user_id(),
            Target.added_by == _current_user_id(),
        )
        .order_by(Report.created_at.desc(), Report.id.desc())
        .all()
    )

    return jsonify(
        [
            {
                "id": report.id,
                "scan_id": scan.id,
                "tool_used": scan.tool_used,
                "scan_status": scan.status,
                "target": {
                    "id": target.id,
                    "name": target.name,
                    "ip_address": target.ip_address,
                    "hostname": target.hostname,
                },
                "file_path": report.file_path,
                "created_at": (
                    iso_utc(report.created_at)
                    if report.created_at
                    else None
                ),
            }
            for report, scan, target in rows
        ]
    ), 200


@reports_bp.route("/", methods=["POST"])
@jwt_required()
def create_report():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    scan_id = data.get("scan_id")

    if not scan_id:
        return jsonify({"error": "scan_id is required."}), 400

    scan = _get_user_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404

    report = Report(
        scan_id=scan.id,
        generated_by=_current_user_id(),
        file_path=None,
    )
    db.session.add(report)
    db.session.commit()

    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()

    try:
        output_path = generate_scan_report(
            report,
            scan,
            scan.target if hasattr(scan, "target") else db.session.get(Target, scan.target_id),
            vulnerabilities,
        )
        report.file_path = str(output_path.relative_to(REPORTS_DIRECTORY.parent))
        report.format_version = 2
        db.session.commit()
    except Exception as error:
        db.session.delete(report)
        db.session.commit()
        return jsonify(
            {
                "error": "The PDF report could not be generated.",
                "details": "Report generation failed. Check the server logs.",
            }
        ), 500

    return jsonify(
        {
            "message": "Report export registered successfully.",
            "report": {
                "id": report.id,
                "scan_id": report.scan_id,
                "created_at": (
                    iso_utc(report.created_at)
                    if report.created_at
                    else None
                ),
                "download_url": f"/api/reports/{report.id}/download",
            },
        }
    ), 201


@reports_bp.route("/<int:report_id>/download", methods=["GET"])
@jwt_required()
def download_report(report_id):
    row = (
        db.session.query(Report, Scan, Target)
        .join(Scan, Report.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .filter(
            Report.id == report_id,
            Report.generated_by == _current_user_id(),
            Target.added_by == _current_user_id(),
        )
        .first()
    )

    if not row:
        return jsonify({"error": "Report not found."}), 404

    report, scan, target = row

    # Older report records may not have a PDF file yet. Generate it lazily so
    # existing records remain useful after enabling server-side PDF exports.
    if not report.file_path or report.format_version != 2:
        try:
            vulnerabilities = Vulnerability.query.filter_by(scan_id=scan.id).all()
            output_path = generate_scan_report(
                report,
                scan,
                target,
                vulnerabilities,
            )
            report.file_path = str(
                output_path.relative_to(REPORTS_DIRECTORY.parent)
            )
            report.format_version = 2
            db.session.commit()
        except Exception as error:
            db.session.rollback()
            return jsonify(
                {
                    "error": "The PDF report could not be generated.",
                    "details": "Report generation failed. Check the server logs.",
                }
            ), 500

    file_path = (REPORTS_DIRECTORY.parent / report.file_path).resolve()
    reports_root = REPORTS_DIRECTORY.resolve()

    if reports_root not in file_path.parents or not file_path.is_file():
        return jsonify({"error": "Report file not found."}), 404

    return send_file(
        file_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=file_path.name,
    )


@reports_bp.route("/<int:report_id>", methods=["DELETE"])
@jwt_required()
def delete_report(report_id):
    report = Report.query.filter_by(
        id=report_id,
        generated_by=_current_user_id(),
    ).first()

    if not report:
        return jsonify({"error": "Report not found."}), 404

    if report.file_path:
        file_path = (REPORTS_DIRECTORY.parent / report.file_path).resolve()
        reports_root = REPORTS_DIRECTORY.resolve()
        if reports_root in file_path.parents and file_path.is_file():
            file_path.unlink()

    db.session.delete(report)
    db.session.commit()
    return jsonify({"message": "Report record deleted successfully."}), 200
