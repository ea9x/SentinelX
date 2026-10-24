from time_utils import iso_utc
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Scan, Target, Vulnerability, FindingReview, Report
from finding_quality import finding_type, fingerprint, review_data, SEVERITY
from time_utils import utc_now

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
            "finding_type": finding_type(vulnerability),
            "fingerprint": fingerprint(vulnerability,target.id),
            **review_data(vulnerability),
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

    # Current exposure: latest completed run for each target/tool, excluding
    # suppressed manual decisions and informational observations. Historical rows remain available.
    scans=(Scan.query.join(Target,Scan.target_id==Target.id)
           .filter(Target.added_by==int(get_jwt_identity()),Target.is_deleted.is_(False)).order_by(Scan.id.desc()).all())
    latest={}
    for scan in scans:
        latest.setdefault((scan.target_id,scan.tool_used),scan)
    completed={}
    for scan in scans:
        if scan.status=='completed':completed.setdefault((scan.target_id,scan.tool_used),scan)
    current_ids={scan.id for scan in completed.values()}
    target_ids={scan.id:scan.target_id for scan in scans}
    groups={}
    for finding in vulns:
        if finding.scan_id not in current_ids or finding_type(finding)=='information' or finding.review_state in {'fixed','false_positive'} or finding.status in {'fixed','ignored'}: continue
        key=fingerprint(finding,target_ids[finding.scan_id])
        if key not in groups or SEVERITY.get(finding.severity,0)>SEVERITY.get(groups[key],0): groups[key]=finding.severity
    stats = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
    for severity in groups.values(): stats[severity]+=1
    incomplete=sum(scan.status!='completed' for scan in latest.values())
    return jsonify({'total':len(groups),'by_severity':stats,'record_total':len(vulns),
                    'information_records':sum(finding_type(item)=='information' for item in vulns),
                    'incomplete_latest_scans':incomplete,'scope':'last_completed_tool_scans'}),200


def owned_finding(finding_id):
    return (Vulnerability.query.join(Scan,Vulnerability.scan_id==Scan.id)
            .join(Target,Scan.target_id==Target.id)
            .filter(Vulnerability.id==finding_id,Target.added_by==int(get_jwt_identity())).first())

@vulnerabilities_bp.route('/<int:finding_id>/review',methods=['PUT'])
@jwt_required()
def review_finding(finding_id):
    finding=owned_finding(finding_id)
    if not finding:return jsonify(error='Finding not found.'),404
    data=request.get_json(silent=True)
    if not isinstance(data,dict):return jsonify(error='A JSON object is required.'),400
    state=data.get('review_state');note=data.get('review_note','');revision=data.get('review_revision')
    if not isinstance(state,str) or state not in {'confirmed','needs_review','false_positive','fixed'} or not isinstance(note,str) or len(note)>2000 or not isinstance(revision,int) or isinstance(revision,bool) or revision<0:
        return jsonify(error='Invalid review. Use a supported state, a note up to 2000 characters and the current revision.'),400
    if state in {'fixed','false_positive'} and not note.strip():
        return jsonify(error='A review note is required for fixed or false-positive findings.'),400
    previous=finding.review_state
    now=utc_now();reviewer=int(get_jwt_identity())
    changed=Vulnerability.query.filter_by(id=finding.id,review_revision=revision).update(
        {'review_state':state,'review_note':note.strip(),'review_revision':revision+1,'reviewed_by':reviewer,'reviewed_at':now,
         'status':'fixed' if state=='fixed' else 'ignored' if state=='false_positive' else 'open'},synchronize_session=False)
    if not changed:
        db.session.rollback();return jsonify(error='This finding was updated elsewhere. Reload before saving.'),409
    db.session.add(FindingReview(vulnerability_id=finding.id,reviewer_id=reviewer,previous_state=previous,
                                new_state=state,note=note.strip(),created_at=now))
    # Existing exported files are retained; a new download regenerates the report.
    Report.query.filter_by(scan_id=finding.scan_id).update({'file_path':None},synchronize_session=False)
    db.session.commit();db.session.refresh(finding)
    return jsonify({'id':finding.id,'status':finding.status,**review_data(finding)}),200

@vulnerabilities_bp.route('/<int:finding_id>/reviews',methods=['GET'])
@jwt_required()
def finding_reviews(finding_id):
    if not owned_finding(finding_id):return jsonify(error='Finding not found.'),404
    rows=FindingReview.query.filter_by(vulnerability_id=finding_id).order_by(FindingReview.id.desc()).all()
    return jsonify([{'id':item.id,'previous_state':item.previous_state,'review_state':item.new_state,
                     'review_note':item.note,'reviewed_by':item.reviewer_id,'reviewed_at':iso_utc(item.created_at)} for item in rows]),200
