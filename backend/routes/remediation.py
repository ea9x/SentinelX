"""Owner-scoped remediation tracking; assignee text never grants access."""
import json
import uuid
from datetime import date
from flask import Blueprint,request,jsonify
from flask_jwt_extended import jwt_required,get_jwt_identity
from sqlalchemy.exc import IntegrityError
from models import db,RemediationTask,RemediationUpdate,Vulnerability,Scan,Target,ScanJob
from finding_quality import finding_type,fingerprint,SEVERITY
from scan_options import validate_options,encrypt_options
from time_utils import utc_now,iso_utc

remediation_bp=Blueprint('remediation',__name__)
STATES={'planned','in_progress','ready_for_retest','completed'}

def owner():return int(get_jwt_identity())
def owned_finding(finding_id):
    return (Vulnerability.query.join(Scan,Vulnerability.scan_id==Scan.id).join(Target,Scan.target_id==Target.id)
            .filter(Vulnerability.id==finding_id,Target.added_by==owner()).first())
def serialize(task):
    finding=db.session.get(Vulnerability,task.finding_id);scan=db.session.get(Scan,finding.scan_id)
    target=db.session.get(Target,scan.target_id);job=db.session.get(ScanJob,task.last_job_id) if task.last_job_id else None
    result={}
    if job and job.result:
        try:result=json.loads(job.result)
        except (ValueError,TypeError):pass
    return {'id':task.id,'finding_id':finding.id,'title':finding.title,'severity':finding.severity,
            'review_state':finding.review_state,'baseline_scan_id':scan.id,'tool':scan.tool_used,
            'target_name':target.name,'target_deleted':bool(target.is_deleted),
            'assignee':task.assignee,'due_date':task.due_date.isoformat() if task.due_date else '',
            'notes':task.notes,'state':task.state,'revision':task.revision,
            'updated_at':iso_utc(task.updated_at),'last_job_id':task.last_job_id,
            'last_job_status':job.status if job else None,
            'comparison_scan_id':result.get('scan_id') if job and job.status=='completed' and isinstance(result,dict) else None}

def candidate_rows():
    scans=(Scan.query.join(Target,Scan.target_id==Target.id).filter(Target.added_by==owner(),Target.is_deleted.is_(False),Scan.status=='completed').order_by(Scan.id.desc()).all())
    latest={}
    for scan in scans:latest.setdefault((scan.target_id,scan.tool_used),scan.id)
    ids=set(latest.values())
    if not ids:return []
    rows=(db.session.query(Vulnerability,Scan,Target).join(Scan,Vulnerability.scan_id==Scan.id).join(Target,Scan.target_id==Target.id)
          .filter(Target.added_by==owner(),Scan.id.in_(ids)).order_by(Vulnerability.id.desc()).all())
    groups={}
    for finding,scan,target in rows:
        if finding_type(finding)=='information' or finding.review_state in {'fixed','false_positive'} or finding.status in {'fixed','ignored'}:continue
        key=fingerprint(finding,target.id)
        if key not in groups or SEVERITY[finding.severity]>SEVERITY[groups[key]['severity']]:
            groups[key]={'finding_id':finding.id,'title':finding.title,'severity':finding.severity,'review_state':finding.review_state,'scan_id':scan.id,'target_name':target.name}
    return sorted(groups.values(),key=lambda row:(-SEVERITY[row['severity']],row['review_state']!='confirmed',-row['finding_id']))

def changes(data,finding):
    assignee=data.get('assignee','');notes=data.get('notes','');state=data.get('state','planned');due=data.get('due_date')
    if not isinstance(assignee,str) or len(assignee)>100 or not isinstance(notes,str) or len(notes)>4000 or not isinstance(state,str) or state not in STATES:
        raise ValueError('Invalid task. Check the assignee, progress state and note length.')
    if due not in (None,''):
        if not isinstance(due,str):raise ValueError('Use a valid due date in YYYY-MM-DD format.')
        try:due=date.fromisoformat(due)
        except ValueError:raise ValueError('Use a valid due date in YYYY-MM-DD format.') from None
    else:due=None
    if state=='completed' and finding.review_state!='fixed':raise ValueError('Review the finding as fixed before completing its task.')
    return {'assignee':assignee.strip(),'notes':notes.strip(),'state':state,'due_date':due}

def log_update(task):
    db.session.add(RemediationUpdate(task_id=task.id,actor_id=owner(),state=task.state,assignee=task.assignee,due_date=task.due_date,notes=task.notes))

@remediation_bp.route('/',methods=['GET'])
@jwt_required()
def list_tasks():
    tasks=RemediationTask.query.filter_by(owner_id=owner()).order_by(RemediationTask.updated_at.desc()).all()
    return jsonify({'tasks':[serialize(task) for task in tasks],'candidates':candidate_rows()}),200

@remediation_bp.route('/',methods=['POST'])
@jwt_required()
def create_task():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or set(data)-{'finding_id','assignee','due_date','notes','state'}:return jsonify(error='Invalid task data.'),400
    finding_id=data.get('finding_id')
    if not isinstance(finding_id,int) or isinstance(finding_id,bool):return jsonify(error='Invalid finding ID.'),400
    finding=owned_finding(finding_id)
    if not finding:return jsonify(error='Finding not found.'),404
    try:values=changes(data,finding)
    except ValueError as error:return jsonify(error=str(error)),400
    task=RemediationTask(finding_id=finding.id,owner_id=owner(),**values)
    try:
        db.session.add(task);db.session.flush();log_update(task);db.session.commit()
    except IntegrityError:
        db.session.rollback();return jsonify(error='A task already exists for this occurrence.'),409
    return jsonify(serialize(task)),201

@remediation_bp.route('/<int:task_id>',methods=['PUT'])
@jwt_required()
def update_task(task_id):
    task=RemediationTask.query.filter_by(id=task_id,owner_id=owner()).with_for_update().first()
    if not task:return jsonify(error='Task not found.'),404
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or set(data)-{'assignee','due_date','notes','state','revision'}:return jsonify(error='Invalid task data.'),400
    revision=data.get('revision')
    if not isinstance(revision,int) or isinstance(revision,bool):return jsonify(error='Invalid task revision.'),400
    if revision!=task.revision:return jsonify(error='The task changed elsewhere. Reload before saving.'),409
    try:values=changes(data,db.session.get(Vulnerability,task.finding_id))
    except ValueError as error:return jsonify(error=str(error)),400
    for key,value in values.items():setattr(task,key,value)
    task.revision+=1;task.updated_at=utc_now();log_update(task);db.session.commit()
    return jsonify(serialize(task)),200

@remediation_bp.route('/<int:task_id>/history',methods=['GET'])
@jwt_required()
def task_history(task_id):
    if not RemediationTask.query.filter_by(id=task_id,owner_id=owner()).first():return jsonify(error='Task not found.'),404
    rows=RemediationUpdate.query.filter_by(task_id=task_id).order_by(RemediationUpdate.id.desc()).all()
    return jsonify([{'id':row.id,'actor_id':row.actor_id,'state':row.state,'assignee':row.assignee,'due_date':row.due_date.isoformat() if row.due_date else '', 'notes':row.notes,'created_at':iso_utc(row.created_at)} for row in rows]),200

@remediation_bp.route('/<int:task_id>/retest',methods=['POST'])
@jwt_required()
def retest_task(task_id):
    task=RemediationTask.query.filter_by(id=task_id,owner_id=owner()).with_for_update().first()
    if not task:return jsonify(error='Task not found.'),404
    finding=db.session.get(Vulnerability,task.finding_id);scan=db.session.get(Scan,finding.scan_id)
    target=db.session.get(Target,scan.target_id)
    if target.is_deleted:return jsonify(error='Restore or add a target before rescanning. This target is no longer active.'),409
    previous=db.session.get(ScanJob,task.last_job_id) if task.last_job_id else None
    if previous and previous.status in {'queued','running'}:return jsonify(serialize(task)),202
    if scan.tool_used not in {'nmap','zap','whatweb','nuclei','sslyze'}:return jsonify(error='This legacy tool is not supported for retesting.'),400
    try:
        body=request.get_json(silent=True)
        options=validate_options({} if body is None else body)
        if options and scan.tool_used!='zap':raise ValueError('Web scan options apply only to ZAP retests.')
    except (ValueError,TypeError) as error:return jsonify(error=str(error)),400
    pending=ScanJob.query.filter(ScanJob.status.in_(['queued','running']))
    if pending.filter_by(user_id=owner()).count()>=5 or pending.count()>=100:return jsonify(error='The scan queue is full. Try again after a scan finishes.'),429
    job=ScanJob(id=str(uuid.uuid4()),user_id=owner(),target_id=target.id,tool=scan.tool_used,encrypted_options=encrypt_options(options))
    db.session.add(job);db.session.flush();task.last_job_id=job.id;task.revision+=1;task.updated_at=utc_now();db.session.commit()
    return jsonify(serialize(task)),202
