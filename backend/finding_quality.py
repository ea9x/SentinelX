"""Conservative finding identities shared by grouping, comparison and risk totals."""
import hashlib
import json
import re
from urllib.parse import urlsplit

SEVERITY = {'Info':0,'Low':1,'Medium':2,'High':3,'Critical':4}

def finding_type(finding):
    title=(finding.title or '').strip().casefold()
    if finding.severity == 'Info' or finding.verification_status == 'informational' or title.startswith('open port:') or title == 'tls configuration summary' or finding.source_tool == 'whatweb':
        return 'information'
    return 'potential_vulnerability'

def fingerprint(finding, target_id):
    title=' '.join((finding.title or '').split()).casefold()
    identifier=(finding.cve_id or '').strip().upper()
    rule=identifier if re.fullmatch(r'CVE-\d{4}-\d{4,}',identifier) else title
    url=finding.affected_url or ''
    try:
        parsed=urlsplit(url)
        location=[parsed.scheme.lower(),parsed.hostname or '',parsed.port,parsed.path or '/',parsed.query]
    except ValueError:
        location=[url]
    path=finding.affected_path or ''
    port=finding.affected_port
    if not url and not path and port is None:
        # Do not merge records when the scanner supplied no usable location.
        location=['unknown',finding.id]
    identity=[target_id,rule,location,path,port,(finding.http_method or '').upper(),finding.parameter_name or '',finding_type(finding)]
    return hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()

def review_data(finding):
    from time_utils import iso_utc
    return {'review_state':finding.review_state or 'needs_review','review_note':finding.review_note or '',
            'review_revision':finding.review_revision or 0,'reviewed_by':finding.reviewed_by,
            'reviewed_at':iso_utc(finding.reviewed_at) if finding.reviewed_at else None}

def group_scan(findings,target_id,include_information=False):
    groups={}
    for finding in findings:
        category=finding_type(finding)
        if category == 'information' and not include_information: continue
        key=fingerprint(finding,target_id)
        if key not in groups:
            groups[key]={'fingerprint':key,'title':finding.title,'cve_id':finding.cve_id,
                         'severity':finding.severity,'finding_type':category,'location_complete':bool(finding.affected_url or finding.affected_path or finding.affected_port is not None),'occurrences':[]}
        group=groups[key]
        if SEVERITY.get(finding.severity,0)>SEVERITY.get(group['severity'],0): group['severity']=finding.severity
        group['occurrences'].append({'id':finding.id,'scan_id':finding.scan_id,'source_tool':finding.source_tool,
                                    'evidence':finding.evidence,'affected_url':finding.affected_url,
                                    'affected_path':finding.affected_path,**review_data(finding)})
    return groups
