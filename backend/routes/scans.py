from time_utils import iso_utc
from time_utils import utc_now
from datetime import datetime
import os
import re
import json
import uuid

from flask import Blueprint, jsonify, g, request
from finding_quality import finding_type, fingerprint, review_data, SEVERITY
from scan_options import validate_options, encrypt_options
from job_control import check_cancelled, progress
from flask_jwt_extended import (
    get_jwt_identity,
    jwt_required,
)

from models import (
    db,
    Scan,
    Target,
    Vulnerability,
    ScanJob,
)

from scanners.nmap_scanner import run_nmap_scan
from scanners.whatweb_scanner import run_whatweb_scan
from scanners.zap_scanner import run_zap_scan
from scanners.nuclei_scanner import run_nuclei_scan
from scanners.sslyze_scanner import run_sslyze_scan


scans_bp = Blueprint(
    "scans",
    __name__,
)


PORT_RISK_MAP = {
    "21": (
        "High",
        "Disable plain FTP or replace it with SFTP.",
    ),
    "22": (
        "Low",
        "Restrict SSH access and use secure authentication keys.",
    ),
    "23": (
        "Critical",
        "Disable Telnet immediately and use SSH instead.",
    ),
    "445": (
        "High",
        "Restrict SMB access and ensure the operating system is updated.",
    ),
    "3306": (
        "Medium",
        "Restrict direct remote access to the MySQL service.",
    ),
    "3389": (
        "High",
        "Restrict RDP access and protect it against brute-force attacks.",
    ),
}


DEFAULT_PORT_RISK = (
    "Info",
    "Review whether this port needs to remain accessible.",
)


def _serialize_datetime(value):
    if not value:
        return None

    return iso_utc(value)


def _current_user_id():
    return int(g.scan_user_id) if hasattr(g, "scan_user_id") else int(get_jwt_identity())


def _get_owned_target(target_id):
    return Target.query.filter_by(
        id=target_id,
        added_by=_current_user_id(),
        is_deleted=False,
    ).first()


def _target_host(target):
    return (
        target.ip_address
        or target.hostname
    )


def _target_url(target):
    host = _target_host(target)
    port = target.port or 80

    scheme = (
        "https"
        if int(port) == 443
        else "http"
    )

    return f"{scheme}://{"[" + host + "]" if ":" in host else host}:{port}"


def _scanner_host(target):
    host = _target_host(target)

    if (
        os.getenv("RUNNING_IN_DOCKER", "false").lower() == "true"
        and host in {"127.0.0.1", "localhost", "::1"}
    ):
        return "host.docker.internal"

    return host


def _scanner_url(target):
    host = _scanner_host(target)
    port = target.port or 80
    readiness = _service_readiness(target)
    scheme = "https" if readiness.get('tls') else "http" if readiness.get('http') else "https" if int(port) == 443 else "http"
    return f"{scheme}://{"[" + host + "]" if ":" in host else host}:{port}"


def _service_readiness(target):
    """Cache only within this HTTP request/job; never reuse stale service checks."""
    from readiness import inspect_target
    cache = getattr(g, 'service_readiness', None)
    if cache is None:
        cache = g.service_readiness = {}
    key = (_scanner_host(target), target.port or 80)
    if key not in cache:
        check_cancelled()
        try:
            cache[key] = inspect_target(*key)
        except (OSError, ValueError):
            cache[key] = {'tcp_open':None, 'http':None, 'tls':None, 'service':'unknown',
                          'message':'Service detection was unavailable. Scan coverage requires review.'}
    return cache[key]


def _start_scan(target, tool):
    check_cancelled()
    if getattr(g, 'scan_job_tool', None)=='full':
        g.progress_base={'nmap':0,'whatweb':20,'zap':40,'nuclei':60,'sslyze':80}.get(tool,0)
        g.progress_span=20
    else:
        g.progress_base=0;g.progress_span=100
    progress(f'Running {tool.upper()}',0)
    scan = Scan(
        target_id=target.id,
        tool_used=tool,
        status="running",
        started_at=utc_now(),
    )

    db.session.add(scan)
    db.session.commit()

    return scan


def _complete_scan(scan, raw_output):
    scan.status = "completed"
    scan.raw_output = raw_output
    scan.finished_at = utc_now()

    db.session.commit()


def _public_scan_error(result):
    error = str(result.get('error') or 'The scanner failed.')
    lower = error.lower()
    if any(value in lower for value in ['actively refused', 'connection refused', 'serverrejectedconnection', 'server rejected the connection']):
        return 'The target refused the connection. Check that the service is running on the configured port. TLS scans require a TLS-enabled port, usually 443.'
    if any(value in lower for value in ['timed out', 'timeout']):
        return 'The connection or scan timed out. Check target availability and firewall settings.'
    if any(value in lower for value in ['getaddrinfo', 'name or service not known', 'unable to resolve', 'name resolution']):
        return 'The hostname could not be resolved. Check the hostname and DNS settings.'
    if any(value in lower for value in ['traceback', 'connectivity_error_trace', 'file "', 'ssl handshake', 'tls handshake', 'wrong version number']):
        return 'The TLS scan could not complete. Verify that this port supports TLS; HTTPS usually uses port 443.'
    return error


def _scanner_failure_details(result):
    sections = [str(result.get("error") or "The scanner failed.")]
    for key in ("stderr", "raw_output"):
        if result.get(key):
            sections.append(f"{key}:\n{result[key]}")
    # MySQL TEXT has a byte limit. Keep useful failure evidence without overflow.
    return "\n\n".join(sections).encode("utf-8")[:60000].decode("utf-8", errors="ignore")


def _fail_scan(scan, error):
    scan.status = "failed"
    scan.raw_output = str(error or "")
    scan.finished_at = utc_now()

    db.session.commit()


def _parse_nmap_output(raw_output):
    ports = []

    for line in (raw_output or "").splitlines():
        match = re.match(
            r"^\s*(\d+)\/(tcp|udp)\s+open\s+"
            r"(\S+)(?:\s+(.*))?$",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        port, protocol, service, version = (
            match.groups()
        )

        ports.append(
            {
                "port": int(port),
                "protocol": protocol.lower(),
                "service": service,
                "version": (
                    (version or "").strip()
                    or None
                ),
                "state": "open",
            }
        )

    return ports


def _normalize_confidence(finding, tool_used):
    value = str(finding.get("confidence") or "").strip().lower()

    if "high" in value or value in {"3", "confirmed", "certain"}:
        return "High"
    if "low" in value or value in {"1", "tentative"}:
        return "Low"
    if "medium" in value or value in {"2", "moderate"}:
        return "Medium"

    tool = str(finding.get("source_tool") or tool_used or "").lower()
    evidence = str(finding.get("evidence") or "").strip()

    if tool in {"nmap", "sslyze"} and evidence:
        return "High"
    if tool in {"zap", "nuclei", "whatweb"}:
        return "Medium"
    return "Low"


def _verification_status(finding):
    supplied = str(finding.get("verification_status") or "").strip().lower()
    allowed = {"confirmed", "needs_review", "informational", "false_positive"}
    if supplied in allowed:
        return supplied
    if str(finding.get("severity") or "Info").lower() == "info":
        return "informational"
    return "needs_review"


def _finding_risk_score(severity, confidence):
    severity_score = {
        "Critical": 10.0,
        "High": 8.0,
        "Medium": 5.5,
        "Low": 3.0,
        "Info": 1.0,
    }.get(severity or "Info", 1.0)
    confidence_weight = {
        "High": 1.0,
        "Medium": 0.85,
        "Low": 0.65,
    }.get(confidence or "Medium", 0.85)
    return round(severity_score * confidence_weight, 1)


def _finding_identity(scan, finding):
    values = (
        scan.id,
        finding.get("title"),
        finding.get("cve_id"),
        finding.get("affected_url"),
        finding.get("affected_path"),
        finding.get("affected_port"),
        finding.get("http_method"),
        finding.get("parameter_name"),
        finding.get("source_tool") or scan.tool_used,
    )
    return tuple(str(value or "").strip().lower() for value in values)


def _save_finding(scan, finding):
    vulnerability = Vulnerability(
        scan_id=scan.id,
        cve_id=finding.get("cve_id"),
        title=finding.get(
            "title",
            "Security Finding",
        ),
        severity=finding.get(
            "severity",
            "Info",
        ),
        description=finding.get(
            "description",
        ),
        ai_recommendation=finding.get(
            "recommendation",
        ),
        status="open",

        affected_url=finding.get(
            "affected_url",
        ),
        affected_path=finding.get(
            "affected_path",
        ),
        affected_port=finding.get(
            "affected_port",
        ),
        http_method=finding.get(
            "http_method",
        ),
        parameter_name=finding.get(
            "parameter_name",
        ),
        evidence=finding.get(
            "evidence",
        ),
        source_tool=finding.get(
            "source_tool",
            scan.tool_used,
        ),
        confidence=_normalize_confidence(
            finding,
            scan.tool_used,
        ),
        verification_status=_verification_status(finding),
    )

    db.session.add(vulnerability)
    return vulnerability


def _save_findings(scan, findings):
    saved = []
    seen = set()

    for finding in findings:
        identity = _finding_identity(scan, finding)
        if identity in seen:
            # Duplicate scanner output is ignored, while the same finding on
            # another URL, path, port, method, or parameter remains visible.
            continue
        seen.add(identity)
        saved.append(_save_finding(scan, finding))

    db.session.flush()
    return saved


def _nmap_findings(
    target,
    open_ports,
):
    findings = []

    for port_info in open_ports:
        port = str(
            port_info.get("port")
        )

        protocol = port_info.get(
            "protocol",
            "tcp",
        )

        service = port_info.get(
            "service",
            "unknown",
        )

        version = port_info.get(
            "version",
        )

        severity, recommendation = (
            PORT_RISK_MAP.get(
                port,
                DEFAULT_PORT_RISK,
            )
        )

        evidence_parts = [
            f"Service: {service}",
        ]

        if version:
            evidence_parts.append(
                f"Version: {version}"
            )

        findings.append(
            {
                "cve_id": None,
                "title": (
                    f"Open Port: "
                    f"{port}/{protocol} "
                    f"({service})"
                ),
                "severity": severity,
                "description": (
                    f"The {service} service was "
                    f"detected on port {port}/"
                    f"{protocol} on {target.name}."
                ),
                "recommendation": recommendation,
                "affected_url": (
                    f"{protocol}://"
                    f"{target.ip_address}:"
                    f"{port}"
                ),
                "affected_path": None,
                "affected_port": int(port),
                "http_method": None,
                "parameter_name": None,
                "evidence": " | ".join(
                    evidence_parts
                ),
                "source_tool": "nmap",
            }
        )

    return findings


def _whatweb_findings(
    target,
    technologies,
):
    target_url = _scanner_url(target)

    findings = []

    for technology in technologies:
        name = technology.get(
            "technology",
            "Unknown Technology",
        )

        details = technology.get(
            "details",
            "No details are available.",
        )

        findings.append(
            {
                "cve_id": None,
                "title": (
                    f"Detected Technology: {name}"
                ),
                "severity": "Info",
                "description": (
                    f"WhatWeb detected {name}. "
                    f"Details: {details}"
                ),
                "recommendation": (
                    "Verify that the detected "
                    "technology is updated and "
                    "securely configured."
                ),
                "affected_url": target_url,
                "affected_path": "/",
                "affected_port": (
                    target.port or 80
                ),
                "http_method": "GET",
                "parameter_name": None,
                "evidence": str(details),
                "source_tool": "whatweb",
            }
        )

    return findings


def _scan_response(
    message,
    scan,
    target,
    saved,
):
    return jsonify(
        {
            "message": message,
            "scan_id": scan.id,
            "target": target.name,
            "vulnerabilities_found": len(saved),
            "vulnerabilities": [
                {
                    "id": vulnerability.id,
                "finding_type": finding_type(vulnerability),
                "fingerprint": fingerprint(vulnerability,target.id),
                **review_data(vulnerability),
                    "title": vulnerability.title,
                    "severity": (
                        vulnerability.severity
                    ),
                    "cve_id": (
                        vulnerability.cve_id
                    ),
                    "recommendation": (
                        vulnerability
                        .ai_recommendation
                    ),
                    "affected_url": (
                        vulnerability
                        .affected_url
                    ),
                    "affected_path": (
                        vulnerability
                        .affected_path
                    ),
                    "affected_port": (
                        vulnerability
                        .affected_port
                    ),
                    "http_method": (
                        vulnerability
                        .http_method
                    ),
                    "parameter_name": (
                        vulnerability
                        .parameter_name
                    ),
                    "evidence": (
                        vulnerability
                        .evidence
                    ),
                    "source_tool": (
                        vulnerability
                        .source_tool
                    ),
                }
                for vulnerability in saved
            ],
        }
    ), 200


def execute_nmap(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    if not _target_host(target):
        return jsonify(
            {
                "error": (
                    "The target has no IP address or hostname."
                ),
            }
        ), 400

    scan = _start_scan(
        target,
        "nmap",
    )

    result = run_nmap_scan(
        _scanner_host(target), target.port
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return jsonify(
            {
                "error": "The Nmap scan failed.",
                "details": _public_scan_error(result),
                "scan_id": scan.id,
            }
        ), 500


    findings = _nmap_findings(
        target,
        result.get("open_ports", []),
    )

    saved = _save_findings(
        scan,
        findings,
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return _scan_response(
        "Nmap scan completed successfully.",
        scan,
        target,
        saved,
    )


def execute_whatweb(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    if not _target_host(target):
        return jsonify(
            {
                "error": (
                    "The target has no IP address "
                    "or hostname."
                ),
            }
        ), 400

    target_url = _scanner_url(target)

    scan = _start_scan(
        target,
        "whatweb",
    )

    result = run_whatweb_scan(
        target_url
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return jsonify(
            {
                "error": (
                    "The WhatWeb scan failed."
                ),
                "details": _public_scan_error(result),
                "scan_id": scan.id,
            }
        ), 500


    findings = _whatweb_findings(
        target,
        result.get("technologies", []),
    )

    saved = _save_findings(
        scan,
        findings,
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return _scan_response(
        "WhatWeb scan completed successfully.",
        scan,
        target,
        saved,
    )


def execute_zap(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    if not _target_host(target):
        return jsonify(
            {
                "error": (
                    "The target has no IP address "
                    "or hostname."
                ),
            }
        ), 400

    target_url = _scanner_url(target)

    scan = _start_scan(
        target,
        "zap",
    )

    result = run_zap_scan(
        target_url
    )

    if not result.get("success"):
        partial = _save_findings(scan, result.get('vulnerabilities', []))
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return jsonify(
            {
                "error": "The ZAP scan did not complete. Partial findings are available in scan history.",
                "vulnerabilities_found": len(partial),
                "details": _public_scan_error(result),
                "scan_id": scan.id,
            }
        ), 500


    saved = _save_findings(
        scan,
        result.get(
            "vulnerabilities",
            [],
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return _scan_response(
        "ZAP scan completed successfully.",
        scan,
        target,
        saved,
    )


def execute_nuclei(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    if not _target_host(target):
        return jsonify(
            {
                "error": (
                    "The target has no IP address "
                    "or hostname."
                ),
            }
        ), 400

    target_url = _scanner_url(target)

    scan = _start_scan(
        target,
        "nuclei",
    )

    result = run_nuclei_scan(
        target_url
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return jsonify(
            {
                "error": (
                    "The Nuclei scan failed."
                ),
                "details": _public_scan_error(result),
                "scan_id": scan.id,
            }
        ), 500


    saved = _save_findings(
        scan,
        result.get(
            "vulnerabilities",
            [],
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return _scan_response(
        "Nuclei scan completed successfully.",
        scan,
        target,
        saved,
    )


def execute_sslyze(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    host = _scanner_host(target)

    if not host:
        return jsonify(
            {
                "error": (
                    "The target has no IP address "
                    "or hostname."
                ),
            }
        ), 400

    port = target.port or 443

    scan = _start_scan(
        target,
        "sslyze",
    )

    result = run_sslyze_scan(
        host,
        port,
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return jsonify(
            {
                "error": "The SSLyze scan failed.",
                "details": _public_scan_error(result),
                "scan_id": scan.id,
            }
        ), 500


    saved = _save_findings(
        scan,
        result.get(
            "vulnerabilities",
            [],
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return _scan_response(
        "SSLyze scan completed successfully.",
        scan,
        target,
        saved,
    )


def _run_full_nmap(target):
    if not _target_host(target):
        return {
            "status": "skipped",
            "reason": (
                "The target has no IP address or hostname."
            ),
        }, 0

    scan = _start_scan(
        target,
        "nmap",
    )

    result = run_nmap_scan(
        _scanner_host(target), target.port
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return {
            "status": "failed",
            "scan_id": scan.id,
            "error": _public_scan_error(result),
        }, 0


    saved = _save_findings(
        scan,
        _nmap_findings(
            target,
            result.get("open_ports", []),
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return {
        "status": "completed",
        "scan_id": scan.id,
        "found": len(saved),
    }, len(saved)


def _run_full_whatweb(target):
    scan = _start_scan(
        target,
        "whatweb",
    )

    result = run_whatweb_scan(
        _scanner_url(target)
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return {
            "status": "failed",
            "scan_id": scan.id,
            "error": _public_scan_error(result),
        }, 0


    saved = _save_findings(
        scan,
        _whatweb_findings(
            target,
            result.get("technologies", []),
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return {
        "status": "completed",
        "scan_id": scan.id,
        "found": len(saved),
    }, len(saved)


def _run_full_zap(target):
    scan = _start_scan(
        target,
        "zap",
    )

    result = run_zap_scan(
        _scanner_url(target)
    )

    if not result.get("success"):
        partial = _save_findings(scan, result.get('vulnerabilities', []))
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return {
            "status": "failed",
            "scan_id": scan.id,
            "error": _public_scan_error(result),
            "found": len(partial),
        }, len(partial)


    saved = _save_findings(
        scan,
        result.get(
            "vulnerabilities",
            [],
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return {
        "status": "completed",
        "scan_id": scan.id,
        "found": len(saved),
    }, len(saved)


def _run_full_nuclei(target):
    scan = _start_scan(
        target,
        "nuclei",
    )

    result = run_nuclei_scan(
        _scanner_url(target)
    )

    if not result.get("success"):
        _fail_scan(
            scan,
            _scanner_failure_details(result),
        )

        return {
            "status": "failed",
            "scan_id": scan.id,
            "error": _public_scan_error(result),
        }, 0


    saved = _save_findings(
        scan,
        result.get(
            "vulnerabilities",
            [],
        ),
    )

    _complete_scan(
        scan,
        result.get("raw_output"),
    )

    return {
        "status": "completed",
        "scan_id": scan.id,
        "found": len(saved),
    }, len(saved)


def _run_full_sslyze(target):
    scan = _start_scan(target, "sslyze")
    result = run_sslyze_scan(_scanner_host(target), target.port or 443)
    if not result.get("success"):
        _fail_scan(scan, _scanner_failure_details(result))
        return {"status": "failed", "scan_id": scan.id, "error": _public_scan_error(result)}, 0
    saved = _save_findings(scan, result.get("vulnerabilities", []))
    _complete_scan(scan, result.get("raw_output"))
    return {"status": "completed", "scan_id": scan.id, "found": len(saved)}, len(saved)


def execute_full(target_id):
    target = _get_owned_target(target_id)

    if not target:
        return jsonify(
            {
                "error": "Target not found.",
            }
        ), 404

    if not _target_host(target):
        return jsonify(
            {
                "error": (
                    "The target has no IP address "
                    "or hostname."
                ),
            }
        ), 400

    tools = {}
    total_findings = 0
    readiness = _service_readiness(target)
    handlers = {'nmap':_run_full_nmap,'whatweb':_run_full_whatweb,'zap':_run_full_zap,
                'nuclei':_run_full_nuclei,'sslyze':_run_full_sslyze}
    for name, handler in handlers.items():
        check_cancelled()
        reason = None
        if name != 'nmap':
            if readiness.get('tcp_open') is False:
                reason = 'The target port was unreachable during readiness checks. This tool did not run.'
            elif name == 'sslyze' and readiness.get('tls') is False:
                reason = 'TLS was not confirmed on this port. TLS checks did not run.'
            elif name in {'whatweb','zap','nuclei'} and readiness.get('http') is False:
                reason = 'HTTP or HTTPS was not confirmed on this port. Web checks did not run.'
        if reason:
            tools[name] = {'status':'skipped','reason':reason}
            continue
        summary, count = handler(target)
        tools[name] = summary
        total_findings += count

    failed_tools = [name for name, result in tools.items() if result["status"] == "failed"]
    completed_tools = [name for name, result in tools.items() if result["status"] == "completed"]
    skipped_tools = [name for name, result in tools.items() if result['status'] == 'skipped']
    status = 'partial' if completed_tools and (failed_tools or skipped_tools) else 'failed' if failed_tools or skipped_tools else 'completed'

    return jsonify(
        {
            "status": status,
            "failed_tools": failed_tools,
            "skipped_tools": skipped_tools,
            "readiness": readiness,
            "coverage_complete": status == 'completed',
            "message": "Full scan completed." if status == "completed" else "Full scan did not complete successfully.",
            "target": target.name,
            "total_vulnerabilities_found": (
                total_findings
            ),
            "tools": tools,
        }
    ), 200


@scans_bp.route(
    "/",
    methods=["GET"],
)
@jwt_required()
def get_all_scans():
    scans = (
        Scan.query
        .join(Target, Scan.target_id == Target.id)
        .filter(Target.added_by == _current_user_id())
        .order_by(Scan.id.desc())
        .all()
    )

    result = []

    for scan in scans:
        target = db.session.get(
            Target,
            scan.target_id,
        )

        result.append(
            {
                "id": scan.id,
                "target_id": scan.target_id,
                "target_name": (
                    target.name
                    if target
                    else "Unknown Target"
                ),
                "target_ip": (
                    target.ip_address
                    if target
                    else None
                ),
                "tool_used": scan.tool_used,
                "status": scan.status,
                "started_at": (
                    _serialize_datetime(
                        scan.started_at
                    )
                ),
                "finished_at": (
                    _serialize_datetime(
                        scan.finished_at
                    )
                ),
            }
        )

    return jsonify(result), 200


@scans_bp.route(
    "/<int:scan_id>",
    methods=["GET"],
)
@jwt_required()
def get_scan_details(scan_id):
    user_id = _current_user_id()

    scan = (
        Scan.query
        .join(
            Target,
            Scan.target_id == Target.id,
        )
        .filter(
            Scan.id == scan_id,
            Target.added_by == user_id,
        )
        .first()
    )

    if not scan:
        return jsonify(
            {
                "error": "Scan not found.",
            }
        ), 404

    target = db.session.get(
        Target,
        scan.target_id,
    )

    vulnerabilities = (
        Vulnerability.query
        .filter_by(scan_id=scan.id)
        .order_by(Vulnerability.id.asc())
        .all()
    )

    if scan.tool_used == "nmap":
        ports = _parse_nmap_output(
            scan.raw_output
        )
    else:
        ports = []

    services = [
        {
            "port": port["port"],
            "protocol": port["protocol"],
            "name": port["service"],
            "version": port["version"],
        }
        for port in ports
    ]

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for vulnerability in vulnerabilities:
        severity = vulnerability.severity

        if severity in severity_counts:
            severity_counts[severity] += 1

    duration_seconds = None

    if (
        scan.started_at
        and scan.finished_at
    ):
        duration_seconds = max(
            0,
            int(
                (
                    scan.finished_at
                    - scan.started_at
                ).total_seconds()
            ),
        )

    vulnerability_data = []

    for vulnerability in vulnerabilities:
        vulnerability_data.append(
            {
                "id": vulnerability.id,
                "cve_id": vulnerability.cve_id,
                "title": vulnerability.title,
                "severity": vulnerability.severity,
                "description": (
                    vulnerability.description
                ),
                "ai_recommendation": (
                    vulnerability
                    .ai_recommendation
                ),
                "status": vulnerability.status,

                "affected_url": (
                    vulnerability.affected_url
                ),
                "affected_path": (
                    vulnerability.affected_path
                ),
                "affected_port": (
                    vulnerability.affected_port
                ),
                "http_method": (
                    vulnerability.http_method
                ),
                "parameter_name": (
                    vulnerability.parameter_name
                ),
                "evidence": (
                    vulnerability.evidence
                ),
                "source_tool": (
                    vulnerability.source_tool
                    or scan.tool_used
                ),
                "confidence": (
                    vulnerability.confidence
                    or "Medium"
                ),
                "verification_status": (
                    vulnerability.verification_status
                    or "needs_review"
                ),
                "finding_type": finding_type(vulnerability),
                **review_data(vulnerability),
                "risk_score": 0 if finding_type(vulnerability)=='information' or vulnerability.review_state in {'fixed','false_positive'} or vulnerability.status in {'fixed','ignored'} else _finding_risk_score(
                    vulnerability.severity,
                    vulnerability.confidence,
                ),

                "created_at": (
                    _serialize_datetime(
                        vulnerability.created_at
                    )
                ),
            }
        )

    potential_counts={level:0 for level in SEVERITY}
    active={}
    for finding in vulnerabilities:
        if finding_type(finding)=='information' or finding.review_state in {'fixed','false_positive'} or finding.status in {'fixed','ignored'}:continue
        key=fingerprint(finding,target.id)
        if key not in active or SEVERITY[finding.severity]>SEVERITY[active[key]]:active[key]=finding.severity
    for level in active.values():potential_counts[level]+=1
    return jsonify(
        {
            "scan": {
                "id": scan.id,
                "tool_used": scan.tool_used,
                "status": scan.status,
                "started_at": (
                    _serialize_datetime(
                        scan.started_at
                    )
                ),
                "finished_at": (
                    _serialize_datetime(
                        scan.finished_at
                    )
                ),
                "duration_seconds": (
                    duration_seconds
                ),
            },
            "target": {
                "id": target.id,
                "name": target.name,
                "ip_address": (
                    target.ip_address
                ),
                "hostname": target.hostname,
                "port": target.port,
            },
            "ports": ports,
            "services": services,
            "severity_counts": severity_counts,
            "potential_severity_counts": potential_counts,
            "vulnerabilities": (
                vulnerability_data
            ),
        }
    ), 200


SCAN_HANDLERS = {
    "nmap": execute_nmap, "whatweb": execute_whatweb, "zap": execute_zap,
    "nuclei": execute_nuclei, "sslyze": execute_sslyze, "full": execute_full,
}

@scans_bp.route("/<tool>/<int:target_id>", methods=["POST"])
@jwt_required()
def enqueue_scan(tool, target_id):
    data = request.get_json(silent=True)
    if data is None: data = {}
    try:
        options = validate_options(data)
        if options and tool not in {'zap', 'full'}:
            raise ValueError('Web scan options apply only to ZAP and Full scans.')
    except (ValueError, TypeError) as error:
        return jsonify({'error': str(error)}), 400
    if tool not in SCAN_HANDLERS:
        return jsonify({"error": "Unknown scan tool."}), 404
    target = _get_owned_target(target_id)
    if not target:
        return jsonify({"error": "Target not found."}), 404
    if not _target_host(target):
        return jsonify({"error": "The target has no IP address or hostname."}), 400
    pending = ScanJob.query.filter(ScanJob.status.in_(["queued", "running"]))
    if pending.filter_by(user_id=_current_user_id()).count() >= 5 or pending.count() >= 100:
        return jsonify({"error": "The scan queue is full. Try again after a scan finishes."}), 429
    job = ScanJob(id=str(uuid.uuid4()), user_id=_current_user_id(), target_id=target.id, tool=tool,
                  encrypted_options=encrypt_options(options))
    db.session.add(job)
    db.session.commit()
    return jsonify({"job_id": job.id, "status": "queued", "message": "Scan queued."}), 202

@scans_bp.route('/compare',methods=['GET'])
@jwt_required()
def compare_scans():
    from finding_quality import group_scan
    baseline_id=request.args.get('baseline',type=int);current_id=request.args.get('current',type=int)
    if not baseline_id or not current_id or baseline_id==current_id:return jsonify(error='Choose two different scans.'),400
    def owned(scan_id):
        return Scan.query.join(Target,Scan.target_id==Target.id).filter(Scan.id==scan_id,Target.added_by==_current_user_id()).first()
    baseline,current=owned(baseline_id),owned(current_id)
    if not baseline or not current:return jsonify(error='Scan not found.'),404
    if (baseline.target_id,baseline.tool_used)!=(current.target_id,current.tool_used):return jsonify(error='Compare the same target and tool.'),400
    if baseline.status!='completed' or current.status!='completed':return jsonify(error='Both scans must be completed before comparison.'),409
    if (baseline.started_at or datetime.min,baseline.id)>=(current.started_at or datetime.min,current.id):return jsonify(error='Choose an older baseline and a newer scan.'),400
    include=request.args.get('include_information')=='true'
    before=group_scan(Vulnerability.query.filter_by(scan_id=baseline.id).all(),baseline.target_id,include)
    after=group_scan(Vulnerability.query.filter_by(scan_id=current.id).all(),current.target_id,include)
    uncertain=[group for group in list(before.values())+list(after.values()) if not group['location_complete']]
    before={key:group for key,group in before.items() if group['location_complete']}
    after={key:group for key,group in after.items() if group['location_complete']}
    categories={'new':[after[key] for key in sorted(after.keys()-before.keys())],
                'persistent':[after[key] for key in sorted(after.keys()&before.keys())],
                'not_observed':[before[key] for key in sorted(before.keys()-after.keys())]}
    if uncertain: categories['insufficient_location']=uncertain
    return jsonify({'baseline':baseline.id,'current':current.id,'summary':{key:len(value) for key,value in categories.items()},
                    'groups':categories,'warning':'Not observed does not mean fixed. Scan coverage and settings may differ.'}),200

@scans_bp.route("/jobs/<job_id>", methods=["GET"])
@jwt_required()
def get_scan_job(job_id):
    job = ScanJob.query.filter_by(id=job_id, user_id=_current_user_id()).first()
    if not job:
        return jsonify({"error": "Scan job not found."}), 404
    return jsonify({"job_id": job.id, "status": job.status,
                    "stage":job.stage, "progress":job.progress, "cancel_requested":job.cancel_requested,
                    "result": json.loads(job.result) if job.result else None,
                    "response_status": job.response_status}), 200


@scans_bp.route('/jobs/<job_id>/cancel', methods=['POST'])
@jwt_required()
def cancel_scan_job(job_id):
    job=ScanJob.query.filter_by(id=job_id,user_id=_current_user_id()).first()
    if not job: return jsonify({'error':'Scan job not found.'}),404
    if job.status not in {'queued','running'}:
        return jsonify({'job_id':job.id,'status':job.status,'message':'The job has already finished.'}),200
    job.cancel_requested=True
    if job.status=='queued':
        job.status='cancelled';job.stage='Cancelled';job.encrypted_options=None;job.finished_at=utc_now()
        job.result=json.dumps({'status':'cancelled','message':'Queued scan cancelled.'});job.response_status=409
    db.session.commit()
    return jsonify({'job_id':job.id,'status':job.status,'message':'Cancellation requested. ZAP stops at its next check; other tools finish their current step.'}),202


@scans_bp.route('/jobs',methods=['GET'])
@jwt_required()
def list_scan_jobs():
    rows=(db.session.query(ScanJob,Target.name).join(Target,Target.id==ScanJob.target_id)
          .filter(ScanJob.user_id==_current_user_id(),Target.added_by==_current_user_id())
          .order_by(ScanJob.created_at.desc()).limit(20).all())
    return jsonify([{'job_id':job.id,'target_name':name,'target_id':job.target_id,'tool':job.tool,
                     'status':job.status,'stage':job.stage,'progress':job.progress,'cancel_requested':job.cancel_requested}
                    for job,name in rows]),200
