"""OWASP ZAP scanner integration for SentinelX."""

import json
import os
import time
import re
import uuid
from contextvars import ContextVar
from urllib.parse import urlencode
from urllib.parse import urlparse

import requests
from flask import g, has_app_context
from scanners.api_scanner import run_api_scan
from job_control import check_cancelled, progress, cancellation_requested

_scan_context=ContextVar('zap_scan_context', default=None)


ZAP_BASE_URL = os.getenv(
    "ZAP_API_URL",
    "http://127.0.0.1:8080",
).rstrip("/")

ZAP_API_KEY = os.getenv(
    "ZAP_API_KEY",
    "",
)

SPIDER_MAX_WAIT = 120
ACTIVE_SCAN_MAX_WAIT = 600
POLL_INTERVAL = 2


ZAP_RISK_MAP = {
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Informational": "Info",
}


def _api_params(**values):
    params = {
        "apikey": ZAP_API_KEY,
    }

    params.update(values)
    return params


def _zap_get(path, *, timeout=15, **params):
    try:
        send = requests.post if path in {'/JSON/sessionManagement/action/setSessionManagementMethod/', '/JSON/authentication/action/setAuthenticationMethod/', '/JSON/users/action/setAuthenticationCredentials/'} else requests.get
        arguments = {'data': _api_params(**params)} if send is requests.post else {'params':_api_params(**params)}
        response = send(
            f"{ZAP_BASE_URL}{path}",
            **arguments,
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as error:
        # Requests exceptions include the query URL, which contains the API key.
        status = getattr(getattr(error, "response", None), "status_code", None)
        detail = f"HTTP {status}" if status is not None else type(error).__name__
        raise RuntimeError(f"ZAP API request failed ({detail}).") from None


def _wait_for_scan(status_path, scan_id, max_wait):
    if scan_id is None: raise ValueError('ZAP did not return a scan ID.')
    deadline = time.monotonic() + max_wait
    try:
        while time.monotonic() < deadline:
            check_cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            payload = _zap_get(status_path, scanId=scan_id, timeout=min(10, remaining))
            phase = 'ZAP active scan' if '/ascan/' in status_path else 'ZAP crawling'
            value = int(payload.get('status',0))
            progress(phase,35+value*0.6 if '/ascan/' in status_path else 10+value*0.25)
            if int(payload.get("status", 0)) >= 100:
                return {"success": True}
            time.sleep(min(POLL_INTERVAL, max(0, deadline - time.monotonic())))
    except Exception:
        _stop_scan(status_path, scan_id)
        raise
    _stop_scan(status_path, scan_id)
    return {"success": False, "error": "The ZAP scan timed out. A stop was requested."}


def _stop_scan(status_path, scan_id):
    if scan_id is None: return
    # Stop only this task, so a timed-out ZAP scan cannot keep using shared resources.
    stop_path = status_path.replace("/view/status/", "/action/stop/")
    try:
        _zap_get(stop_path, scanId=scan_id, timeout=5)
    except Exception:
        pass


def _run_spider(target_url):
    context=_scan_context.get()
    extra={'contextId':context['id'],'userId':context['user']} if context and context.get('user') else {}
    payload = _zap_get(
        "/JSON/spider/action/scanAsUser/" if extra else "/JSON/spider/action/scan/",
        **extra,
        url=target_url,
        recurse="true",
        timeout=10,
    )

    return _wait_for_scan(
        "/JSON/spider/view/status/",
        payload.get("scan", payload.get("scanAsUser")),
        SPIDER_MAX_WAIT,
    )


def _run_active_scan(target_url):
    context=_scan_context.get()
    extra={'contextId':context['id'],'userId':context['user']} if context and context.get('user') else {}
    if context and context.get('policy'): extra['scanPolicyName']=context['policy']
    payload = _zap_get(
        "/JSON/ascan/action/scanAsUser/" if context and context.get('user') else "/JSON/ascan/action/scan/",
        **extra,
        url=target_url,
        recurse="true",
        timeout=10,
    )

    return _wait_for_scan(
        "/JSON/ascan/view/status/",
        payload.get("scan", payload.get("scanAsUser")),
        ACTIVE_SCAN_MAX_WAIT,
    )


def _get_alerts(target_url):
    payload = _zap_get(
        "/JSON/core/view/alerts/",
        baseurl=target_url,
        start=0,
        count=5000,
        timeout=20,
    )

    return payload.get("alerts", [])


def _clean(value, fallback="Not available"):
    text = str(value or "").strip()
    return text or fallback


def _deduplicate_alerts(alerts):
    """
    Keep one finding for every unique combination of:
    alert name, URL, HTTP method, and parameter.
    """

    unique = {}

    for alert in alerts:
        key = (
            _clean(
                alert.get("name"),
                "Unnamed alert",
            ).lower(),
            _clean(
                alert.get("url"),
                "",
            ).lower(),
            _clean(
                alert.get("method"),
                "GET",
            ).upper(),
            _clean(
                alert.get("param"),
                "",
            ).lower(),
        )

        unique.setdefault(key, alert)

    return list(unique.values())


def _get_location(alert, target_url):
    affected_url = _clean(
        alert.get("url"),
        target_url,
    )

    parsed_url = urlparse(affected_url)

    affected_path = parsed_url.path or "/"
    affected_port = parsed_url.port

    if affected_port is None:
        if parsed_url.scheme == "https":
            affected_port = 443
        else:
            affected_port = 80

    http_method = _clean(
        alert.get("method"),
        "GET",
    ).upper()

    parameter_name = _clean(
        alert.get("param"),
        "",
    )

    evidence = _clean(
        alert.get("evidence"),
        "",
    )

    return {
        "affected_url": affected_url,
        "affected_path": affected_path,
        "affected_port": affected_port,
        "http_method": http_method,
        "parameter_name": parameter_name,
        "evidence": evidence,
    }


def _format_description(alert, target_url):
    location = _get_location(
        alert,
        target_url,
    )

    confidence = _clean(
        alert.get("confidence"),
    )

    description = _clean(
        alert.get("description"),
        "No description is available.",
    )

    return "\n".join(
        [
            f"Affected URL: {location['affected_url']}",
            f"Path: {location['affected_path']}",
            f"Port: {location['affected_port']}",
            f"HTTP Method: {location['http_method']}",
            f"Confidence: {confidence}",
            (
                "Parameter: "
                f"{location['parameter_name'] or 'Not available'}"
            ),
            (
                "Evidence: "
                f"{location['evidence'] or 'Not available'}"
            ),
            "",
            description,
        ]
    )


def run_zap_scan(target_url, options=None):
    api_result = {'success': False, 'vulnerabilities': [], 'observations': []}
    context={};context_token=_scan_context.set(context)
    try:
        version_payload = _zap_get(
            "/JSON/core/view/version/",
            timeout=5,
        )

        version = version_payload.get("version")
        if options is None:
            options = getattr(g, 'web_scan_options', {}) if has_app_context() else {}
        progress('API discovery and account verification',2)
        def configure_auth(headers):
            if not options.get('authenticated_zap'): return
            context['name']='SentinelX-'+uuid.uuid4().hex
            context['id']=_zap_get('/JSON/context/action/newContext/',contextName=context['name'])['contextId']
            _zap_get('/JSON/context/action/includeInContext/',contextName=context['name'],regex=re.escape(target_url.rstrip('/'))+r'(?:/.*)?')
            login=options['accounts'][0]['login']
            _zap_get('/JSON/authentication/action/setAuthenticationMethod/',contextId=context['id'],authMethodName='jsonBasedAuthentication',
                     authMethodConfigParams=urlencode({'loginUrl':target_url.rstrip('/')+login['path'],'loginRequestData':json.dumps(login['json'])}))
            _zap_get('/JSON/sessionManagement/action/setSessionManagementMethod/',contextId=context['id'],methodName='headerBasedSessionManagement',
                     methodConfigParams=urlencode({'headers':'Authorization:Bearer {%json:'+login['token_field']+'%}'}))
            context['user']=_zap_get('/JSON/users/action/newUser/',contextId=context['id'],name='verified-test-account')['userId']
            _zap_get('/JSON/users/action/setAuthenticationCredentials/',contextId=context['id'],userId=context['user'],
                     authCredentialsConfigParams=urlencode({'username':str(login['json'].get('email') or login['json'].get('username') or 'test-account'),
                                                           'password':str(login['json'].get('password') or 'configured-test-login')}))
            _zap_get('/JSON/users/action/setUserEnabled/',contextId=context['id'],userId=context['user'],enabled='true')
        def seed(path, headers):
            # Authenticated requests are checked directly, keeping credentials
            # out of the shared ZAP history and global configuration.
            if headers: return
            host = urlparse(target_url).netloc
            message = f'GET {target_url.rstrip("/")}{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
            _zap_get('/JSON/core/action/sendRequest/', request=message, followRedirects='false', timeout=15)
        api_result = run_api_scan(target_url, options, seed=seed, on_authenticated=configure_auth)
        if options.get('authenticated_zap') and not context.get('user'):
            return {'success':False,'error':'Authenticated ZAP setup failed; no anonymous fallback was run.',
                    'vulnerabilities':api_result.get('vulnerabilities',[])}
        check_cancelled()
        # A separate per-run policy reduces expensive low-strength probes without
        # mutating global scanner settings. Comprehensive mode retains defaults.
        if options.get('scan_mode','focused')=='focused':
            context['policy']='SentinelX-'+uuid.uuid4().hex
            _zap_get('/JSON/ascan/action/addScanPolicy/',scanPolicyName=context['policy'],alertThreshold='MEDIUM',attackStrength='LOW')
        spider_result = _run_spider(target_url)
        active_result = _run_active_scan(target_url) if spider_result['success'] else {'success':False,'error':spider_result.get('error')}
        complete = api_result['success'] and spider_result['success'] and active_result['success']
        progress('Collecting findings',96)

        alerts = _deduplicate_alerts(
            _get_alerts(target_url)
        )

        vulnerabilities = list(api_result.get('vulnerabilities', []))

        for alert in alerts:
            risk = alert.get(
                "risk",
                "Informational",
            )

            cwe_id = str(
                alert.get("cweid") or ""
            ).strip()

            if cwe_id in {"", "-1", "0"}:
                cwe_id = None
            else:
                cwe_id = f"CWE-{cwe_id}"

            location = _get_location(
                alert,
                target_url,
            )

            vulnerability = {
                "title": _clean(
                    alert.get("name"),
                    "Unnamed ZAP Alert",
                ),
                "severity": ZAP_RISK_MAP.get(
                    risk,
                    "Info",
                ),
                "description": _format_description(
                    alert,
                    target_url,
                ),
                "recommendation": _clean(
                    alert.get("solution"),
                    (
                        "Review the relevant OWASP guidance "
                        "and validate the finding manually."
                    ),
                ),
                "cve_id": cwe_id,
                "affected_url": location["affected_url"],
                "affected_path": location["affected_path"],
                "affected_port": location["affected_port"],
                "http_method": location["http_method"],
                "parameter_name": location["parameter_name"],
                "evidence": location["evidence"],
                "source_tool": "zap",
                "confidence": _clean(
                    alert.get("confidence"),
                ),
                "reference": _clean(
                    alert.get("reference"),
                    "",
                ),
            }

            vulnerabilities.append(vulnerability)

        summary = {
            "tool": "OWASP ZAP",
            "version": version,
            "target": target_url,
            "alerts_received": len(alerts),
            "findings_saved": len(vulnerabilities),
            "api_coverage": {k:v for k,v in api_result.items() if k != 'vulnerabilities'},
            "complete": complete,
            "scan_mode":options.get('scan_mode','focused'),
            "authenticated_active_scan":bool(context.get('user')),
        }

        return {
            "success": complete,
            "error": None if complete else (api_result.get('error') or active_result.get('error') or spider_result.get('error')),
            "raw_output": json.dumps(
                summary,
                ensure_ascii=False,
                indent=2,
            ),
            "vulnerabilities": vulnerabilities,
        }

    except requests.exceptions.RequestException as error:
        return {
            "success": False,
            "error": (
                "Unable to communicate with the ZAP API: "
                f"{error}"
            ),
        }

    except (KeyError, TypeError, ValueError) as error:
        return {
            "success": False,
            "error": (
                "ZAP returned an unexpected response: "
                f"{type(error).__name__}"
            ),
            "vulnerabilities":api_result.get('vulnerabilities',[]),
        }

    except Exception as error:
        return {
            "success": False,
            "error": 'The scan was cancelled.' if cancellation_requested() else 'ZAP could not complete. Check service availability and scan settings.',
            "vulnerabilities":api_result.get('vulnerabilities',[]),
        }
    finally:
        if context.get('id'):
            try: _zap_get('/JSON/context/action/removeContext/',contextName=context['name'])
            except Exception: pass
        if context.get('policy'):
            try: _zap_get('/JSON/ascan/action/removeScanPolicy/',scanPolicyName=context['policy'])
            except Exception: pass
        _scan_context.reset(context_token)
