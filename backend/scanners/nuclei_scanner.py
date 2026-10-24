"""Nuclei scanner integration for SentinelX."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[2]

try:
    SCAN_TIMEOUT_SECONDS = max(30, int(os.getenv("NUCLEI_TIMEOUT_SECONDS", "600")))
except ValueError:
    SCAN_TIMEOUT_SECONDS = 600

_BUNDLED_NUCLEI = PROJECT_ROOT / "tools" / "nuclei" / "nuclei.exe"
NUCLEI_EXECUTABLE = Path(
    os.getenv("NUCLEI_PATH")
    or shutil.which("nuclei")
    or _BUNDLED_NUCLEI
)


SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Info",
}


VALID_HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}


def _first_identifier(
    classification,
    template_id,
):
    cve_ids = classification.get("cve-id") or []
    cwe_ids = classification.get("cwe-id") or []

    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]

    if cve_ids:
        return str(cve_ids[0]).upper()

    if cwe_ids:
        value = str(cwe_ids[0]).upper()

        if value.startswith("CWE-"):
            return value

        return f"CWE-{value}"

    return str(
        template_id or "NUCLEI"
    )[:50]


def _extract_http_method(item):
    request_text = str(
        item.get("request") or ""
    ).strip()

    if not request_text:
        return None

    first_line = request_text.splitlines()[0]
    possible_method = first_line.split(
        " ",
        1,
    )[0].upper()

    if possible_method in VALID_HTTP_METHODS:
        return possible_method

    return None


def _extract_evidence(item):
    extracted_results = (
        item.get("extracted-results")
        or []
    )

    if isinstance(extracted_results, str):
        extracted_results = [
            extracted_results
        ]

    evidence = " | ".join(
        str(value)
        for value in extracted_results
        if value is not None
    ).strip()

    if evidence:
        return evidence

    matcher_name = str(
        item.get("matcher-name") or ""
    ).strip()

    if matcher_name:
        return matcher_name

    return None


def _get_location(item, target_url):
    affected_url = str(
        item.get("matched-at")
        or item.get("host")
        or target_url
    ).strip()

    parsed_url = urlparse(affected_url)

    affected_path = (
        parsed_url.path or "/"
    )

    affected_port = parsed_url.port

    if affected_port is None:
        if parsed_url.scheme == "https":
            affected_port = 443
        else:
            affected_port = 80

    return {
        "affected_url": affected_url,
        "affected_path": affected_path,
        "affected_port": affected_port,
        "http_method": _extract_http_method(item),
        "parameter_name": (
            item.get("matcher-name")
        ),
        "evidence": _extract_evidence(item),
    }


def _format_description(item, target_url):
    info = item.get("info") or {}

    classification = (
        info.get("classification")
        or {}
    )

    tags = info.get("tags") or []

    if isinstance(tags, str):
        tags = [tags]

    location = _get_location(
        item,
        target_url,
    )

    lines = [
        (
            "Matched URL: "
            f"{location['affected_url']}"
        ),
        (
            "Path: "
            f"{location['affected_path']}"
        ),
        (
            "Port: "
            f"{location['affected_port']}"
        ),
        (
            "HTTP Method: "
            f"{location['http_method'] or 'Not available'}"
        ),
        (
            "Parameter or Matcher: "
            f"{location['parameter_name'] or 'Not available'}"
        ),
        (
            "Evidence: "
            f"{location['evidence'] or 'Not available'}"
        ),
        (
            "Template ID: "
            f"{item.get('template-id') or 'Not available'}"
        ),
        (
            "Protocol: "
            f"{item.get('type') or 'Not available'}"
        ),
        (
            "Tags: "
            f"{', '.join(tags) if tags else 'Not available'}"
        ),
    ]

    cvss_score = classification.get(
        "cvss-score"
    )

    if cvss_score not in (None, ""):
        lines.append(
            f"CVSS Score: {cvss_score}"
        )

    description = str(
        info.get("description") or ""
    ).strip()

    if description:
        lines.extend(
            [
                "",
                description,
            ]
        )

    return "\n".join(lines)


def run_nuclei_scan(target_url):
    if not NUCLEI_EXECUTABLE.is_file():
        return {
            "success": False,
            "error": (
                "Nuclei was not found at "
                f"{NUCLEI_EXECUTABLE}"
            ),
        }

    command = [
        str(NUCLEI_EXECUTABLE),
        "-u",
        target_url,
        "-no-stdin",
        "-disable-update-check",
        "-no-interactsh",
        "-retries",
        "0",
        "-type",
        "http",
        "-tags",
        "tech,misconfig,exposure",
        "-exclude-tags",
        "dos,fuzz,intrusive",
        "-severity",
        "info,low,medium,high,critical",
        "-rate-limit",
        "20",
        "-timeout",
        "10",
        "-jsonl",
        "-silent",
        "-no-color",
    ]

    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )

    except subprocess.TimeoutExpired as error:
        def text_output(value):
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        return {
            "success": False,
            "error": f"The Nuclei scan timed out after {SCAN_TIMEOUT_SECONDS} seconds; results are incomplete.",
            "raw_output": text_output(error.stdout),
            "stderr": text_output(error.stderr),
        }

    except OSError as error:
        return {
            "success": False,
            "error": str(error),
        }

    findings = []
    seen = set()
    invalid_records = 0

    for output_line in completed.stdout.splitlines():
        output_line = output_line.strip()

        if not output_line:
            continue

        try:
            item = json.loads(output_line)

        except json.JSONDecodeError:
            invalid_records += 1
            continue

        if not isinstance(item, dict) or not isinstance(item.get("info") or {}, dict):
            invalid_records += 1
            continue

        template_id = item.get(
            "template-id"
        )

        matched_at = (
            item.get("matched-at")
            or item.get("host")
        )

        matcher_name = item.get(
            "matcher-name"
        )

        unique_key = (
            template_id,
            matched_at,
            matcher_name,
        )

        if unique_key in seen:
            continue

        seen.add(unique_key)

        info = item.get("info") or {}

        classification = (
            info.get("classification")
            or {}
        )

        severity_name = str(
            info.get("severity") or "info"
        ).lower()

        severity = SEVERITY_MAP.get(
            severity_name,
            "Info",
        )

        location = _get_location(
            item,
            target_url,
        )

        finding = {
            "title": str(
                info.get("name")
                or template_id
                or "Nuclei Finding"
            ),
            "severity": severity,
            "description": _format_description(
                item,
                target_url,
            ),
            "recommendation": str(
                info.get("remediation")
                or (
                    "Validate this finding and apply "
                    "the vendor or template guidance."
                )
            ).strip(),
            "cve_id": _first_identifier(
                classification,
                template_id,
            ),
            "affected_url": location["affected_url"],
            "affected_path": location["affected_path"],
            "affected_port": location["affected_port"],
            "http_method": location["http_method"],
            "parameter_name": location["parameter_name"],
            "evidence": location["evidence"],
            "source_tool": "nuclei",
        }

        findings.append(finding)

    if completed.returncode != 0:
        error = (
            completed.stderr.strip()
            or "Nuclei exited with an error."
        )

        return {
            "success": False,
            "error": error[-2000:],
            "exit_code": completed.returncode,
            "raw_output": completed.stdout,
            "vulnerabilities": findings,
        }

    if invalid_records:
        return {"success": False, "error": "Nuclei returned invalid result records; the scan is incomplete.",
                "raw_output": completed.stdout, "vulnerabilities": findings}

    return {
        "success": True,
        "raw_output": completed.stdout,
        "vulnerabilities": findings,
        "stderr": completed.stderr,
    }
