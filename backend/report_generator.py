import re
from collections import Counter, OrderedDict
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


REPORTS_DIRECTORY = Path(__file__).resolve().parent / "generated_reports"

SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}

SEVERITY_SCORES = {
    "Critical": 10.0,
    "High": 8.5,
    "Medium": 6.0,
    "Low": 3.5,
    "Info": 1.0,
}

CONFIDENCE_WEIGHTS = {
    "High": 1.0,
    "Medium": 0.85,
    "Low": 0.65,
}

SERVICE_NAMES = {
    "microsoft-ds": "Microsoft SMB",
    "microsoft-ds?": "Microsoft SMB",
    "msrpc": "Microsoft Windows RPC",
    "http-proxy": "HTTP Proxy",
}


def _plain(value, fallback="Not available"):
    if value is None or value == "":
        return fallback
    return str(value)


def _text(value, fallback="Not available"):
    return escape(_plain(value, fallback))


def _format_datetime(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "Not available"


def _normalize_severity(value):
    candidate = _plain(value, "Info").strip().title()
    return candidate if candidate in SEVERITY_ORDER else "Info"


def _normalize_confidence(value):
    candidate = _plain(value, "Medium").strip().title()
    return candidate if candidate in CONFIDENCE_WEIGHTS else "Medium"


def _verification_label(value):
    labels = {
        "confirmed": "Confirmed",
        "needs_review": "Needs Review",
        "informational": "Informational",
        "false_positive": "False Positive",
    }
    return labels.get(_plain(value, "needs_review").strip().lower(), "Needs Review")


def _risk_score(finding):
    stored = getattr(finding, "risk_score", None)
    if stored not in (None, ""):
        try:
            return round(float(stored), 1)
        except (TypeError, ValueError):
            pass

    severity = _normalize_severity(getattr(finding, "severity", None))
    confidence = _normalize_confidence(getattr(finding, "confidence", None))
    return round(SEVERITY_SCORES[severity] * CONFIDENCE_WEIGHTS[confidence], 1)


def _service_name(value):
    raw = _plain(value).strip()
    return SERVICE_NAMES.get(raw.lower(), raw.rstrip("?"))


def _parse_nmap_ports(raw_output):
    ports = []
    for line in (raw_output or "").splitlines():
        match = re.match(
            r"^\s*(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue

        port, protocol, service, version = match.groups()
        ports.append(
            {
                "port": port,
                "protocol": protocol.upper(),
                "service": _service_name(service),
                "version": (version or "").strip() or "Not detected",
                "state": "Open",
            }
        )
    return ports


def _severity_color(severity):
    return {
        "Critical": colors.HexColor("#B91C1C"),
        "High": colors.HexColor("#C2410C"),
        "Medium": colors.HexColor("#A16207"),
        "Low": colors.HexColor("#15803D"),
        "Info": colors.HexColor("#0369A1"),
    }.get(severity, colors.HexColor("#475569"))


def _overall_risk(vulnerabilities):
    if not vulnerabilities:
        return "None", 0.0
    highest = max(vulnerabilities, key=_risk_score)
    return _normalize_severity(getattr(highest, "severity", None)), _risk_score(highest)


def _location(finding):
    url = _plain(getattr(finding, "affected_url", None), "")
    path = _plain(getattr(finding, "affected_path", None), "")
    port = getattr(finding, "affected_port", None)
    method = _plain(getattr(finding, "http_method", None), "")
    parameter = _plain(getattr(finding, "parameter_name", None), "")
    evidence = _plain(getattr(finding, "evidence", None), "")
    source_tool = _plain(getattr(finding, "source_tool", None), "")

    if url and not path:
        try:
            path = urlsplit(url).path or "/"
        except ValueError:
            path = ""

    return {
        "url": url,
        "path": path,
        "port": port,
        "method": method,
        "parameter": parameter,
        "evidence": evidence,
        "source_tool": source_tool,
    }


def _group_findings(vulnerabilities):
    groups = OrderedDict()
    ordered = sorted(
        vulnerabilities,
        key=lambda item: (
            -SEVERITY_ORDER[_normalize_severity(getattr(item, "severity", None))],
            -_risk_score(item),
            _plain(getattr(item, "title", None)),
        ),
    )

    for finding in ordered:
        key = (
            _plain(getattr(finding, "title", None)),
            _normalize_severity(getattr(finding, "severity", None)),
            _plain(getattr(finding, "cve_id", None), ""),
            _plain(getattr(finding, "description", None), ""),
            _plain(getattr(finding, "ai_recommendation", None), ""),
        )
        if key not in groups:
            groups[key] = {
                "finding": finding,
                "locations": [],
            }
        location = _location(finding)
        if location not in groups[key]["locations"]:
            groups[key]["locations"].append(location)
    return list(groups.values())


def _header_footer(canvas, document):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(colors.HexColor("#0F172A"))
    canvas.rect(0, height - 10 * mm, width, 10 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawString(18 * mm, height - 6.5 * mm, "SENTINELX - CONFIDENTIAL")
    canvas.drawRightString(width - 18 * mm, height - 6.5 * mm, "AUTHORIZED SECURITY ASSESSMENT")

    canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
    canvas.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(18 * mm, 10 * mm, "SentinelX Security Assessment")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()


def generate_scan_report(report, scan, target, vulnerabilities):
    REPORTS_DIRECTORY.mkdir(parents=True, exist_ok=True)
    filename = f"sentinelx-report-{report.id}-scan-{scan.id}.pdf"
    output_path = REPORTS_DIRECTORY / filename

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"SentinelX Report {report.id}",
        author="SentinelX",
        subject="Authorized security assessment",
    )

    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=27,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceAfter=2 * mm,
    )
    subtitle_style = ParagraphStyle(
        "SentinelSubtitle",
        parent=base["Normal"],
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=5 * mm,
    )
    heading_style = ParagraphStyle(
        "SentinelHeading",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=17,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=4 * mm,
        spaceAfter=2.5 * mm,
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155"),
        alignment=TA_LEFT,
    )
    small_style = ParagraphStyle(
        "SentinelSmall",
        parent=body_style,
        fontSize=7.5,
        leading=10,
    )
    badge_style = ParagraphStyle(
        "SentinelBadge",
        parent=small_style,
        fontName="Helvetica-Bold",
        textColor=colors.white,
        alignment=TA_CENTER,
    )
    label_style = ParagraphStyle(
        "SentinelLabel",
        parent=small_style,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#475569"),
    )

    vulnerabilities = list(vulnerabilities or [])
    severity_counts = Counter(
        _normalize_severity(getattr(item, "severity", None))
        for item in vulnerabilities
    )
    overall_risk, highest_score = _overall_risk(vulnerabilities)
    needs_review = sum(
        1
        for item in vulnerabilities
        if _verification_label(getattr(item, "verification_status", None)) == "Needs Review"
    )
    grouped_findings = _group_findings(vulnerabilities)

    story = [
        Paragraph("SentinelX", title_style),
        Paragraph("Security Assessment Report", subtitle_style),
    ]

    summary_data = [
        ["Report ID", f"#{report.id}", "Scan ID", f"#{scan.id}"],
        ["Target", _text(target.name), "Tool", _text(scan.tool_used).upper()],
        [
            "Address",
            _text(target.ip_address or target.hostname),
            "Status",
            _text(scan.status).title(),
        ],
        [
            "Started",
            _format_datetime(scan.started_at),
            "Finished",
            _format_datetime(scan.finished_at),
        ],
        [
            "Generated",
            _format_datetime(report.created_at),
            "Findings",
            str(len(vulnerabilities)),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[27 * mm, 55 * mm, 27 * mm, 55 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend([summary_table, Paragraph("Executive Summary", heading_style)])
    if scan.status != 'completed':
        story.append(Paragraph('<b>INCOMPLETE SCAN:</b> The scan did not complete. Findings below are partial evidence; missing findings must not be interpreted as proof of safety.',body_style))
    story.append(Paragraph('Automated alerts require validation. Confidence describes the scanner evidence and does not mean that exploitation or business impact has been confirmed. Similar findings are grouped below; their individual locations are retained.',body_style))

    executive_data = [
        [
            Paragraph("<b>Overall Risk</b>", label_style),
            Paragraph("<b>Highest Score</b>", label_style),
            Paragraph("<b>Needs Review</b>", label_style),
            Paragraph("<b>Unique Findings</b>", label_style),
        ],
        [
            Paragraph(f"<b>{_text(overall_risk)}</b>", body_style),
            Paragraph(f"<b>{highest_score:.1f} / 10</b>", body_style),
            Paragraph(f"<b>{needs_review}</b>", body_style),
            Paragraph(f"<b>{len(grouped_findings)}</b>", body_style),
        ],
    ]
    executive_table = Table(executive_data, colWidths=[41 * mm] * 4)
    executive_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([executive_table, Spacer(1, 2 * mm)])

    severity_cells = []
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        severity_cells.append(
            Table(
                [[Paragraph(f"<b>{severity}: {severity_counts.get(severity, 0)}</b>", badge_style)]],
                colWidths=[31.8 * mm],
                style=TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), _severity_color(severity)),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ]
                ),
            )
        )
    severity_table = Table([severity_cells], colWidths=[32.8 * mm] * 5)
    severity_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(severity_table)

    ports = _parse_nmap_ports(scan.raw_output) if str(scan.tool_used).lower() == "nmap" else []
    if ports:
        story.append(Paragraph("Open Ports and Services", heading_style))
        port_data = [["Port", "Protocol", "Service", "Version", "State"]]
        for port in ports:
            port_data.append(
                [
                    port["port"],
                    port["protocol"],
                    Paragraph(_text(port["service"]), small_style),
                    Paragraph(_text(port["version"]), small_style),
                    port["state"],
                ]
            )
        port_table = Table(
            port_data,
            colWidths=[18 * mm, 22 * mm, 34 * mm, 73 * mm, 17 * mm],
            repeatRows=1,
        )
        port_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(port_table)

    story.append(Paragraph("Security Findings", heading_style))
    if not grouped_findings:
        story.append(Paragraph("No findings were saved for this scan.", body_style))

    for index, group in enumerate(grouped_findings, start=1):
        finding = group["finding"]
        locations = group["locations"]
        severity = _normalize_severity(getattr(finding, "severity", None))
        confidence = _normalize_confidence(getattr(finding, "confidence", None))
        verification = _verification_label(getattr(finding, "verification_status", None))
        score = _risk_score(finding)
        cve = _plain(getattr(finding, "cve_id", None), "")

        header = Table(
            [[
                Paragraph(f"<b>{index}. {_text(getattr(finding, 'title', None))}</b>", body_style),
                Paragraph(f"<b>{severity}</b>", badge_style),
            ]],
            colWidths=[137 * mm, 27 * mm],
        )
        header.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F8FAFC")),
                    ("BACKGROUND", (1, 0), (1, 0), _severity_color(severity)),
                    ("ALIGN", (1, 0), (1, 0), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        metadata = [
            Paragraph(f"<b>Risk Score</b><br/>{score:.1f} / 10", small_style),
            Paragraph(f"<b>Confidence</b><br/>{_text(confidence)}", small_style),
            Paragraph(f"<b>Review Status</b><br/>{_text(verification)}", small_style),
            Paragraph(f"<b>Affected Locations</b><br/>{len(locations)}", small_style),
        ]
        metadata_table = Table([metadata], colWidths=[41 * mm] * 4)
        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ]
            )
        )

        finding_block = [header, Spacer(1, 1.2 * mm), metadata_table]
        if cve:
            finding_block.extend([Spacer(1, 1 * mm), Paragraph(f"<b>Reference:</b> {_text(cve)}", small_style)])

        location_data = [["Affected URL / Resource", "Method", "Port", "Source"]]
        for location in locations:
            resource = location["url"] or location["path"] or "Not available"
            location_data.append(
                [
                    Paragraph(_text(resource), small_style),
                    _plain(location["method"]),
                    _plain(location["port"]),
                    _plain(location["source_tool"] or scan.tool_used).upper(),
                ]
            )
        location_table = Table(
            location_data,
            colWidths=[102 * mm, 20 * mm, 18 * mm, 24 * mm],
            repeatRows=1,
        )
        location_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        finding_block.extend(
            [
                Spacer(1, 0.6 * mm),
                location_table,
                Spacer(1, 0.6 * mm),
                Paragraph(f"<b>Description:</b> {_text(getattr(finding, 'description', None))}", body_style),
                Spacer(1, 0.6 * mm),
                Paragraph(f"<b>Recommendation:</b> {_text(getattr(finding, 'ai_recommendation', None))}", body_style),
                Spacer(1, 1.2 * mm),
            ]
        )
        story.append(KeepTogether(finding_block))

    story.extend(
        [
            Spacer(1, 1.5 * mm),
            Paragraph("Assessment Notice", heading_style),
            Paragraph(
                "Findings represent scanner observations and require validation. Open ports and detected services do not by themselves confirm an exploitable vulnerability. Review affected resources in an authorized environment before remediation decisions are made.",
                body_style,
            ),
        ]
    )

    document.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path
