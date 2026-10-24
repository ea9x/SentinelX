import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
_BUNDLED_SSLYZE = PROJECT_ROOT / "tools" / "sslyze" / "sslyze.exe"
SSLYZE_PATH = Path(
    os.getenv("SSLYZE_PATH")
    or shutil.which("sslyze")
    or _BUNDLED_SSLYZE
)


def _finding(
    title,
    severity,
    description,
    recommendation,
    target_url,
    port,
    evidence,
):
    return {
        "cve_id": None,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "affected_url": target_url,
        "affected_path": "/",
        "affected_port": int(port),
        "http_method": "GET",
        "parameter_name": None,
        "evidence": evidence,
        "source_tool": "sslyze",
    }


def _parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None


def _parse_results(data, host, port):
    findings = []
    target_url = f"https://{host}:{port}"

    server_results = data.get("server_scan_results") or []

    if not server_results:
        return findings

    server_result = server_results[0]
    scan_result = server_result.get("scan_result") or {}

    certificate_section = (
        scan_result.get("certificate_info") or {}
    )
    certificate_result = (
        certificate_section.get("result") or {}
    )
    deployments = (
        certificate_result.get("certificate_deployments")
        or []
    )

    if deployments:
        deployment = deployments[0]
        certificate_chain = (
            deployment.get("received_certificate_chain")
            or []
        )

        if certificate_chain:
            certificate = certificate_chain[0]

            common_name = (
                certificate
                .get("subject", {})
                .get("rfc4514_string", "Unknown")
            )

            issuer = (
                certificate
                .get("issuer", {})
                .get("rfc4514_string", "Unknown")
            )

            valid_until_text = certificate.get(
                "not_valid_after"
            )
            valid_until = _parse_datetime(
                valid_until_text
            )

            if (
                valid_until
                and valid_until < datetime.now(timezone.utc)
            ):
                findings.append(
                    _finding(
                        title="Expired TLS Certificate",
                        severity="High",
                        description=(
                            "The TLS certificate presented by "
                            "the server has expired."
                        ),
                        recommendation=(
                            "Replace the expired certificate "
                            "with a valid certificate issued by "
                            "a trusted certificate authority."
                        ),
                        target_url=target_url,
                        port=port,
                        evidence=(
                            f"Subject: {common_name} | "
                            f"Issuer: {issuer} | "
                            f"Expired: {valid_until_text}"
                        ),
                    )
                )

            signature_name = (
                certificate
                .get("signature_hash_algorithm", {})
                .get("name", "")
                .lower()
            )

            if signature_name in {"sha1", "md5"}:
                findings.append(
                    _finding(
                        title="Weak Certificate Signature Algorithm",
                        severity="High",
                        description=(
                            f"The certificate uses the obsolete "
                            f"{signature_name.upper()} signature "
                            "algorithm."
                        ),
                        recommendation=(
                            "Replace the certificate with one "
                            "signed using SHA-256 or a stronger "
                            "signature algorithm."
                        ),
                        target_url=target_url,
                        port=port,
                        evidence=(
                            f"Signature algorithm: "
                            f"{signature_name.upper()}"
                        ),
                    )
                )

            public_key = certificate.get(
                "public_key", {}
            )
            key_algorithm = public_key.get(
                "algorithm", "Unknown"
            )
            key_size = public_key.get("key_size")

            if (
                key_algorithm == "RSAPublicKey"
                and isinstance(key_size, int)
                and key_size < 2048
            ):
                findings.append(
                    _finding(
                        title="Weak RSA Certificate Key",
                        severity="High",
                        description=(
                            f"The certificate uses a "
                            f"{key_size}-bit RSA key, which is "
                            "below the recommended minimum."
                        ),
                        recommendation=(
                            "Generate a new certificate using "
                            "an RSA key of at least 2048 bits "
                            "or use a secure modern EC key."
                        ),
                        target_url=target_url,
                        port=port,
                        evidence=(
                            f"Public key: {key_algorithm} | "
                            f"Key size: {key_size} bits"
                        ),
                    )
                )

        validation_results = (
            deployment.get("path_validation_results")
            or []
        )

        trusted = any(
            result.get("was_validation_successful")
            for result in validation_results
        )

        if validation_results and not trusted:
            findings.append(
                _finding(
                    title="Untrusted TLS Certificate",
                    severity="Medium",
                    description=(
                        "The certificate chain could not be "
                        "validated against the available trust "
                        "stores."
                    ),
                    recommendation=(
                        "Use a certificate issued by a trusted "
                        "certificate authority and provide the "
                        "complete certificate chain."
                    ),
                    target_url=target_url,
                    port=port,
                    evidence=(
                        "Certificate validation failed for all "
                        "tested trust stores."
                    ),
                )
            )

    headers_section = (
        scan_result.get("http_headers") or {}
    )
    headers_result = (
        headers_section.get("result") or {}
    )

    if (
        headers_section.get("status") == "COMPLETED"
        and headers_result.get(
            "strict_transport_security_header"
        ) is None
    ):
        findings.append(
            _finding(
                title="HTTP Strict Transport Security Header Missing",
                severity="Medium",
                description=(
                    "The HTTPS service does not return the "
                    "Strict-Transport-Security header."
                ),
                recommendation=(
                    "Enable HSTS after confirming that the "
                    "application and its subdomains are fully "
                    "available over HTTPS."
                ),
                target_url=target_url,
                port=port,
                evidence=(
                    "Strict-Transport-Security header was "
                    "not returned by the server."
                ),
            )
        )

    tls12 = (
        scan_result.get("tls_1_2_cipher_suites") or {}
    )
    tls13 = (
        scan_result.get("tls_1_3_cipher_suites") or {}
    )

    tls12_result = tls12.get("result") or {}
    tls13_result = tls13.get("result") or {}

    tls12_supported = tls12_result.get(
        "is_tls_version_supported", False
    )
    tls13_supported = tls13_result.get(
        "is_tls_version_supported", False
    )

    tls12_ciphers = (
        tls12_result.get("accepted_cipher_suites")
        or []
    )
    tls13_ciphers = (
        tls13_result.get("accepted_cipher_suites")
        or []
    )

    findings.append(
        _finding(
            title="TLS Configuration Summary",
            severity="Info",
            description=(
                "SSLyze analyzed the supported TLS "
                "protocols and cipher suites."
            ),
            recommendation=(
                "Prefer TLS 1.3 and modern TLS 1.2 cipher "
                "suites. Disable obsolete protocols and "
                "weak cryptographic configurations."
            ),
            target_url=target_url,
            port=port,
            evidence=(
                f"TLS 1.2 supported: {tls12_supported} | "
                f"TLS 1.2 ciphers: {len(tls12_ciphers)} | "
                f"TLS 1.3 supported: {tls13_supported} | "
                f"TLS 1.3 ciphers: {len(tls13_ciphers)}"
            ),
        )
    )

    return findings


def run_sslyze_scan(host, port=443):
    if not SSLYZE_PATH.exists():
        return {
            "success": False,
            "error": (
                "SSLyze executable was not found at: "
                f"{SSLYZE_PATH}"
            ),
        }

    output_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
        ) as temporary_file:
            output_path = Path(temporary_file.name)

        command = [
            str(SSLYZE_PATH),
            "--certinfo",
            "--tlsv1_2",
            "--tlsv1_3",
            "--http_headers",
            "--json_out",
            str(output_path),
            f"{"[" + host + "]" if ":" in host else host}:{int(port)}",
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            creationflags=getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            ),
        )

        if not output_path.exists():
            return {
                "success": False,
                "error": (
                    process.stderr.strip()
                    or process.stdout.strip()
                    or "SSLyze did not create a JSON result."
                ),
            }

        with output_path.open(
            "r",
            encoding="utf-8",
        ) as result_file:
            data = json.load(result_file)

        server_results = (
            data.get("server_scan_results") or []
        )

        if not server_results:
            invalid_targets = data.get(
                "invalid_server_strings", {}
            )

            return {
                "success": False,
                "error": (
                    f"SSLyze could not scan the target. "
                    f"{invalid_targets}"
                ),
            }

        server_result = server_results[0]

        if server_result.get("scan_status") != "COMPLETED":
            return {
                "success": False,
                "error": (
                    server_result.get(
                        "connectivity_error_trace"
                    )
                    or "The SSLyze scan did not complete."
                ),
            }

        findings = _parse_results(
            data,
            host,
            int(port),
        )

        return {
            "success": True,
            "raw_output": json.dumps(
                data,
                ensure_ascii=False,
            ),
            "vulnerabilities": findings,
            "sslyze_version": data.get(
                "sslyze_version"
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "The SSLyze scan timed out.",
        }

    except json.JSONDecodeError as error:
        return {
            "success": False,
            "error": (
                f"SSLyze returned invalid JSON: {error}"
            ),
        }

    except Exception as error:
        return {
            "success": False,
            "error": str(error),
        }

    finally:
        if output_path and output_path.exists():
            try:
                output_path.unlink()
            except OSError:
                pass
