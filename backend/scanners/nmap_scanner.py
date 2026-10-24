import re
import subprocess


def run_nmap_scan(target_ip, port=None):
    """
    Run a fast Nmap service-version scan against the target
    and return structured open-port information.
    """
    try:
        # -F: Scan the 100 most common ports.
        # -sV: Detect service names and versions.
        # -T4: Use faster scan timing.
        command = ["nmap", "-sV", "-T4"]
        command += ["-p", str(int(port))] if port is not None else ["-F"]
        command += [target_ip]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=240,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "error": result.stderr.strip() or "Nmap scan failed.",
            }

        raw_output = result.stdout
        open_ports = []

        for line in raw_output.splitlines():
            match = re.match(
                r"^\s*(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
                line,
                re.IGNORECASE,
            )

            if not match:
                continue

            port, protocol, service, version = match.groups()

            open_ports.append(
                {
                    "port": port,
                    "protocol": protocol.lower(),
                    "service": service,
                    "version": (version or "").strip() or None,
                }
            )

        return {
            "success": True,
            "raw_output": raw_output,
            "open_ports": open_ports,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "The Nmap scan timed out.",
        }

    except FileNotFoundError:
        return {
            "success": False,
            "error": "Nmap is not installed or is not available in PATH.",
        }

    except Exception as error:
        return {
            "success": False,
            "error": str(error),
        }
