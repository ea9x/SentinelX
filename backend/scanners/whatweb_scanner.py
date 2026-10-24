import subprocess
import re
import os
import shutil
import time
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WHATWEB_PATH = Path(
    os.getenv("WHATWEB_PATH")
    or PROJECT_ROOT / "tools" / "WhatWeb" / "whatweb"
)


BLOCKED_MESSAGE = 'WhatWeb is blocked by the operating system. Review the Ruby installation and application-control policy.'


def _blocked(text):
    return 'application control policy' in text.lower() and 'blocked' in text.lower()


@lru_cache(maxsize=4)
def _probe_runtime(path, ruby, time_bucket):
    try:
        result = subprocess.run([ruby, path, '--version'], capture_output=True, text=True,
                                timeout=5, cwd=str(Path(path).parent))
        available = result.returncode == 0 and bool(result.stdout.strip())
        return {'available':available,'label':'WhatWeb',
                **({'error':BLOCKED_MESSAGE if _blocked(result.stderr) else 'WhatWeb could not start. Check the Ruby installation.'} if not available else {})}
    except (OSError, subprocess.TimeoutExpired):
        return {'available':False,'label':'WhatWeb','error':'WhatWeb could not start. Check the Ruby installation.'}


def check_whatweb_runtime(path=None):
    path = Path(path) if path is not None else WHATWEB_PATH
    ruby = os.getenv('RUBY_PATH') or shutil.which('ruby')
    if not path.is_file() or not ruby:
        return {'available':False,'label':'WhatWeb','error':'WhatWeb or Ruby was not found at the configured path.'}
    return dict(_probe_runtime(str(path),ruby,int(time.monotonic()//60)))


def run_whatweb_scan(target_url):
    """
    Run WhatWeb for a URL and extract detected technologies.
    """
    try:
        command = [os.getenv('RUBY_PATH') or "ruby", str(WHATWEB_PATH), target_url]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(WHATWEB_PATH.parent)
        )

        raw_output = result.stdout.strip()


        if result.returncode != 0 or not raw_output or "ERROR" in raw_output:
            return {
                "success": False,
                "error": BLOCKED_MESSAGE if _blocked(result.stderr) else result.stderr.strip() or raw_output or "No results were returned.",
                "stderr": result.stderr.strip(),
                "raw_output": raw_output,
            }

        # Extract Plugin[value] entries such as HTTPServer[Werkzeug/3.1.8].
        findings = re.findall(r'([A-Za-z\-]+)\[([^\]]+)\]', raw_output)

        technologies = []
        for name, value in findings:
            technologies.append({
                "technology": name,
                "details": value
            })

        return {
            "success": True,
            "raw_output": raw_output,
            "technologies": technologies
        }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "The scan timed out."}
    except FileNotFoundError:
        return {"success": False, "error": "WhatWeb or Ruby was not found at the configured path."}
    except Exception as e:
        return {"success": False, "error": str(e)}
