import os
import shutil
import json
from http.client import HTTPException
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required

from config import Config
from models import User, RevokedToken, db
from routes.auth import auth_bp
from routes.reports import reports_bp
from routes.scans import scans_bp
from routes.targets import targets_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.remediation import remediation_bp
from routes.users import users_bp


app = Flask(__name__)
app.config.from_object(Config)
from bootstrap_admin import register_bootstrap
register_bootstrap(app)

CORS(app, resources={r"/api/*": {"origins": app.config.get("PUBLIC_APP_URL", "http://localhost:8088")}}, supports_credentials=True)
db.init_app(app)
jwt = JWTManager(app)
from security import install_security
install_security(app)


@jwt.token_in_blocklist_loader
def reject_disabled_accounts(_jwt_header, jwt_payload):
    identity = jwt_payload.get("sub")
    if not identity:
        return True
    try:
        user_id = int(identity)
    except (TypeError, ValueError):
        return True
    if db.session.get(RevokedToken, jwt_payload.get("jti")):
        return True
    user = db.session.get(User, user_id)
    from routes.auth import hash_reset_token
    return (not user or not user.is_active or
            jwt_payload.get("credential_version") != hash_reset_token(user.password_hash))


@jwt.revoked_token_loader
def disabled_account_response(_jwt_header, _jwt_payload):
    return jsonify({"error": "This session is no longer valid. Sign in again."}), 403

app.register_blueprint(remediation_bp, url_prefix="/api/remediation")
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(targets_bp, url_prefix="/api/targets")
app.register_blueprint(scans_bp, url_prefix="/api/scans")
app.register_blueprint(
    vulnerabilities_bp,
    url_prefix="/api/vulnerabilities",
)
app.register_blueprint(reports_bp, url_prefix="/api/reports")
app.register_blueprint(users_bp, url_prefix="/api/users")


@app.route("/")
def home():
    return jsonify(
        {
            "message": "SentinelX Backend is running successfully.",
            "status": "OK",
        }
    )


@app.route("/test-db")
@jwt_required()
def test_db():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"database": "Connected successfully."})
    except Exception as error:
        return jsonify(
            {
                "database": "Connection failed.",
                "error": "Database connection unavailable.",
            }
        ), 500


@app.route("/api/health")
@jwt_required()
def system_health():
    project_root = Path(__file__).resolve().parent.parent
    checks = {}

    try:
        db.session.execute(db.text("SELECT 1"))
        checks["database"] = {"available": True, "label": "SQLite" if db.engine.dialect.name == "sqlite" else "MySQL"}
    except Exception as error:
        checks["database"] = {
            "available": False,
            "label": "MySQL",
            "details": "Database connection unavailable.",
        }

    checks["nmap"] = {
        "available": shutil.which("nmap") is not None,
        "label": "Nmap",
    }

    whatweb_path = Path(
        os.getenv("WHATWEB_PATH")
        or project_root / "tools" / "WhatWeb" / "whatweb"
    )
    from scanners.whatweb_scanner import check_whatweb_runtime
    checks["whatweb"] = check_whatweb_runtime(whatweb_path)

    nuclei_path = Path(
        os.getenv("NUCLEI_PATH")
        or shutil.which("nuclei")
        or project_root / "tools" / "nuclei" / "nuclei.exe"
    )
    checks["nuclei"] = {
        "available": nuclei_path.is_file(),
        "label": "Nuclei",
    }

    sslyze_path = Path(
        os.getenv("SSLYZE_PATH")
        or shutil.which("sslyze")
        or project_root / "tools" / "sslyze" / "sslyze.exe"
    )
    checks["sslyze"] = {
        "available": sslyze_path.is_file(),
        "label": "SSLyze",
    }
    zap_url = os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
    zap_key = os.getenv("ZAP_API_KEY", "")
    try:
        if not zap_key:
            raise ValueError("Configure a private ZAP_API_KEY.")
        query = urlencode({"apikey": zap_key})
        with urlopen(
            f"{zap_url}/JSON/core/view/version/?{query}", timeout=2
        ) as response:
            zap_data = json.loads(response.read().decode("utf-8"))
        checks["zap"] = {
            "available": True,
            "label": "OWASP ZAP",
            "version": zap_data.get("version"),
        }
    except (URLError, TimeoutError, ValueError, OSError, HTTPException):
        checks["zap"] = {"available": False, "label": "OWASP ZAP"}

    available_count = sum(
        1 for check in checks.values() if check["available"]
    )
    total_count = len(checks)

    if available_count == total_count:
        status = "online"
    else:
        status = "degraded"

    return jsonify(
        {
            "status": status,
            "available_services": available_count,
            "total_services": total_count,
            "checks": checks,
        }
    ), 200


if __name__ == "__main__":
    from schema import ensure_schema
    with app.app_context():
        ensure_schema()
    from threading import Thread
    from scan_worker import run_worker
    Thread(target=run_worker, args=(app,), daemon=True, name="scan-worker").start()
    print(app.url_map)
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("FLASK_PORT", "5000")),
        debug=False,
    )

