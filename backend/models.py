from time_utils import utc_now
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.mysql import LONGTEXT

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
    )
    email = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
    )
    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )
    role = db.Column(
        db.Enum("admin", "analyst"),
        default="analyst",
    )
    avatar_icon = db.Column(
        db.String(30),
        nullable=False,
        default="shield",
    )
    avatar_color = db.Column(
        db.String(20),
        nullable=False,
        default="#38bdf8",
    )
    avatar_url = db.Column(
        db.String(255),
        nullable=True,
    )
    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )
    created_at = db.Column(
        db.DateTime,
        default=utc_now,
    )


class PasswordReset(db.Model):
    __tablename__ = "password_resets"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    challenge_hash = db.Column(db.String(64), unique=True, nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(
        db.String(100),
        nullable=False,
    )
    ip_address = db.Column(db.String(45))
    hostname = db.Column(db.String(100))
    port = db.Column(
        db.Integer,
        default=80,
    )
    added_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
    )
    is_deleted = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    created_at = db.Column(
        db.DateTime,
        default=utc_now,
    )


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(
        db.Integer,
        db.ForeignKey("targets.id"),
        nullable=False,
    )
    tool_used = db.Column(
    db.Enum(
        "nmap",
        "zap",
        "nikto",
        "nuclei",
        "whatweb",
        "sslyze",
    ),
    nullable=False,
    )
    status = db.Column(
        db.Enum(
            "pending",
            "running",
            "completed",
            "failed",
        ),
        default="pending",
    )
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    raw_output = db.Column(db.Text().with_variant(LONGTEXT(), "mysql", "mariadb"))


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False,
    )

    cve_id = db.Column(db.String(50))
    title = db.Column(
        db.String(255),
        nullable=False,
    )

    severity = db.Column(
        db.Enum(
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info",
        ),
        nullable=False,
    )

    description = db.Column(db.Text)
    ai_recommendation = db.Column(db.Text)

    status = db.Column(
        db.Enum(
            "open",
            "fixed",
            "ignored",
        ),
        default="open",
    )

    affected_url = db.Column(db.String(2048))
    affected_path = db.Column(db.String(1024))
    affected_port = db.Column(db.Integer)
    http_method = db.Column(db.String(20))
    parameter_name = db.Column(db.String(255))
    evidence = db.Column(db.Text)
    source_tool = db.Column(db.String(30))
    confidence = db.Column(db.String(20), nullable=False, default="Medium")
    verification_status = db.Column(
        db.String(30),
        nullable=False,
        default="needs_review",
    )

    created_at = db.Column(
        db.DateTime,
        default=utc_now,
    )


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False,
    )
    generated_by = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
    )
    file_path = db.Column(db.String(255))
    created_at = db.Column(
        db.DateTime,
        default=utc_now,
    )


class ScanJob(db.Model):
    __tablename__ = "scan_jobs"
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    tool = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="queued", index=True)
    result = db.Column(db.Text)
    encrypted_options = db.Column(db.Text)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    progress = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    stage = db.Column(db.String(80), nullable=False, default='Queued', server_default='Queued')
    response_status = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    finished_at = db.Column(db.DateTime)


class RevokedToken(db.Model):
    __tablename__ = "revoked_tokens"
    jti = db.Column(db.String(36), primary_key=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class AuthRateLimit(db.Model):
    __tablename__ = 'auth_rate_limits'
    key = db.Column(db.String(64), primary_key=True)
    hits = db.Column(db.Integer, nullable=False, default=1)
    expires_at = db.Column(db.Integer, nullable=False, index=True)
