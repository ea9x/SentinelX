from time_utils import iso_utc
from time_utils import utc_now
import hashlib
import hmac
import re
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, send_from_directory
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    get_jwt,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)
from sqlalchemy import or_

from models import PasswordReset, RevokedToken, User, db
from services.email import send_password_reset_link

auth_bp = Blueprint("auth", __name__)
bcrypt = Bcrypt()

ALLOWED_AVATARS = {"shield", "user", "secret", "robot", "analyst"}
ALLOWED_COLORS = {
    "#38bdf8",
    "#3b82f6",
    "#8b5cf6",
    "#22c55e",
    "#f59e0b",
    "#ef4444",
}
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
AVATAR_DIRECTORY = Path(__file__).resolve().parent.parent / "uploads" / "avatars"
AVATAR_DIRECTORY.mkdir(parents=True, exist_ok=True)


def hash_reset_token(value):
    secret = str(current_app.config["SECRET_KEY"]).encode("utf-8")
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_password_reset(user):
    now = utc_now()
    token = secrets.token_urlsafe(32)
    digest = hash_reset_token(token)
    record = PasswordReset(
        user_id=user.id, challenge_hash=digest, code_hash=digest,
        expires_at=now + timedelta(seconds=current_app.config.get("RESET_TTL_SECONDS", 900)),
    )
    db.session.add(record)
    try:
        url = current_app.config.get("PUBLIC_APP_URL", "http://localhost:8088").rstrip("/")
        send_password_reset_link(user.email, f"{url}/forgot-password#token={token}")
        db.session.commit()
    except (OSError, RuntimeError, smtplib.SMTPException):
        db.session.rollback()
        current_app.logger.exception("Unable to deliver password reset link")


def serialize_user(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "avatar_icon": user.avatar_icon or "shield",
        "avatar_color": user.avatar_color or "#38bdf8",
        "avatar_url": f"/api/auth/avatars/{user.avatar_url}" if user.avatar_url else None,
        "is_active": bool(user.is_active),
        "created_at": iso_utc(user.created_at) if user.created_at else None,
    }


def current_user():
    user_id = get_jwt_identity()
    return db.session.get(User, int(user_id)) if user_id else None


def require_admin(user):
    if not user:
        return jsonify({"error": "User not found."}), 404
    if user.role != "admin":
        return jsonify({"error": "Administrator access is required."}), 403
    return None


@auth_bp.route("/register", methods=["POST"])
def register():
    if not current_app.config.get("ALLOW_REGISTRATION", False):
        return jsonify({"error": "Public registration is disabled. Contact your administrator."}), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if len(username) > 50 or len(email) > 100 or len(password.encode("utf-8")) > 72:
        return jsonify({"error": "Username, email, or password exceeds the maximum length."}), 400
    if not username or not email or not password:
        return jsonify({"error": "All fields are required."}), 400
    if not EMAIL_PATTERN.match(email):
        return jsonify({"error": "Enter a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must contain at least 8 characters."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "This email address is already in use."}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "This username is already in use."}), 409

    user = User(
        username=username,
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
        role="analyst",
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Account created successfully."}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    user = User.query.filter_by(email=email).first()

    if len(password.encode("utf-8")) > 72 or not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid email address or password."}), 401
    if not user.is_active:
        return jsonify({"error": "This account has been disabled by an administrator."}), 403

    access_token = create_access_token(identity=str(user.id), additional_claims={"credential_version": hash_reset_token(user.password_hash)})
    response = jsonify({"message": "Signed in successfully.", "user": serialize_user(user)})
    set_access_cookies(response, access_token)
    return response, 200


@auth_bp.route("/password/forgot", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    email = str(data.get("email", "")).strip().lower()
    user = User.query.filter_by(email=email, is_active=True).first() if EMAIL_PATTERN.match(email) else None
    if user:
        issue_password_reset(user)
    return jsonify({"message": "If an active account matches that email, a password reset link has been sent."}), 202


@auth_bp.route("/password/reset", methods=["POST"])
def reset_forgotten_password():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    token = str(data.get("token", "")).strip()
    new_password = str(data.get("new_password", ""))
    if not token or len(token) > 256:
        return jsonify({"error": "A valid password reset link is required."}), 400
    if len(new_password) < 8 or len(new_password.encode("utf-8")) > 72:
        return jsonify({"error": "New password must contain at least 8 characters and at most 72 UTF-8 bytes."}), 400
    record = PasswordReset.query.filter_by(challenge_hash=hash_reset_token(token)).first()
    now = utc_now()
    if not record or record.consumed_at or record.expires_at <= now:
        return jsonify({"error": "This reset link is invalid or has expired."}), 401
    # Only link-based records are valid; old numeric reset challenges are rejected.
    if not hmac.compare_digest(record.code_hash, hash_reset_token(token)):
        return jsonify({"error": "This reset link is invalid or has expired."}), 401
    user = db.session.get(User, record.user_id)
    if not user or not user.is_active:
        return jsonify({"error": "This reset link is invalid or has expired."}), 401
    if bcrypt.check_password_hash(user.password_hash, new_password):
        return jsonify({"error": "Choose a password different from the current password."}), 400
    # A conditional update consumes the link once, including concurrent requests.
    consumed = PasswordReset.query.filter_by(id=record.id, consumed_at=None).update(
        {"consumed_at": now}, synchronize_session=False
    )
    if consumed != 1:
        db.session.rollback()
        return jsonify({"error": "This reset link has already been used."}), 401
    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    PasswordReset.query.filter_by(user_id=user.id, consumed_at=None).update(
        {"consumed_at": now}, synchronize_session=False
    )
    db.session.commit()
    return jsonify({"message": "Your password has been reset successfully."}), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    claims = get_jwt()
    db.session.merge(RevokedToken(jti=claims["jti"], expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc).replace(tzinfo=None)))
    RevokedToken.query.filter(RevokedToken.expires_at < utc_now()).delete()
    db.session.commit()
    response = jsonify({"message": "Signed out successfully."})
    unset_jwt_cookies(response)
    return response, 200

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    user = current_user()
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify(serialize_user(user)), 200


@auth_bp.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user = current_user()
    if not user:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    username = str(data.get("username", user.username)).strip()
    email = str(data.get("email", user.email)).strip().lower()
    avatar_icon = str(data.get("avatar_icon", user.avatar_icon or "shield"))
    avatar_color = str(data.get("avatar_color", user.avatar_color or "#38bdf8"))
    current_password = str(data.get("current_password", ""))

    if not username or len(username) > 50 or len(email) > 100 or not EMAIL_PATTERN.match(email):
        return jsonify({"error": "Enter a valid username and email address."}), 400
    if avatar_icon not in ALLOWED_AVATARS or avatar_color not in ALLOWED_COLORS:
        return jsonify({"error": "Invalid avatar selection."}), 400

    identity_changed = username != user.username or email != user.email
    if identity_changed and not bcrypt.check_password_hash(
        user.password_hash, current_password
    ):
        return jsonify({"error": "Current password is required to change account details."}), 400

    duplicate = User.query.filter(
        User.id != user.id,
        or_(User.username == username, User.email == email),
    ).first()
    if duplicate:
        return jsonify({"error": "Username or email address is already in use."}), 409

    if email != user.email:
        PasswordReset.query.filter_by(user_id=user.id, consumed_at=None).update(
            {"consumed_at": utc_now()}, synchronize_session=False
        )
    user.username = username
    user.email = email
    user.avatar_icon = avatar_icon
    user.avatar_color = avatar_color
    db.session.commit()
    return jsonify({"message": "Profile updated successfully.", "user": serialize_user(user)}), 200


@auth_bp.route("/password", methods=["PUT"])
@jwt_required()
def update_password():
    user = current_user()
    if not user:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))

    if not bcrypt.check_password_hash(user.password_hash, current_password):
        return jsonify({"error": "Current password is incorrect."}), 400
    if len(new_password) < 8 or len(new_password.encode("utf-8")) > 72:
        return jsonify({"error": "New password must contain at least 8 characters and at most 72 UTF-8 bytes."}), 400
    if bcrypt.check_password_hash(user.password_hash, new_password):
        return jsonify({"error": "Choose a password different from the current password."}), 400

    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    PasswordReset.query.filter_by(user_id=user.id, consumed_at=None).update(
        {"consumed_at": utc_now()}, synchronize_session=False
    )
    db.session.commit()
    response = jsonify({"message": "Password changed successfully."})
    set_access_cookies(response, create_access_token(identity=str(user.id), additional_claims={"credential_version": hash_reset_token(user.password_hash)}))
    return response, 200


@auth_bp.route("/avatar", methods=["POST"])
@jwt_required()
def upload_avatar():
    return jsonify({"error": "Profile photo uploads are no longer supported."}), 410


@auth_bp.route("/avatar", methods=["DELETE"])
@jwt_required()
def remove_avatar():
    user = current_user()
    if not user:
        return jsonify({"error": "User not found."}), 404

    old_filename = user.avatar_url
    user.avatar_url = None
    db.session.commit()

    if old_filename:
        old_path = AVATAR_DIRECTORY / Path(old_filename).name
        if old_path.is_file():
            old_path.unlink(missing_ok=True)

    return jsonify({"message": "Profile photo removed.", "user": serialize_user(user)}), 200


@auth_bp.route("/avatars/<path:filename>", methods=["GET"])
@jwt_required()
def get_avatar(filename):
    user = current_user()
    if not user or user.avatar_url != filename:
        return jsonify({"error": "Profile image not found."}), 404
    return send_from_directory(AVATAR_DIRECTORY, Path(filename).name, max_age=3600)
