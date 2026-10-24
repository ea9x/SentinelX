from time_utils import iso_utc
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import or_

from models import User, db


users_bp = Blueprint("users", __name__)
ALLOWED_ROLES = {"admin", "analyst"}


def serialize_user(user):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": bool(user.is_active),
        "avatar_icon": user.avatar_icon or "shield",
        "avatar_color": user.avatar_color or "#38bdf8",
        "avatar_url": (
            f"/api/auth/avatars/{user.avatar_url}" if user.avatar_url else None
        ),
        "created_at": iso_utc(user.created_at) if user.created_at else None,
    }


def get_requesting_admin():
    identity = get_jwt_identity()
    user = db.session.get(User, int(identity)) if identity else None
    if not user:
        return None, (jsonify({"error": "User not found."}), 404)
    if user.role != "admin":
        return None, (
            jsonify({"error": "Administrator access is required."}),
            403,
        )
    if not user.is_active:
        return None, (jsonify({"error": "This account is disabled."}), 403)
    return user, None


@users_bp.route("", methods=["GET"])
@jwt_required()
def list_users():
    _, denied = get_requesting_admin()
    if denied:
        return denied

    search = str(request.args.get("search", "")).strip()
    query = User.query
    if search:
        term = f"%{search}%"
        query = query.filter(
            or_(User.username.ilike(term), User.email.ilike(term))
        )

    users = query.order_by(User.created_at.desc(), User.id.desc()).all()
    return jsonify([serialize_user(user) for user in users]), 200


@users_bp.route("/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    administrator, denied = get_requesting_admin()
    if denied:
        return denied

    target = db.session.get(User, user_id)
    if not target:
        return jsonify({"error": "User not found."}), 404

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required."}), 400
    requested_role = str(data.get("role", target.role)).strip().lower()
    requested_active = data.get("is_active", target.is_active)

    if requested_role not in ALLOWED_ROLES:
        return jsonify({"error": "Invalid user role."}), 400
    if not isinstance(requested_active, bool):
        return jsonify({"error": "is_active must be true or false."}), 400

    if target.id == administrator.id and (
        requested_role != "admin" or not requested_active
    ):
        return jsonify(
            {
                "error": (
                    "You cannot remove your own administrator role "
                    "or disable your own account."
                )
            }
        ), 400

    if target.role == "admin" and (
        requested_role != "admin" or not requested_active
    ):
        other_active_admins = User.query.filter(
            User.id != target.id,
            User.role == "admin",
            User.is_active.is_(True),
        ).count()
        if other_active_admins == 0:
            return jsonify(
                {"error": "At least one active administrator must remain."}
            ), 400

    target.role = requested_role
    target.is_active = requested_active
    db.session.commit()

    return jsonify(
        {
            "message": "User access updated successfully.",
            "user": serialize_user(target),
        }
    ), 200
