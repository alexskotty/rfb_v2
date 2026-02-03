from flask import Blueprint, jsonify, request

bp = Blueprint("api", __name__, url_prefix="/api")

@bp.get("/health")
def health():
    return jsonify({"ok": True})

# Later:
# - POST /api/auth/start (username -> requires TOTP)
# - POST /api/auth/verify (username + totp -> session)
# - Admin: POST /api/admin/users, POST /api/admin/users/<id>/reset-mfa
# - Checklists: GET templates, POST submissions, GET exports
# - Photos: POST /api/photos/email
