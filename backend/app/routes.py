# backend/app/routes.py
import os
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row

import pyotp

from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity


api_bp = Blueprint("api", __name__)


# -----------------------------
# Database helpers (psycopg v3)
# -----------------------------
def _get_database_url() -> str:
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        raise RuntimeError("DATABASE_URL env var is not set.")
    return db_url


def _connect():
    """
    Connect using Render's DATABASE_URL. Supports either:
    - postgres://  (Render often provides this)
    - postgresql://
    psycopg accepts both, but normalize if needed.
    """
    db_url = _get_database_url()
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    # dict_row gives us dicts back from fetchone/fetchall
    return psycopg.connect(db_url, row_factory=dict_row)


def db_get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Expected users table columns:
      id, username, totp_secret, role, is_active
    """
    sql = """
        SELECT id, username, totp_secret, role, is_active
        FROM users
        WHERE username = %s
        LIMIT 1
        totp_secret = user.get("totp_secret")
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (username,))
            row = cur.fetchone()
            return row


def db_insert_post_job_submission(payload: Dict[str, Any], submitted_by_user_id: int) -> int:
    """
    Minimal insert example.
    Adapt columns to your actual schema.
    """
    sql = """
        INSERT INTO post_job_submissions
            (submitted_by_user_id, job_type_id, turnout_type_id, appliance_id, notes)
        VALUES
            (%s, %s, %s, %s, %s)
        RETURNING id
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    submitted_by_user_id,
                    payload.get("job_type_id"),
                    payload.get("turnout_type_id"),
                    payload.get("appliance_id"),
                    payload.get("notes"),
                ),
            )
            new_id = cur.fetchone()["id"]
            conn.commit()
            return int(new_id)


def db_list_post_job_submissions(limit: int = 50) -> List[Dict[str, Any]]:
    sql = """
        SELECT id, submitted_by_user_id, job_type_id, turnout_type_id, appliance_id, notes, created_at
        FROM post_job_submissions
        ORDER BY created_at DESC
        LIMIT %s
    """
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (limit,))
            return cur.fetchall() or []


# -----------------------------
# Utility helpers
# -----------------------------
def json_body() -> Dict[str, Any]:
    """
    Safe JSON parsing; returns {} instead of raising.
    """
    return request.get_json(silent=True) or {}


def require_fields(data: Dict[str, Any], fields: List[str]) -> Optional[str]:
    """
    Returns missing field name if any required field missing/blank, else None.
    """
    for f in fields:
        v = data.get(f)
        if v is None:
            return f
        if isinstance(v, str) and not v.strip():
            return f
    return None


# -----------------------------
# Routes
# -----------------------------
@api_bp.get("/_canary")
def canary():
    return jsonify({"ok": True, "route": "/api/_canary"}), 200


@api_bp.get("/health")
def health():
    # Optional: check DB connectivity
    db_ok = True
    err = None
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 AS one;")
                cur.fetchone()
    except Exception as e:
        db_ok = False
        err = str(e)

    return jsonify({
        "status": "ok",
        "db_ok": db_ok,
        "db_error": err,
    }), 200


@api_bp.post("/auth/login")
def login():
    # --- targeted logging (THIS IS WHERE IT GOES) ---
    current_app.logger.info("LOGIN %s %s", request.method, request.path)
    current_app.logger.info("LOGIN content_type=%s", request.content_type)

    raw = request.data.decode("utf-8", errors="replace") if request.data else ""
    current_app.logger.info("LOGIN raw_body=%s", raw)

    parsed = request.get_json(silent=True)
    current_app.logger.info("LOGIN parsed_json=%s", parsed)
    # --- end targeted logging ---

    data = parsed or {}

    missing = require_fields(data, ["username", "totp"])
    if missing:
        return jsonify({
            "error": "missing_fields",
            "missing": missing,
            "expected": ["username", "totp"],
        }), 400

    username = str(data.get("username")).strip()
    totp_code = str(data.get("totp")).strip()

    if (not totp_code.isdigit()) or (len(totp_code) != 6):
        return jsonify({
            "error": "invalid_totp_format",
            "message": "totp must be a 6-digit code",
        }), 400

    # Fetch user
    try:
        user = db_get_user_by_username(username)
    except Exception as e:
        current_app.logger.exception("LOGIN db_get_user_by_username failed")
        return jsonify({"error": "db_error", "message": str(e)}), 500

    if not user:
        return jsonify({"error": "invalid_credentials"}), 401

    if not user.get("is_active", False):
        return jsonify({"error": "inactive_user"}), 403

    totp_secret = user.get("totp_secret")
    if not totp_secret:
        return jsonify({"error": "totp_not_configured"}), 409

    # Verify TOTP (valid_window helps minor clock drift)
    if not pyotp.TOTP(totp_secret).verify(totp_code, valid_window=1):
        return jsonify({"error": "invalid_credentials"}), 401

    # JWT
    token = create_access_token(identity={
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
    })
    return jsonify({"access_token": token}), 200


@api_bp.get("/auth/me")
@jwt_required()
def me():
    ident = get_jwt_identity()
    return jsonify({"identity": ident}), 200


@api_bp.get("/refdata")
@jwt_required()
def refdata():
    """
    Placeholder: return reference data.
    Later: job_types, turnout_types, appliances, crew, equipment_items etc.
    For now, return a stub so JWT testing is easy.
    """
    return jsonify({
        "job_types": [],
        "turnout_types": [],
        "appliances": [],
        "crew_members": [],
    }), 200


@api_bp.post("/checklists/post-job")
@jwt_required()
def submit_post_job():
    """
    Placeholder submit route.
    Adjust fields + inserts to match your actual schema.
    """
    data = json_body()
    # minimal set; adjust to your real required fields
    missing = require_fields(data, ["job_type_id", "turnout_type_id", "appliance_id"])
    if missing:
        return jsonify({"error": "missing_fields", "missing": missing}), 400

    ident = get_jwt_identity()
    user_id = ident.get("id") if isinstance(ident, dict) else None
    if not user_id:
        return jsonify({"error": "invalid_jwt_identity"}), 401

    try:
        submission_id = db_insert_post_job_submission(data, submitted_by_user_id=int(user_id))
    except Exception as e:
        current_app.logger.exception("POST-JOB insert failed")
        return jsonify({"error": "db_error", "message": str(e)}), 500

    return jsonify({"ok": True, "submission_id": submission_id}), 201


@api_bp.get("/admin/checklists/post-job/submissions")
@jwt_required()
def admin_list_post_job():
    """
    Placeholder admin list.
    You can later enforce role-based access (role == 'admin').
    """
    ident = get_jwt_identity()
    role = ident.get("role") if isinstance(ident, dict) else None
    if role not in ("admin", "superadmin"):
        return jsonify({"error": "forbidden", "message": "admin role required"}), 403

    limit_raw = request.args.get("limit", "50")
    try:
        limit = max(1, min(200, int(limit_raw)))
    except ValueError:
        limit = 50

    try:
        rows = db_list_post_job_submissions(limit=limit)
    except Exception as e:
        current_app.logger.exception("ADMIN list submissions failed")
        return jsonify({"error": "db_error", "message": str(e)}), 500

    return jsonify({"submissions": rows}), 200
