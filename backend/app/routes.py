import os
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from flask import Blueprint, jsonify, request

from .db import get_conn
from .security import encrypt_str, decrypt_str, hash_token, sign_jwt, verify_jwt, safe_equals

bp = Blueprint("api", __name__, url_prefix="/api")

@bp.get("/debug/bootstrap")
def debug_bootstrap():
    expected = os.getenv("ADMIN_BOOTSTRAP_KEY", "")
    provided = request.headers.get("X-Admin-Bootstrap-Key", "")
    return jsonify({
        "has_expected": bool(expected),
        "expected_len": len(expected),
        "provided_len": len(provided),
        "match": bool(expected) and safe_equals(expected, provided),
    })


# -------------------------
# Basics
# -------------------------
@bp.get("/health")
def health():
    return jsonify({"status": "ok"})

@bp.get("/db-check")
def db_check():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select 1;")
            cur.fetchone()
    return jsonify({"db": "ok"})

def _client_ip():
    # basic; can improve later with Render headers
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def _audit(action: str, actor_user_id=None, target=None):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "insert into audit_log(actor_user_id, action, target, ip) values (%s,%s,%s,%s)",
                (actor_user_id, action, target, _client_ip()),
            )
        conn.commit()

def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def _require_auth():
    token = _get_bearer_token()
    if not token:
        return None
    try:
        return verify_jwt(token)
    except Exception:
        return None

def _require_admin():
    payload = _require_auth()
    if not payload:
        return None
    if payload.get("role") != "admin":
        return None
    return payload

# -------------------------
# Bootstrap admin creation (first admin)
# -------------------------
def _bootstrap_ok():
    expected = os.getenv("ADMIN_BOOTSTRAP_KEY", "")
    provided = request.headers.get("X-Admin-Bootstrap-Key", "")
    return bool(expected) and safe_equals(expected, provided)

# -------------------------
# Admin: Create user
# -------------------------
@bp.post("/admin/users")
def admin_create_user():
    """
    Creates a user + an enrolment token.
    Authorization:
      - If an admin JWT exists: Bearer token
      - OR bootstrap header for first admin: X-Admin-Bootstrap-Key
    """
    payload = _require_admin()
    if not payload and not _bootstrap_ok():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()
    role = (data.get("role") or "standard").strip().lower()

    if not username or not display_name or role not in ("standard", "admin"):
        return jsonify({"error": "invalid_input"}), 400

    # Generate a TOTP secret for enrolment (stored encrypted in enrol_tokens until confirmed)
    secret = pyotp.random_base32()
    secret_enc = encrypt_str(secret)

    enrol_token = secrets.token_urlsafe(32)
    enrol_token_hash = hash_token(enrol_token)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)

    with get_conn() as conn:
        with conn.cursor() as cur:
            # create user (no totp_secret_enc yet)
            cur.execute(
                """
                insert into users(username, display_name, role, is_active, totp_secret_enc)
                values (%s,%s,%s,true,null)
                returning id
                """,
                (username, display_name, role),
            )
            user_id = cur.fetchone()[0]

            cur.execute(
                """
                insert into enrol_tokens(user_id, token_hash, totp_secret_enc, expires_at)
                values (%s,%s,%s,%s)
                """,
                (user_id, enrol_token_hash, secret_enc, expires),
            )

        conn.commit()

    actor_id = payload.get("user_id") if payload else None
    _audit("admin_create_user", actor_user_id=actor_id, target=f"user:{username}")

    # Provide otpauth URI so admin can share QR/link in whatever way you want
    issuer = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    return jsonify({
        "username": username,
        "display_name": display_name,
        "role": role,
        "enrol_token": enrol_token,
        "otpauth_uri": otpauth_uri,
        "expires_at": expires.isoformat(),
        "enrol_url_hint": f"/api/enrol/{enrol_token}"
    }), 201

# -------------------------
# Enrolment: fetch provisioning URI
# -------------------------
@bp.get("/enrol/<token>")
def enrol_get(token):
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select e.user_id, e.totp_secret_enc, e.expires_at, e.used_at, u.username
                from enrol_tokens e
                join users u on u.id = e.user_id
                where e.token_hash = %s
                """,
                (token_hash,),
            )
            row = cur.fetchone()

    if not row:
        return jsonify({"error": "invalid_token"}), 404

    user_id, secret_enc, expires_at, used_at, username = row
    if used_at is not None:
        return jsonify({"error": "token_used"}), 400
    if expires_at < now:
        return jsonify({"error": "token_expired"}), 400

    secret = decrypt_str(secret_enc)
    issuer = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    return jsonify({"username": username, "otpauth_uri": otpauth_uri})

# -------------------------
# Enrolment: confirm code (activates TOTP for user)
# -------------------------
@bp.post("/enrol/confirm")
def enrol_confirm():
    data = request.get_json(force=True) or {}
    token = (data.get("token") or "").strip()
    code = (data.get("code") or "").strip()

    if not token or not code:
        return jsonify({"error": "invalid_input"}), 400

    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select e.id, e.user_id, e.totp_secret_enc, e.expires_at, e.used_at, u.username
                from enrol_tokens e
                join users u on u.id = e.user_id
                where e.token_hash = %s
                """,
                (token_hash,),
            )
            row = cur.fetchone()

            if not row:
                return jsonify({"error": "invalid_token"}), 404

            enrol_id, user_id, secret_enc, expires_at, used_at, username = row
            if used_at is not None:
                return jsonify({"error": "token_used"}), 400
            if expires_at < now:
                return jsonify({"error": "token_expired"}), 400

            secret = decrypt_str(secret_enc)
            totp = pyotp.TOTP(secret)

            if not totp.verify(code, valid_window=1):
                return jsonify({"error": "invalid_code"}), 400

            # Activate: move secret into users, mark token used
            cur.execute("update users set totp_secret_enc = %s where id = %s", (secret_enc, user_id))
            cur.execute("update enrol_tokens set used_at = now() where id = %s", (enrol_id,))
        conn.commit()

    _audit("enrol_confirm", actor_user_id=user_id, target=f"user:{username}")
    return jsonify({"status": "enrolled"}), 200

# -------------------------
# Login: username + TOTP => JWT
# -------------------------
@bp.post("/auth/login")
def auth_login():
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip().lower()
    code = (data.get("code") or "").strip()

    # generic error responses to avoid user enumeration
    if not username or not code:
        return jsonify({"error": "invalid_login"}), 400

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select id, role, is_active, totp_secret_enc from users where username = %s",
                (username,),
            )
            row = cur.fetchone()

    if not row:
        return jsonify({"error": "invalid_login"}), 401

    user_id, role, is_active, secret_enc = row
    if not is_active or not secret_enc:
        return jsonify({"error": "invalid_login"}), 401

    secret = decrypt_str(secret_enc)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "invalid_login"}), 401

    token = sign_jwt({"user_id": user_id, "username": username, "role": role}, ttl_seconds=8 * 3600)
    _audit("login_success", actor_user_id=user_id, target=f"user:{username}")

    return jsonify({"access_token": token, "token_type": "bearer"}), 200

# -------------------------
# Admin: reset MFA (forces re-enrolment)
# -------------------------
@bp.post("/admin/users/<username>/reset-mfa")
def admin_reset_mfa(username):
    payload = _require_admin()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401

    username = (username or "").strip().lower()
    if not username:
        return jsonify({"error": "invalid_input"}), 400

    # generate new enrol token + new secret
    secret = pyotp.random_base32()
    secret_enc = encrypt_str(secret)
    enrol_token = secrets.token_urlsafe(32)
    enrol_token_hash = hash_token(enrol_token)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select id from users where username = %s", (username,))
            r = cur.fetchone()
            if not r:
                return jsonify({"error": "not_found"}), 404
            user_id = r[0]

            cur.execute("update users set totp_secret_enc = null where id = %s", (user_id,))
            cur.execute(
                "insert into enrol_tokens(user_id, token_hash, totp_secret_enc, expires_at) values (%s,%s,%s,%s)",
                (user_id, enrol_token_hash, secret_enc, expires),
            )
        conn.commit()

    issuer = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    _audit("admin_reset_mfa", actor_user_id=payload["user_id"], target=f"user:{username}")

    return jsonify({
        "username": username,
        "enrol_token": enrol_token,
        "otpauth_uri": otpauth_uri,
        "expires_at": expires.isoformat(),
        "enrol_url_hint": f"/api/enrol/{enrol_token}"
    }), 200
