# backend/app/routes.py
import os
import io
import csv
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from flask import Blueprint, jsonify, request
from psycopg.errors import UniqueViolation

from .db import get_conn
from .security import encrypt_str, decrypt_str, hash_token, sign_jwt, verify_jwt, safe_equals

bp = Blueprint("api", __name__, url_prefix="/api")

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


# -------------------------
# Helpers
# -------------------------
def _client_ip():
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

def _require_user():
    payload = _require_auth()
    if not payload:
        return None
    return payload

def _require_admin():
    payload = _require_auth()
    if not payload:
        return None
    if payload.get("role") != "admin":
        return None
    return payload

def _bootstrap_ok():
    expected = os.getenv("ADMIN_BOOTSTRAP_KEY", "")
    provided = request.headers.get("X-Admin-Bootstrap-Key", "")
    return bool(expected) and safe_equals(expected, provided)

def _read_uploaded_csv():
    """
    Reads multipart upload under field name 'file', returns (reader, raw_text).
    """
    if "file" not in request.files:
        return None, None
    f = request.files["file"]
    raw = f.read().decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    return reader, raw


# -------------------------
# Auth: Login (username + TOTP) => JWT
# -------------------------
@bp.post("/auth/login")
def auth_login():
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip().lower()
    code = (data.get("code") or "").strip()

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
    if (not is_active) or (not secret_enc):
        return jsonify({"error": "invalid_login"}), 401

    secret = decrypt_str(secret_enc)
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "invalid_login"}), 401

    token = sign_jwt({"user_id": user_id, "username": username, "role": role}, ttl_seconds=8 * 3600)
    _audit("login_success", actor_user_id=user_id, target=f"user:{username}")
    return jsonify({"access_token": token, "token_type": "bearer"}), 200


# -------------------------
# Admin: Create user (bootstrap header OR admin JWT)
# -------------------------
@bp.post("/admin/users")
def admin_create_user():
    payload = _require_admin()
    if not payload and not _bootstrap_ok():
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()
    role = (data.get("role") or "standard").strip().lower()

    if not username or not display_name or role not in ("standard", "admin"):
        return jsonify({"error": "invalid_input"}), 400

    secret = pyotp.random_base32()
    secret_enc = encrypt_str(secret)

    enrol_token = secrets.token_urlsafe(32)
    enrol_token_hash = hash_token(enrol_token)
    expires = datetime.now(timezone.utc) + timedelta(hours=24)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
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
    except UniqueViolation:
        return jsonify({"error": "username_taken"}), 409

    actor_id = payload.get("user_id") if payload else None
    _audit("admin_create_user", actor_user_id=actor_id, target=f"user:{username}")

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
# Enrolment: get otpauth URI by token
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

    _, secret_enc, expires_at, used_at, username = row
    if used_at is not None:
        return jsonify({"error": "token_used"}), 400
    if expires_at < now:
        return jsonify({"error": "token_expired"}), 400

    secret = decrypt_str(secret_enc)
    issuer = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    return jsonify({"username": username, "otpauth_uri": otpauth_uri}), 200


# -------------------------
# Enrolment: confirm code -> activates user TOTP secret
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

            cur.execute("update users set totp_secret_enc = %s where id = %s", (secret_enc, user_id))
            cur.execute("update enrol_tokens set used_at = now() where id = %s", (enrol_id,))
        conn.commit()

    _audit("enrol_confirm", actor_user_id=user_id, target=f"user:{username}")
    return jsonify({"status": "enrolled"}), 200


# -------------------------
# Admin: Reset MFA (forces re-enrolment)
# -------------------------
@bp.post("/admin/users/<username>/reset-mfa")
def admin_reset_mfa(username):
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    username = (username or "").strip().lower()
    if not username:
        return jsonify({"error": "invalid_input"}), 400

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
                """
                insert into enrol_tokens(user_id, token_hash, totp_secret_enc, expires_at)
                values (%s,%s,%s,%s)
                """,
                (user_id, enrol_token_hash, secret_enc, expires),
            )
        conn.commit()

    issuer = os.getenv("TOTP_ISSUER", "Rutherglen Fire Brigade")
    otpauth_uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

    _audit("admin_reset_mfa", actor_user_id=admin["user_id"], target=f"user:{username}")
    return jsonify({
        "username": username,
        "enrol_token": enrol_token,
        "otpauth_uri": otpauth_uri,
        "expires_at": expires.isoformat(),
        "enrol_url_hint": f"/api/enrol/{enrol_token}"
    }), 200


# -------------------------
# Reference data (read-only for logged-in users)
# -------------------------
@bp.get("/refdata")
def get_refdata():
    payload = _require_user()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select name from crew_members where is_active = true order by name;")
            crew = [r[0] for r in cur.fetchall()]

            cur.execute("select id, code, name from appliances where is_active = true order by code;")
            appliances = [{"id": r[0], "code": r[1], "name": r[2]} for r in cur.fetchall()]

            cur.execute("select name from job_types where is_active = true order by name;")
            job_types = [r[0] for r in cur.fetchall()]

            cur.execute("select name from turnout_types where is_active = true order by name;")
            turnout_types = [r[0] for r in cur.fetchall()]

    return jsonify({
        "crew": crew,
        "appliances": appliances,
        "job_types": job_types,
        "turnout_types": turnout_types
    }), 200


@bp.get("/appliances/<int:appliance_id>/equipment")
def get_appliance_equipment(appliance_id: int):
    payload = _require_user()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select name from equipment_items
                where appliance_id = %s
                order by sort_order, name
                """,
                (appliance_id,),
            )
            items = [r[0] for r in cur.fetchall()]

    return jsonify({"appliance_id": appliance_id, "equipment": items}), 200


# -------------------------
# Admin: Single-item endpoints (handy for quick edits)
# -------------------------
@bp.post("/admin/crew")
def admin_add_crew():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "invalid_input"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("insert into crew_members(name, is_active) values (%s, true)", (name,))
            conn.commit()
    except UniqueViolation:
        return jsonify({"error": "already_exists"}), 409

    _audit("admin_add_crew", actor_user_id=admin["user_id"], target=f"crew:{name}")
    return jsonify({"status": "created", "name": name}), 201


@bp.post("/admin/job-types")
def admin_add_job_type():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "invalid_input"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("insert into job_types(name, is_active) values (%s, true)", (name,))
            conn.commit()
    except UniqueViolation:
        return jsonify({"error": "already_exists"}), 409

    _audit("admin_add_job_type", actor_user_id=admin["user_id"], target=f"job_type:{name}")
    return jsonify({"status": "created", "name": name}), 201


@bp.post("/admin/turnout-types")
def admin_add_turnout_type():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "invalid_input"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("insert into turnout_types(name, is_active) values (%s, true)", (name,))
            conn.commit()
    except UniqueViolation:
        return jsonify({"error": "already_exists"}), 409

    _audit("admin_add_turnout_type", actor_user_id=admin["user_id"], target=f"turnout_type:{name}")
    return jsonify({"status": "created", "name": name}), 201


@bp.post("/admin/appliances")
def admin_add_appliance():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    code = (data.get("code") or "").strip().upper()
    name = (data.get("name") or "").strip()

    if not code or not name:
        return jsonify({"error": "invalid_input"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "insert into appliances(code, name, is_active) values (%s, %s, true) returning id",
                    (code, name),
                )
                appliance_id = cur.fetchone()[0]
            conn.commit()
    except UniqueViolation:
        return jsonify({"error": "already_exists"}), 409

    _audit("admin_add_appliance", actor_user_id=admin["user_id"], target=f"appliance:{code}")
    return jsonify({"status": "created", "id": appliance_id, "code": code, "name": name}), 201


@bp.post("/admin/appliances/<int:appliance_id>/equipment")
def admin_add_equipment(appliance_id: int):
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    sort_order = data.get("sort_order", 0)

    if not name:
        return jsonify({"error": "invalid_input"}), 400

    try:
        sort_order = int(sort_order)
    except Exception:
        return jsonify({"error": "invalid_sort_order"}), 400

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select 1 from appliances where id = %s", (appliance_id,))
                if not cur.fetchone():
                    return jsonify({"error": "appliance_not_found"}), 404

                cur.execute(
                    """
                    insert into equipment_items(appliance_id, name, sort_order)
                    values (%s, %s, %s)
                    """,
                    (appliance_id, name, sort_order),
                )
            conn.commit()
    except UniqueViolation:
        return jsonify({"error": "already_exists"}), 409

    _audit("admin_add_equipment", actor_user_id=admin["user_id"], target=f"equipment:{appliance_id}:{name}")
    return jsonify({"status": "created", "appliance_id": appliance_id, "name": name, "sort_order": sort_order}), 201


# -------------------------
# Admin: CSV import endpoints (multipart/form-data field "file")
# -------------------------

@bp.post("/admin/import/crew")
def admin_import_crew():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    reader, _ = _read_uploaded_csv()
    if reader is None:
        return jsonify({"error": "missing_file"}), 400

    inserted = 0
    skipped = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in reader:
                name = (row.get("name") or "").strip()
                if not name:
                    skipped += 1
                    continue
                try:
                    cur.execute("insert into crew_members(name, is_active) values (%s, true)", (name,))
                    inserted += 1
                except UniqueViolation:
                    skipped += 1
            conn.commit()

    _audit("admin_import_crew", actor_user_id=admin["user_id"], target=f"inserted:{inserted},skipped:{skipped}")
    return jsonify({"status": "ok", "inserted": inserted, "skipped": skipped}), 200


@bp.post("/admin/import/job-types")
def admin_import_job_types():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    reader, _ = _read_uploaded_csv()
    if reader is None:
        return jsonify({"error": "missing_file"}), 400

    inserted = 0
    skipped = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in reader:
                name = (row.get("name") or "").strip()
                if not name:
                    skipped += 1
                    continue
                try:
                    cur.execute("insert into job_types(name, is_active) values (%s, true)", (name,))
                    inserted += 1
                except UniqueViolation:
                    skipped += 1
            conn.commit()

    _audit("admin_import_job_types", actor_user_id=admin["user_id"], target=f"inserted:{inserted},skipped:{skipped}")
    return jsonify({"status": "ok", "inserted": inserted, "skipped": skipped}), 200


@bp.post("/admin/import/turnout-types")
def admin_import_turnout_types():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    reader, _ = _read_uploaded_csv()
    if reader is None:
        return jsonify({"error": "missing_file"}), 400

    inserted = 0
    skipped = 0
    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in reader:
                name = (row.get("name") or "").strip()
                if not name:
                    skipped += 1
                    continue
                try:
                    cur.execute("insert into turnout_types(name, is_active) values (%s, true)", (name,))
                    inserted += 1
                except UniqueViolation:
                    skipped += 1
            conn.commit()

    _audit("admin_import_turnout_types", actor_user_id=admin["user_id"], target=f"inserted:{inserted},skipped:{skipped}")
    return jsonify({"status": "ok", "inserted": inserted, "skipped": skipped}), 200


@bp.post("/admin/import/appliances")
def admin_import_appliances():
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    reader, _ = _read_uploaded_csv()
    if reader is None:
        return jsonify({"error": "missing_file"}), 400

    inserted = 0
    skipped = 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in reader:
                code = (row.get("code") or "").strip().upper()
                name = (row.get("name") or "").strip()
                if not code or not name:
                    skipped += 1
                    continue
                try:
                    cur.execute("insert into appliances(code, name, is_active) values (%s, %s, true)", (code, name))
                    inserted += 1
                except UniqueViolation:
                    skipped += 1
            conn.commit()

    _audit("admin_import_appliances", actor_user_id=admin["user_id"], target=f"inserted:{inserted},skipped:{skipped}")
    return jsonify({"status": "ok", "inserted": inserted, "skipped": skipped}), 200


@bp.post("/admin/import/equipment")
def admin_import_equipment():
    """
    CSV columns required:
      appliance_code, name
    Optional:
      sort_order

    Example row:
      PUMPER,BA Set,10
    """
    admin = _require_admin()
    if not admin:
        return jsonify({"error": "unauthorized"}), 401

    reader, _ = _read_uploaded_csv()
    if reader is None:
        return jsonify({"error": "missing_file"}), 400

    inserted = 0
    skipped = 0
    missing_appliance = 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for row in reader:
                appliance_code = (row.get("appliance_code") or "").strip().upper()
                name = (row.get("name") or "").strip()
                sort_order_raw = (row.get("sort_order") or "0").strip()

                if not appliance_code or not name:
                    skipped += 1
                    continue

                try:
                    sort_order = int(sort_order_raw) if sort_order_raw else 0
                except Exception:
                    sort_order = 0

                cur.execute("select id from appliances where code = %s", (appliance_code,))
                r = cur.fetchone()
                if not r:
                    missing_appliance += 1
                    continue

                appliance_id = r[0]
                try:
                    cur.execute(
                        "insert into equipment_items(appliance_id, name, sort_order) values (%s, %s, %s)",
                        (appliance_id, name, sort_order),
                    )
                    inserted += 1
                except UniqueViolation:
                    skipped += 1

            conn.commit()

    _audit(
        "admin_import_equipment",
        actor_user_id=admin["user_id"],
        target=f"inserted:{inserted},skipped:{skipped},missing_appliance:{missing_appliance}"
    )
    return jsonify({
        "status": "ok",
        "inserted": inserted,
        "skipped": skipped,
        "missing_appliance": missing_appliance
    }), 200
