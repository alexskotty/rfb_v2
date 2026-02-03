import os
import csv
import io
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    jwt_required,
    create_access_token,
    get_jwt_identity,
)
import pyotp

import psycopg
from psycopg.rows import dict_row
from psycopg.errors import UniqueViolation

bp = Blueprint("api", __name__)


# ----------------------------
# Helpers
# ----------------------------

def _now_utc():
    return datetime.now(timezone.utc)


def get_db():
    """
    psycopg v3 connection.
    Expects DATABASE_URL set (Render sets it automatically if you add Postgres).
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")

    # row_factory=dict_row gives dict rows like RealDictCursor used to.
    return psycopg.connect(dsn, row_factory=dict_row)


def require_json():
    if not request.is_json:
        return None, (jsonify({"error": "Request must be application/json"}), 400)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"error": "Invalid JSON body"}), 400)
    return data, None


def require_file(field_name="file"):
    if field_name not in request.files:
        return None, (jsonify({"error": f"Missing file field '{field_name}'"}), 400)
    f = request.files[field_name]
    if not f or not f.filename:
        return None, (jsonify({"error": "No file provided"}), 400)
    return f, None


def parse_csv_upload(uploaded_file):
    """
    Returns list[dict] from a CSV file upload.
    """
    raw = uploaded_file.read()
    # handle utf-8-sig for Excel exports
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for r in reader:
        # normalize keys/values
        rows.append({(k or "").strip(): (v or "").strip() for k, v in r.items()})
    return rows


def _get_user_by_username(cur, username: str):
    cur.execute(
        """
        SELECT id, username, role, totp_secret, is_active
        FROM users
        WHERE username = %s
        """,
        (username,),
    )
    return cur.fetchone()


def _is_admin_role(role_value: str) -> bool:
    return (role_value or "").lower() == "admin"


def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        # We store identity as a dict in token below; support both dict and int
        user_id = identity.get("user_id") if isinstance(identity, dict) else identity

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
                if not row or not _is_admin_role(row["role"]):
                    return jsonify({"error": "Admin access required"}), 403
        finally:
            conn.close()

        return fn(*args, **kwargs)

    return wrapper


# ----------------------------
# Health
# ----------------------------

@bp.get("/health")
def health():
    return jsonify({"ok": True}), 200


# ----------------------------
# Auth
# ----------------------------

@bp.post("/auth/login")
def login():
    """
    Passwordless login:
    Body: { "username": "...", "totp": "123456" }
    Returns: { "access_token": "...", "role": "...", "user_id": ... }
    """
    data, err = require_json()
    if err:
        return err

    username = (data.get("username") or "").strip()
    totp_code = (data.get("totp") or "").strip()

    if not username or not totp_code:
        return jsonify({"error": "username and totp are required"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            user = _get_user_by_username(cur, username)
            if not user:
                return jsonify({"error": "Invalid credentials"}), 401
            if not user.get("is_active", True):
                return jsonify({"error": "User is inactive"}), 403

            secret = user.get("totp_secret")
            if not secret:
                return jsonify({"error": "User is not enrolled for MFA"}), 403

            if not pyotp.TOTP(secret).verify(totp_code, valid_window=1):
                return jsonify({"error": "Invalid credentials"}), 401

            identity = {"user_id": user["id"], "role": user["role"], "username": user["username"]}
            token = create_access_token(identity=identity)

            return jsonify(
                {
                    "access_token": token,
                    "role": user["role"],
                    "user_id": user["id"],
                }
            ), 200
    finally:
        conn.close()


# ----------------------------
# Ref data
# ----------------------------

@bp.get("/refdata")
@jwt_required(optional=True)
def refdata():
    """
    Returns reference data used by the app.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM crew_members ORDER BY id")
            crew = cur.fetchall()

            cur.execute("SELECT * FROM appliances ORDER BY id")
            appliances = cur.fetchall()

            cur.execute("SELECT * FROM job_types ORDER BY id")
            job_types = cur.fetchall()

            cur.execute("SELECT * FROM turnout_types ORDER BY id")
            turnout_types = cur.fetchall()

            cur.execute("SELECT * FROM equipment_items ORDER BY id")
            equipment = cur.fetchall()

        return jsonify(
            {
                "crew": crew,
                "appliances": appliances,
                "job_types": job_types,
                "turnout_types": turnout_types,
                "equipment": equipment,
            }
        ), 200
    finally:
        conn.close()


@bp.get("/appliances/<int:appliance_id>/equipment")
@jwt_required(optional=True)
def equipment_for_appliance(appliance_id: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM equipment_items WHERE appliance_id = %s ORDER BY id",
                (appliance_id,),
            )
            rows = cur.fetchall()
        return jsonify({"appliance_id": appliance_id, "equipment": rows}), 200
    finally:
        conn.close()


# ----------------------------
# Admin CSV imports
# ----------------------------

def _import_appliances(rows):
    """
    Expected columns (case-insensitive):
    - name (required)
    Optional:
    - callsign
    - active (true/false)
    """
    conn = get_db()
    inserted = 0
    updated = 0

    try:
        with conn:
            with conn.cursor() as cur:
                for r in rows:
                    name = r.get("name") or r.get("Name")
                    if not name:
                        continue
                    callsign = r.get("callsign") or r.get("Callsign") or None
                    active_raw = (r.get("active") or r.get("Active") or "true").lower()
                    active = active_raw not in ("0", "false", "no", "n")

                    # assumes UNIQUE(name) exists; if not, it will insert duplicates
                    cur.execute(
                        """
                        INSERT INTO appliances (name, callsign, active)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (name) DO UPDATE
                        SET callsign = EXCLUDED.callsign,
                            active = EXCLUDED.active
                        """,
                        (name, callsign, active),
                    )
        # We can’t reliably count upserts without extra queries; return total rows processed.
        inserted = len([r for r in rows if (r.get("name") or r.get("Name"))])
        return inserted, updated
    finally:
        conn.close()


def _import_job_types(rows):
    """
    Expected: name (required)
    """
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for r in rows:
                    name = r.get("name") or r.get("Name")
                    if not name:
                        continue
                    cur.execute(
                        """
                        INSERT INTO job_types (name)
                        VALUES (%s)
                        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
                        """,
                        (name,),
                    )
        return len([r for r in rows if (r.get("name") or r.get("Name"))]), 0
    finally:
        conn.close()


def _import_turnout_types(rows):
    """
    Expected: code (required), name (optional)
    Example: code=1, name=Code 1
    """
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for r in rows:
                    code = r.get("code") or r.get("Code")
                    if not code:
                        continue
                    name = r.get("name") or r.get("Name") or None
                    cur.execute(
                        """
                        INSERT INTO turnout_types (code, name)
                        VALUES (%s, %s)
                        ON CONFLICT (code) DO UPDATE
                        SET name = EXCLUDED.name
                        """,
                        (code, name),
                    )
        return len([r for r in rows if (r.get("code") or r.get("Code"))]), 0
    finally:
        conn.close()


def _import_crew(rows):
    """
    Expected: name (required)
    Optional: email, active
    """
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for r in rows:
                    name = r.get("name") or r.get("Name")
                    if not name:
                        continue
                    email = r.get("email") or r.get("Email") or None
                    active_raw = (r.get("active") or r.get("Active") or "true").lower()
                    active = active_raw not in ("0", "false", "no", "n")

                    cur.execute(
                        """
                        INSERT INTO crew_members (name, email, active)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (name) DO UPDATE
                        SET email = EXCLUDED.email,
                            active = EXCLUDED.active
                        """,
                        (name, email, active),
                    )
        return len([r for r in rows if (r.get("name") or r.get("Name"))]), 0
    finally:
        conn.close()


def _import_equipment(rows):
    """
    Expected columns:
    - appliance_id (required) OR appliance_name (required)
    - name (required)
    Optional:
    - active
    """
    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                for r in rows:
                    name = r.get("name") or r.get("Name")
                    if not name:
                        continue

                    appliance_id = r.get("appliance_id") or r.get("ApplianceId") or None
                    appliance_name = r.get("appliance_name") or r.get("ApplianceName") or None

                    if appliance_id:
                        appliance_id = int(appliance_id)
                    else:
                        if not appliance_name:
                            continue
                        cur.execute("SELECT id FROM appliances WHERE name = %s", (appliance_name,))
                        ap = cur.fetchone()
                        if not ap:
                            continue
                        appliance_id = ap["id"]

                    active_raw = (r.get("active") or r.get("Active") or "true").lower()
                    active = active_raw not in ("0", "false", "no", "n")

                    # assumes UNIQUE(appliance_id, name)
                    cur.execute(
                        """
                        INSERT INTO equipment_items (appliance_id, name, active)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (appliance_id, name) DO UPDATE
                        SET active = EXCLUDED.active
                        """,
                        (appliance_id, name, active),
                    )
        return len([r for r in rows if (r.get("name") or r.get("Name"))]), 0
    finally:
        conn.close()


@bp.post("/admin/import/appliances")
@admin_required
def admin_import_appliances():
    f, err = require_file("file")
    if err:
        return err
    rows = parse_csv_upload(f)
    total, _ = _import_appliances(rows)
    return jsonify({"ok": True, "imported": total}), 200


@bp.post("/admin/import/job-types")
@admin_required
def admin_import_job_types():
    f, err = require_file("file")
    if err:
        return err
    rows = parse_csv_upload(f)
    total, _ = _import_job_types(rows)
    return jsonify({"ok": True, "imported": total}), 200


@bp.post("/admin/import/turnout-types")
@admin_required
def admin_import_turnout_types():
    f, err = require_file("file")
    if err:
        return err
    rows = parse_csv_upload(f)
    total, _ = _import_turnout_types(rows)
    return jsonify({"ok": True, "imported": total}), 200


@bp.post("/admin/import/crew")
@admin_required
def admin_import_crew():
    f, err = require_file("file")
    if err:
        return err
    rows = parse_csv_upload(f)
    total, _ = _import_crew(rows)
    return jsonify({"ok": True, "imported": total}), 200


@bp.post("/admin/import/equipment")
@admin_required
def admin_import_equipment():
    f, err = require_file("file")
    if err:
        return err
    rows = parse_csv_upload(f)
    total, _ = _import_equipment(rows)
    return jsonify({"ok": True, "imported": total}), 200


# ----------------------------
# Checklists: Post-job submit
# ----------------------------

@bp.post("/checklists/post-job")
@jwt_required()
def submit_post_job():
    """
    JSON:
    {
      "job_number": "string optional",
      "job_type_id": int required,
      "turnout_type_id": int required,
      "appliance_id": int required,
      "date_started": "ISO optional",
      "date_finished": "ISO optional",
      "location": "string optional",
      "notes": "string optional",
      "crew_member_ids": [int],
      "equipment_item_ids": [int]
    }
    """
    data, err = require_json()
    if err:
        return err

    required = ["job_type_id", "turnout_type_id", "appliance_id"]
    missing = [k for k in required if data.get(k) in (None, "", [])]
    if missing:
        return jsonify({"error": "Missing required fields", "missing": missing}), 400

    crew_member_ids = data.get("crew_member_ids") or []
    equipment_item_ids = data.get("equipment_item_ids") or []
    if not isinstance(crew_member_ids, list) or not all(isinstance(x, int) for x in crew_member_ids):
        return jsonify({"error": "crew_member_ids must be list[int]"}), 400
    if not isinstance(equipment_item_ids, list) or not all(isinstance(x, int) for x in equipment_item_ids):
        return jsonify({"error": "equipment_item_ids must be list[int]"}), 400

    def parse_dt(s):
        if not s:
            return None
        try:
            s2 = str(s).replace("Z", "+00:00")
            return datetime.fromisoformat(s2)
        except Exception:
            return None

    date_started = parse_dt(data.get("date_started"))
    date_finished = parse_dt(data.get("date_finished"))

    identity = get_jwt_identity()
    user_id = identity.get("user_id") if isinstance(identity, dict) else identity

    conn = get_db()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO post_job_submissions
                    (job_number, job_type_id, turnout_type_id, appliance_id,
                     date_started, date_finished, location, notes,
                     created_by_user_id, created_at)
                    VALUES
                    (%s,%s,%s,%s,
                     %s,%s,%s,%s,
                     %s,%s)
                    RETURNING id
                    """,
                    (
                        data.get("job_number"),
                        int(data["job_type_id"]),
                        int(data["turnout_type_id"]),
                        int(data["appliance_id"]),
                        date_started,
                        date_finished,
                        data.get("location"),
                        data.get("notes"),
                        user_id,
                        _now_utc(),
                    ),
                )
                submission_id = cur.fetchone()["id"]

                if crew_member_ids:
                    cur.executemany(
                        """
                        INSERT INTO post_job_submission_crew (submission_id, crew_member_id)
                        VALUES (%s, %s)
                        """,
                        [(submission_id, int(cid)) for cid in crew_member_ids],
                    )

                if equipment_item_ids:
                    cur.executemany(
                        """
                        INSERT INTO post_job_submission_items (submission_id, equipment_item_id)
                        VALUES (%s, %s)
                        """,
                        [(submission_id, int(eid)) for eid in equipment_item_ids],
                    )

        return jsonify({"ok": True, "submission_id": submission_id}), 201
    finally:
        conn.close()


# ----------------------------
# Admin: view submissions
# ----------------------------

@bp.get("/admin/checklists/post-job/submissions")
@admin_required
def list_post_job_submissions():
    """
    Returns basic submission list with linked crew + equipment ids.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  s.*,
                  jt.name AS job_type_name,
                  tt.code AS turnout_type_code,
                  a.name AS appliance_name
                FROM post_job_submissions s
                LEFT JOIN job_types jt ON jt.id = s.job_type_id
                LEFT JOIN turnout_types tt ON tt.id = s.turnout_type_id
                LEFT JOIN appliances a ON a.id = s.appliance_id
                ORDER BY s.id DESC
                LIMIT 200
                """
            )
            subs = cur.fetchall()

            # attach crew + equipment
            sub_ids = [s["id"] for s in subs]
            crew_map = {sid: [] for sid in sub_ids}
            eq_map = {sid: [] for sid in sub_ids}

            if sub_ids:
                cur.execute(
                    """
                    SELECT submission_id, crew_member_id
                    FROM post_job_submission_crew
                    WHERE submission_id = ANY(%s)
                    """,
                    (sub_ids,),
                )
                for r in cur.fetchall():
                    crew_map[r["submission_id"]].append(r["crew_member_id"])

                cur.execute(
                    """
                    SELECT submission_id, equipment_item_id
                    FROM post_job_submission_items
                    WHERE submission_id = ANY(%s)
                    """,
                    (sub_ids,),
                )
                for r in cur.fetchall():
                    eq_map[r["submission_id"]].append(r["equipment_item_id"])

            for s in subs:
                sid = s["id"]
                s["crew_member_ids"] = crew_map.get(sid, [])
                s["equipment_item_ids"] = eq_map.get(sid, [])

        return jsonify({"submissions": subs}), 200
    finally:
        conn.close()
