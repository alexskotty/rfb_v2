from flask import Blueprint, jsonify
from .db import get_conn

bp = Blueprint("api", __name__, url_prefix="/api")

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
