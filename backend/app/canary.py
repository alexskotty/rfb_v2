from flask import Blueprint

canary_bp = Blueprint("canary", __name__)

@canary_bp.get("/_canary")
def canary():
    return {
        "ok": True,
        "canary": "rfb-v2-canary-live"
    }, 200
