# backend/app/__init__.py
import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager


jwt = JWTManager()


def register_error_handlers(app: Flask) -> None:
    """
    Force JSON errors (no HTML pages).
    """
    @app.errorhandler(400)
    def handle_400(e):
        return jsonify({
            "error": "bad_request",
            "message": getattr(e, "description", "Bad request"),
        }), 400

    @app.errorhandler(401)
    def handle_401(e):
        return jsonify({
            "error": "unauthorized",
            "message": getattr(e, "description", "Unauthorized"),
        }), 401

    @app.errorhandler(403)
    def handle_403(e):
        return jsonify({
            "error": "forbidden",
            "message": getattr(e, "description", "Forbidden"),
        }), 403

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({
            "error": "not_found",
            "message": "Route not found",
            "path": getattr(e, "name", None),
        }), 404

    @app.errorhandler(500)
    def handle_500(e):
        # Avoid leaking internals; rely on logs for details
        return jsonify({
            "error": "server_error",
            "message": "Internal server error",
        }), 500


def configure_logging(app: Flask) -> None:
    """
    Render logs are stdout/stderr. Keep it simple.
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")
    app.logger.setLevel(level)


def create_app() -> Flask:
    app = Flask(__name__)

    configure_logging(app)

    # --- Config ---
    # REQUIRED on Render
    app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "")
    if not app.config["JWT_SECRET_KEY"]:
        # Not fatal at import time, but will break JWT creation. Log clearly.
        app.logger.warning("JWT_SECRET_KEY is not set. Login/JWT will fail until set in env.")

    # CORS: lock down later; for now allow web+mobile wrappers to talk to API
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

    # JWT
    jwt.init_app(app)

    # JSON error handlers
    register_error_handlers(app)

    # --- Blueprints ---
    # Single blueprint that carries all routes under /api
    from .routes import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    # Small “root” sanity (optional)
    @app.get("/")
    def root():
        return jsonify({"service": "rfb-v2-api", "status": "ok"}), 200

    return app
