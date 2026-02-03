import os
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS


def create_app():
    app = Flask(__name__)

    # ----- Config -----
    # Must exist for JWT. Set JWT_SECRET_KEY in Render env vars.
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-insecure-change-me")
    app.config["JSON_SORT_KEYS"] = False

    # ----- Extensions -----
    JWTManager(app)
    CORS(app)

    # ----- Blueprints -----
    from .routes import bp as api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    # (optional) canary – remove later
    try:
        from .canary import canary_bp
        app.register_blueprint(canary_bp, url_prefix="/api")
    except Exception:
        pass

    # ----- JSON error handler -----
    @app.errorhandler(Exception)
    def handle_exception(e):
        # This prints the full traceback in Render logs
        app.logger.exception("Unhandled exception")
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500

    return app
