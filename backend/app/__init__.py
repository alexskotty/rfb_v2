from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS


def create_app():
    app = Flask(__name__)

    # -------------------------------------------------
    # Configuration
    # -------------------------------------------------
    app.config["JWT_SECRET_KEY"] = "CHANGE_ME_IN_ENV"  # use env var in prod
    app.config["JSON_SORT_KEYS"] = False

    # -------------------------------------------------
    # Extensions
    # -------------------------------------------------
    JWTManager(app)
    CORS(app)

    # -------------------------------------------------
    # API Blueprint (THIS IS YOUR MAIN API)
    # -------------------------------------------------
    from .routes import bp as api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    # -------------------------------------------------
    # Canary Blueprint (DEPLOYMENT CHECK)
    # -------------------------------------------------
    from .canary import canary_bp
    app.register_blueprint(canary_bp, url_prefix="/api")

    return app
