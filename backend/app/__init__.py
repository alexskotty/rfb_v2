from flask import Flask
from flask_cors import CORS
from .config import Config
from .routes import bp
from .schema import ensure_schema

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    # Ensure DB schema exists
    ensure_schema()

    app.register_blueprint(bp)
    return app
