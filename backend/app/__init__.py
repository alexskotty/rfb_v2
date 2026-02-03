from flask import Flask
from flask_cors import CORS
from .config import Config
from .routes import bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # CORS: set origins via env in production
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    app.register_blueprint(bp)
    return app
