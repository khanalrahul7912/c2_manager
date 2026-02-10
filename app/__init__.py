from __future__ import annotations

import os

from flask import Flask

from app.config import Config, ProductionConfig
from app.extensions import db, login_manager, migrate
from app.models import User
from app.routes import auth_bp, main_bp


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    config_name = os.getenv("FLASK_ENV", "production").lower()
    app.config.from_object(ProductionConfig if config_name == "production" else Config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    @app.cli.command("create-admin")
    def create_admin() -> None:
        """Create the initial admin account."""
        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD")
        if not password:
            raise SystemExit("Set ADMIN_PASSWORD before running create-admin")

        existing = User.query.filter_by(username=username).first()
        if existing:
            raise SystemExit(f"Admin user '{username}' already exists")

        admin = User(username=username, role="admin")
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Created admin user '{username}'")

    return app
