from __future__ import annotations

try:
    from flask_login import LoginManager
    from flask_migrate import Migrate
    from flask_sqlalchemy import SQLAlchemy
except ImportError as exc:
    raise ImportError(
        f"Required Flask extension not found: {exc}. "
        "Please install all dependencies: pip install -r requirements.txt"
    ) from exc


db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"
