from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.engine import make_url


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DB_PATH = (BASE_DIR / "instance" / "app.db").resolve()


def _database_uri() -> str:
    raw = os.getenv("DATABASE_URL", "").strip()
    if not raw:
        return f"sqlite:///{INSTANCE_DB_PATH}"

    url = make_url(raw)
    if url.drivername.startswith("sqlite"):
        db_name = url.database or ""
        if db_name in {":memory:", ""}:
            return raw

        db_path = Path(db_name).expanduser()
        if not db_path.is_absolute():
            db_path = (BASE_DIR / db_path).resolve()
        return f"sqlite:///{db_path}"

    return raw


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "replace-me-in-production")
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REMOTE_COMMAND_TIMEOUT = int(os.getenv("REMOTE_COMMAND_TIMEOUT", "30"))
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    DATA_ENCRYPTION_KEY = os.getenv("DATA_ENCRYPTION_KEY", "")
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    
    # Reverse Shell Listener Configuration
    REVERSE_SHELL_PORT = int(os.getenv("REVERSE_SHELL_PORT", "5000"))
    REVERSE_SHELL_BIND_ADDRESS = os.getenv("REVERSE_SHELL_BIND_ADDRESS", "0.0.0.0")
    REVERSE_SHELL_TIMEOUT = int(os.getenv("REVERSE_SHELL_TIMEOUT", "30"))
    MAX_SHELL_SESSIONS = int(os.getenv("MAX_SHELL_SESSIONS", "100"))
    SHELL_COMMAND_TIMEOUT = int(os.getenv("SHELL_COMMAND_TIMEOUT", "30"))
    
    # SSH Configuration
    MAX_SSH_WORKERS = int(os.getenv("MAX_SSH_WORKERS", "8"))


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
