from __future__ import annotations

import os
import socket
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


def get_public_ip() -> str | None:
    """
    Get public IP address.
    
    Returns:
        Public IP address or None if unavailable
    """
    try:
        import requests
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        return response.json()['ip']
    except Exception:
        try:
            # Fallback method
            import requests
            response = requests.get('https://ifconfig.me/ip', timeout=5)
            return response.text.strip()
        except Exception:
            return None


def get_local_ip() -> str:
    """
    Get local IP address.
    
    Returns:
        Local IP address or '127.0.0.1' if unavailable
    """
    try:
        # Create a socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


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
    
    # Dynamic IP Configuration
    REVERSE_SHELL_PUBLIC_IP = os.getenv("REVERSE_SHELL_PUBLIC_IP") or get_public_ip()
    REVERSE_SHELL_LOCAL_IP = os.getenv("REVERSE_SHELL_LOCAL_IP") or get_local_ip()
    # Which IP to show in connection instructions: 'public', 'local', or specific IP
    REVERSE_SHELL_DISPLAY_IP = os.getenv("REVERSE_SHELL_DISPLAY_IP", "public")
    
    # SSH Configuration
    MAX_SSH_WORKERS = int(os.getenv("MAX_SSH_WORKERS", "8"))


class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
