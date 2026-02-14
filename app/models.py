from __future__ import annotations

from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db, login_manager


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="operator", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    group_name = db.Column(db.String(80), nullable=False, default="default")
    port = db.Column(db.Integer, nullable=False, default=22)
    username = db.Column(db.String(80), nullable=False)
    auth_mode = db.Column(db.String(20), nullable=False, default="key")
    key_path = db.Column(db.String(255), nullable=True)
    password_encrypted = db.Column(db.Text, nullable=True)
    strict_host_key = db.Column(db.Boolean, default=True, nullable=False)

    use_jump_host = db.Column(db.Boolean, default=False, nullable=False)
    jump_address = db.Column(db.String(255), nullable=True)
    jump_port = db.Column(db.Integer, nullable=False, default=22)
    jump_username = db.Column(db.String(80), nullable=True)
    jump_auth_mode = db.Column(db.String(20), nullable=False, default="key")
    jump_key_path = db.Column(db.String(255), nullable=True)
    jump_password_encrypted = db.Column(db.Text, nullable=True)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class CommandExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("host.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    command = db.Column(db.Text, nullable=False)
    stdout = db.Column(db.Text, nullable=False, default="")
    stderr = db.Column(db.Text, nullable=False, default="")
    return_code = db.Column(db.Integer, nullable=False, default=-1)
    status = db.Column(db.String(20), nullable=False, default="pending")
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    host = db.relationship("Host", backref="executions")
    user = db.relationship("User", backref="executions")


class ReverseShell(db.Model):
    """Represents a reverse shell connection from a remote machine."""
    __tablename__ = "reverse_shell"
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), unique=True, nullable=True, index=True)  # Unique session identifier
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(255), nullable=False)  # Source IP
    port = db.Column(db.Integer, nullable=False)  # Source port
    group_name = db.Column(db.String(80), nullable=False, default="default")
    platform = db.Column(db.String(50), nullable=True)  # OS detected
    hostname = db.Column(db.String(255), nullable=True)
    shell_user = db.Column(db.String(100), nullable=True)  # Username on remote shell
    status = db.Column(db.String(20), nullable=False, default="disconnected")  # active, disconnected
    connected_at = db.Column(db.DateTime, nullable=True)
    disconnected_at = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)  # Last activity
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    notes = db.Column(db.Text, nullable=True)  # User notes


class ShellExecution(db.Model):
    """Represents a command execution on a reverse shell."""
    __tablename__ = "shell_execution"
    
    id = db.Column(db.Integer, primary_key=True)
    shell_id = db.Column(db.Integer, db.ForeignKey("reverse_shell.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    command = db.Column(db.Text, nullable=False)
    output = db.Column(db.Text, nullable=False, default="")  # Combined stdout
    stdout = db.Column(db.Text, nullable=True)  # Separate stdout
    stderr = db.Column(db.Text, nullable=True)  # Separate stderr
    exit_code = db.Column(db.Integer, nullable=True)  # Exit code if available
    status = db.Column(db.String(20), nullable=False, default="pending")
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    execution_time = db.Column(db.Float, nullable=True)  # Execution time in seconds

    shell = db.relationship("ReverseShell", backref="executions")
    user = db.relationship("User", backref="shell_executions")
