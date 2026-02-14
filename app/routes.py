from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

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


@main_bp.route("/")
@login_required
def dashboard():
    group = request.args.get("group", "").strip()
    host_page = _page_arg("host_page")
    run_page = _page_arg("run_page")

    host_query = Host.query.order_by(Host.name.asc())
    if group:
        host_query = host_query.filter(Host.group_name == group)

    hosts_pagination = host_query.paginate(page=host_page, per_page=PAGE_SIZE_DEFAULT, error_out=False)
    runs_pagination = CommandExecution.query.order_by(CommandExecution.started_at.desc()).paginate(
        page=run_page, per_page=PAGE_SIZE_DEFAULT, error_out=False
    )

    groups = [value[0] for value in db.session.query(Host.group_name).distinct().all() if value[0]]
    return render_template(
        "dashboard.html",
        hosts=hosts_pagination.items,
        hosts_pagination=hosts_pagination,
        recent_commands=runs_pagination.items,
        runs_pagination=runs_pagination,
        groups=sorted(groups),
        selected_group=group,
    )


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
    """Run SSH command for a host. Target and jump_host must be built before calling."""
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
    form = BulkCommandForm()
    hosts = Host.query.filter_by(is_active=True).order_by(Host.group_name.asc(), Host.name.asc()).all()
    form.host_ids.choices = [
        (host.id, f"[{host.group_name}] {host.name} ({host.username}@{host.address}:{host.port})") for host in hosts
    ]

    if form.validate_on_submit():
        selected_hosts = [host for host in hosts if host.id in form.host_ids.data]
        if not selected_hosts:
            flash("Select at least one host.", "warning")
            return redirect(url_for("main.bulk_operations"))

        command = form.command.data.strip()
        max_workers = min(max(len(selected_hosts), 1), 8)
        success_count = 0
        failure_count = 0

        timeout = current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30)
        user_id = current_user.id  # Get user_id before thread pool
        app = current_app._get_current_object()  # Get app instance for thread context
        execution_map = {host.id: _create_execution(host, command, user_id) for host in selected_hosts}

        # Build SSH endpoints before ThreadPoolExecutor to avoid app context issues
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
                    # Re-query to get updated status
                    with app.app_context():
                        execution = db.session.get(CommandExecution, execution.id)
                        if execution.status == "success":
                            success_count += 1
                        else:
                            failure_count += 1
                except Exception as exc:  # pragma: no cover
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

        flash(f"Bulk execution finished: {success_count} success, {failure_count} failed.", "info")
        return redirect(url_for("main.bulk_operations"))

    run_page = _page_arg("page")
    runs_pagination = CommandExecution.query.order_by(CommandExecution.started_at.desc()).paginate(
        page=run_page, per_page=PAGE_SIZE_DEFAULT, error_out=False
    )
    return render_template(
        "bulk_operations.html",
        form=form,
        recent_bulk=runs_pagination.items,
        runs_pagination=runs_pagination,
    )


@main_bp.route("/hosts/<int:host_id>", methods=["GET", "POST"])
@login_required
def host_detail(host_id: int):
    host = db.get_or_404(Host, host_id)
    form = CommandForm()

    if form.validate_on_submit():
        command = form.command.data.strip()
        execution = _create_execution(host, command, current_user.id)
        result = _run_command_for_host(host, command, current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30))[1]
        app = current_app._get_current_object()
        _complete_execution(app, execution.id, result)
        # Re-query execution to get updated status
        execution = db.session.get(CommandExecution, execution.id)
        flash(f"Command completed with status {execution.status}.", "info")
        return redirect(url_for("main.host_detail", host_id=host.id))

    page = _page_arg("page")
    executions_pagination = CommandExecution.query.filter_by(host_id=host.id).order_by(
        CommandExecution.started_at.desc()
    ).paginate(page=page, per_page=PAGE_SIZE_DEFAULT, error_out=False)

    return render_template(
        "host_detail.html",
        host=host,
        form=form,
        executions=executions_pagination.items,
        executions_pagination=executions_pagination,
    )


# ============================================================================
# Reverse Shell Routes
# ============================================================================


@main_bp.route("/shells")
@login_required
def shells_dashboard():
    """Dashboard for reverse shell connections."""
    group = request.args.get("group", "").strip()
    page = _page_arg("page")
    
    shell_query = ReverseShell.query.order_by(ReverseShell.last_seen.desc().nullslast(), ReverseShell.name.asc())
    if group:
        shell_query = shell_query.filter(ReverseShell.group_name == group)
    
    shells_pagination = shell_query.paginate(page=page, per_page=PAGE_SIZE_DEFAULT, error_out=False)
    
    groups = [value[0] for value in db.session.query(ReverseShell.group_name).distinct().all() if value[0]]
    
    # Get active shells from listener
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = listener.get_active_shells()
    
    return render_template(
        "shells_dashboard.html",
        shells=shells_pagination.items,
        shells_pagination=shells_pagination,
        groups=sorted(groups),
        selected_group=group,
        active_shell_ids=active_shell_ids,
    )


@main_bp.route("/shells/<int:shell_id>", methods=["GET", "POST"])
@login_required
def shell_detail(shell_id: int):
    """Interactive shell management page."""
    shell = db.get_or_404(ReverseShell, shell_id)
    form = ShellCommandForm()
    
    # Check if shell is currently connected
    listener = get_listener(current_app._get_current_object())
    is_connected = shell_id in listener.get_active_shells()
    
    if form.validate_on_submit() and is_connected:
        command = form.command.data.strip()
        
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
        start_time = datetime.utcnow()
        success, output = listener.execute_command(shell_id, command, timeout=60)
        execution_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Update execution record
        execution.output = output
        execution.stdout = output  # For now, store same in stdout
        execution.status = "success" if success else "failed"
        execution.completed_at = datetime.utcnow()
        execution.execution_time = execution_time
        db.session.commit()
        
        flash(f"Command executed with status: {execution.status}", "info")
        return redirect(url_for("main.shell_detail", shell_id=shell.id))
    
    # Get command history
    page = _page_arg("page")
    executions_pagination = ShellExecution.query.filter_by(shell_id=shell.id).order_by(
        ShellExecution.started_at.desc()
    ).paginate(page=page, per_page=PAGE_SIZE_DEFAULT, error_out=False)
    
    return render_template(
        "shell_detail.html",
        shell=shell,
        form=form,
        is_connected=is_connected,
        executions=executions_pagination.items,
        executions_pagination=executions_pagination,
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


@main_bp.route("/operations/bulk-shells", methods=["GET", "POST"])
@login_required
def bulk_shell_operations():
    """Bulk command execution on reverse shells."""
    form = BulkShellCommandForm()
    
    # Get all shells
    shells = ReverseShell.query.filter_by(is_active=True).order_by(
        ReverseShell.group_name.asc(), ReverseShell.name.asc()
    ).all()
    
    # Get active shells
    listener = get_listener(current_app._get_current_object())
    active_shell_ids = set(listener.get_active_shells())
    
    # Only show connected shells in the form
    form.shell_ids.choices = [
        (shell.id, f"[{shell.group_name}] {shell.name} ({shell.address}) {'✓ online' if shell.id in active_shell_ids else '✗ offline'}")
        for shell in shells
    ]
    
    if form.validate_on_submit():
        selected_shells = [shell for shell in shells if shell.id in form.shell_ids.data]
        if not selected_shells:
            flash("Select at least one shell.", "warning")
            return redirect(url_for("main.bulk_shell_operations"))
        
        command = form.command.data.strip()
        success_count = 0
        failure_count = 0
        
        for shell in selected_shells:
            if shell.id not in active_shell_ids:
                # Create failed execution for offline shells
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
            
            # Create execution record
            execution = ShellExecution(
                shell_id=shell.id,
                user_id=current_user.id,
                command=command,
                status="running",
            )
            db.session.add(execution)
            db.session.commit()
            
            # Execute command
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
        
        flash(f"Bulk execution finished: {success_count} success, {failure_count} failed.", "info")
        return redirect(url_for("main.bulk_shell_operations"))
    
    # Get recent operations
    run_page = _page_arg("page")
    runs_pagination = ShellExecution.query.order_by(ShellExecution.started_at.desc()).paginate(
        page=run_page, per_page=PAGE_SIZE_DEFAULT, error_out=False
    )
    
    return render_template(
        "bulk_shell_operations.html",
        form=form,
        recent_bulk=runs_pagination.items,
        runs_pagination=runs_pagination,
    )


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
    """
    Alias to shells_dashboard for API compatibility.
    Display table of all reverse shell sessions.
    """
    return shells_dashboard()


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
    start_time = datetime.utcnow()
    timeout = current_app.config.get('SHELL_COMMAND_TIMEOUT', 30)
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
