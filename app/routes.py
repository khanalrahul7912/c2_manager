from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.forms import BulkCommandForm, BulkHostImportForm, CommandForm, HostForm, LoginForm
from app.models import CommandExecution, Host, User
from app.ssh_service import run_ssh_command


auth_bp = Blueprint("auth", __name__)
main_bp = Blueprint("main", __name__)


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
    query = Host.query.order_by(Host.name.asc())
    if group:
        query = query.filter(Host.group_name == group)

    hosts = query.all()
    groups = [value[0] for value in db.session.query(Host.group_name).distinct().all() if value[0]]
    recent_commands = CommandExecution.query.order_by(CommandExecution.started_at.desc()).limit(30).all()
    return render_template(
        "dashboard.html",
        hosts=hosts,
        groups=sorted(groups),
        selected_group=group,
        recent_commands=recent_commands,
    )


@main_bp.route("/hosts/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_host():
    form = HostForm()
    if form.validate_on_submit():
        host = Host(
            name=form.name.data.strip(),
            address=form.address.data.strip(),
            group_name=(form.group_name.data or "default").strip() or "default",
            port=form.port.data,
            username=form.username.data.strip(),
            key_path=form.key_path.data.strip() or None,
            strict_host_key=form.strict_host_key.data,
            is_active=form.is_active.data,
        )
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

            name, address, username = parts[:3]
            try:
                port = int(parts[3]) if len(parts) > 3 and parts[3] else 22
            except ValueError:
                skipped += 1
                flash(f"Line {idx}: skipped (invalid port value)", "warning")
                continue
            key_path = parts[4] if len(parts) > 4 and parts[4] else None
            group_name = parts[5] if len(parts) > 5 and parts[5] else "default"
            strict_host_key = True
            if len(parts) > 6 and parts[6]:
                strict_host_key = parts[6].lower() not in {"false", "0", "no", "off"}

            db.session.add(
                Host(
                    name=name,
                    address=address,
                    username=username,
                    port=port,
                    key_path=key_path,
                    group_name=group_name,
                    strict_host_key=strict_host_key,
                    is_active=True,
                )
            )
            created += 1

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
    if form.validate_on_submit():
        form.populate_obj(host)
        host.group_name = (form.group_name.data or "default").strip() or "default"
        host.key_path = form.key_path.data.strip() or None
        db.session.commit()
        flash("Host updated.", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("host_form.html", form=form, title=f"Edit Host: {host.name}")


def _run_command_for_host(host: Host, command: str, timeout: int):
    return host.id, run_ssh_command(
        host=host.address,
        username=host.username,
        command=command,
        port=host.port,
        key_path=host.key_path,
        timeout=timeout,
        strict_host_key=host.strict_host_key,
    )


def _create_execution(host: Host, command: str) -> CommandExecution:
    execution = CommandExecution(
        host_id=host.id,
        user_id=current_user.id,
        command=command,
        status="running",
    )
    db.session.add(execution)
    db.session.commit()
    return execution


def _complete_execution(execution: CommandExecution, result) -> None:
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
    form.host_ids.choices = [(host.id, f"[{host.group_name}] {host.name} ({host.username}@{host.address}:{host.port})") for host in hosts]

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
        execution_map = {host.id: _create_execution(host, command) for host in selected_hosts}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_command_for_host, host, command, timeout): host for host in selected_hosts}
            for future in as_completed(futures):
                host = futures[future]
                execution = execution_map[host.id]
                try:
                    _, result = future.result()
                    _complete_execution(execution, result)
                    if execution.status == "success":
                        success_count += 1
                    else:
                        failure_count += 1
                except Exception as exc:  # pragma: no cover - defensive safety
                    failure_count += 1
                    execution.status = "failed"
                    execution.stderr = f"Unexpected error during execution: {exc}"
                    execution.completed_at = datetime.utcnow()
                    db.session.commit()
                    flash(f"{host.name}: unexpected error during execution: {exc}", "danger")

        flash(
            f"Bulk execution finished: {success_count} success, {failure_count} failed.",
            "info",
        )
        return redirect(url_for("main.bulk_operations"))

    recent_bulk = CommandExecution.query.order_by(CommandExecution.started_at.desc()).limit(100).all()
    return render_template("bulk_operations.html", form=form, recent_bulk=recent_bulk)


@main_bp.route("/hosts/<int:host_id>", methods=["GET", "POST"])
@login_required
def host_detail(host_id: int):
    host = db.get_or_404(Host, host_id)
    form = CommandForm()
    executions = (
        CommandExecution.query.filter_by(host_id=host.id)
        .order_by(CommandExecution.started_at.desc())
        .limit(50)
        .all()
    )

    if form.validate_on_submit():
        command = form.command.data.strip()
        execution = _create_execution(host, command)
        result = _run_command_for_host(host, command, current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30))[1]
        _complete_execution(execution, result)
        flash(f"Command completed with status {execution.status}.", "info")
        return redirect(url_for("main.host_detail", host_id=host.id))

    return render_template("host_detail.html", host=host, form=form, executions=executions)
