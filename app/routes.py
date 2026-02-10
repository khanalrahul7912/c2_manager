from __future__ import annotations

from datetime import datetime
from functools import wraps

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.forms import CommandForm, HostForm, LoginForm
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
    hosts = Host.query.order_by(Host.name.asc()).all()
    recent_commands = CommandExecution.query.order_by(CommandExecution.started_at.desc()).limit(20).all()
    return render_template("dashboard.html", hosts=hosts, recent_commands=recent_commands)


@main_bp.route("/hosts/new", methods=["GET", "POST"])
@login_required
@role_required("admin")
def create_host():
    form = HostForm()
    if form.validate_on_submit():
        host = Host(
            name=form.name.data.strip(),
            address=form.address.data.strip(),
            port=form.port.data,
            username=form.username.data.strip(),
            key_path=form.key_path.data.strip() or None,
            is_active=form.is_active.data,
        )
        db.session.add(host)
        db.session.commit()
        flash("Host created.", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("host_form.html", form=form, title="Add Host")


@main_bp.route("/hosts/<int:host_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_host(host_id: int):
    host = db.get_or_404(Host, host_id)
    form = HostForm(obj=host)
    if form.validate_on_submit():
        form.populate_obj(host)
        host.key_path = form.key_path.data.strip() or None
        db.session.commit()
        flash("Host updated.", "success")
        return redirect(url_for("main.dashboard"))
    return render_template("host_form.html", form=form, title=f"Edit Host: {host.name}")


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
        execution = CommandExecution(
            host_id=host.id,
            user_id=current_user.id,
            command=form.command.data.strip(),
            status="running",
        )
        db.session.add(execution)
        db.session.commit()

        result = run_ssh_command(
            host=host.address,
            username=host.username,
            command=execution.command,
            port=host.port,
            key_path=host.key_path,
            timeout=current_app.config.get("REMOTE_COMMAND_TIMEOUT", 30),
        )

        execution.stdout = result.stdout
        execution.stderr = result.stderr
        execution.return_code = result.return_code
        execution.status = "success" if result.return_code == 0 else "failed"
        execution.completed_at = datetime.utcnow()
        db.session.commit()

        flash(f"Command completed with status {execution.status}.", "info")
        return redirect(url_for("main.host_detail", host_id=host.id))

    return render_template("host_detail.html", host=host, form=form, executions=executions)
