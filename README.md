# RemoteOps (SSH-based)

RemoteOps is a Python 3.12 Flask control plane for legitimate remote administration over SSH.

## Included features

- Authentication with securely hashed app user passwords.
- Host inventory with grouping, active/disabled state, and strict host key mode.
- SSH auth options: key-based or password-based (encrypted at rest).
- Optional jump-host (bastion) connectivity per target host.
- Single-host command execution with persistent history.
- Bulk host import from CSV-like lines in UI.
- Bulk command execution across many hosts concurrently.
- Pagination on dashboard, host history, and bulk operation history.
- cPanel Passenger-compatible startup (`passenger_wsgi.py`).

> This project intentionally does **not** implement reverse-shell listeners or C2-style handlers.

## Security model

- Uses SSH transport (no reverse shells).
- App login passwords are hashed with Werkzeug.
- Stored SSH credentials are encrypted using `DATA_ENCRYPTION_KEY`.
- Supports strict host key validation by default.
- Admin-only host management and import.

## Required environment variables

- `SECRET_KEY`: Flask session security key.
- `DATA_ENCRYPTION_KEY`: required to encrypt/decrypt SSH and jump-host passwords.
- `DATABASE_URL`: DB connection URL.
- `ADMIN_PASSWORD`: initial admin creation.

## SQLite path behavior fix

If `DATABASE_URL` is SQLite and uses a relative path (for example `sqlite:///instance/app.db`),
the app now resolves it to an absolute path automatically relative to the project root.
That avoids failures where cPanel/Passenger starts from a different working directory.

## Login/CSRF and migration fixes

- Login is built on `LoginForm(FlaskForm)` so CSRF token is present.
- `login` route control flow is corrected and stable.
- Added `migrations/env.py` with `render_as_batch=True` for SQLite schema changes.

## Fix for common error (`known_hosts`)

If you see:

- `SSH execution failed: Server 'localhost' not found in known_hosts`

then either:

1. add host keys to `~/.ssh/known_hosts`, e.g.:
   ```bash
   ssh-keyscan -H localhost >> ~/.ssh/known_hosts
   ```
2. or edit that host and uncheck **Strict host key validation**.

## Local setup (Python 3.12)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Initialize DB and create admin:

```bash
flask --app app db init
flask --app app db migrate -m "initial schema"
flask --app app db upgrade
ADMIN_PASSWORD='strong-password' flask --app app create-admin
```

Run locally:

```bash
flask --app app run --host 0.0.0.0 --port 5000
```

## cPanel deployment notes

1. Create Python App in cPanel (Python 3.12).
2. Set root to this project.
3. Install dependencies:
   ```bash
   ~/virtualenv/<cpanel_user>/<app_root>/3.12/bin/pip install -r ~/<cpanel_user>/<app_root>/requirements.txt
   ```
4. Set env vars in cPanel (`SECRET_KEY`, `DATA_ENCRYPTION_KEY`, `DATABASE_URL`, `ADMIN_PASSWORD`).
5. Startup file: `passenger_wsgi.py`, entrypoint: `application`.
6. Run migrations in app venv.
7. Restart from cPanel.
