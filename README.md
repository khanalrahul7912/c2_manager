# RemoteOps (SSH-based)

RemoteOps is a Python 3.12 Flask control plane for legitimate remote administration over SSH.

## Included features

- Authentication with role-based controls (`admin` / `operator`).
- Host inventory with grouping, active/disabled status, and per-host strict host key mode.
- Single-host command execution with persistent history.
- Bulk host import from CSV-like lines in the UI.
- Bulk command execution across many hosts concurrently (thread pool).
- cPanel Passenger-compatible startup file (`passenger_wsgi.py`).

> This project intentionally does **not** implement reverse-shell listeners or C2-style handlers.

## Security model

- Uses SSH transport (no reverse shells).
- Supports strict host key validation by default.
- Host key auto-add is configurable per host (disable strict mode only for trusted internal assets).
- Admin-only host management and bulk import.

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

1. Create a Python App in cPanel (Python 3.12).
2. Point application root to this project directory.
3. Install dependencies with app venv pip:
   ```bash
   ~/virtualenv/<cpanel_user>/<app_root>/3.12/bin/pip install -r ~/<cpanel_user>/<app_root>/requirements.txt
   ```
4. Set app environment vars (`SECRET_KEY`, `DATABASE_URL`, `ADMIN_PASSWORD`).
5. Startup file: `passenger_wsgi.py`, entry point: `application`.
6. Run migrations in app venv:
   ```bash
   source ~/virtualenv/<cpanel_user>/<app_root>/3.12/bin/activate
   flask --app app db upgrade
   ADMIN_PASSWORD='strong-password' flask --app app create-admin
   ```
7. Restart app from cPanel.

## cPanel "No such application" troubleshooting

If cPanel reports:

- `No such application (or application not configured) "raahul/c2_manager"`

use this checklist:

1. In cPanel Setup Python App, confirm exact root path (`raahul/c2_manager`).
2. Confirm startup file (`passenger_wsgi.py`) and entry point (`application`).
3. Save, then restart app.
4. Reinstall dependencies in that app virtualenv.
5. If still broken, remove/recreate the Python App entry so Passenger re-registers mapping.

## Production hardening checklist

- Run behind HTTPS.
- Use MySQL/PostgreSQL instead of SQLite.
- Restrict access to trusted admin networks.
- Rotate SSH keys and app secrets.
- Enable centralized logging and alerting.
- Back up DB and test restore.
