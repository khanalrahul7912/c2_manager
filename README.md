# RemoteOps (SSH-based)

RemoteOps is a Python 3.12 Flask control plane for **legitimate remote administration over SSH**. It provides:

- Authenticated operator access with role-based controls.
- Managed host inventory.
- Remote command execution over SSH and captured stdout/stderr.
- Persistent execution history and auditing basics.
- cPanel Passenger-compatible entrypoint (`passenger_wsgi.py`).

## Security model

- Uses SSH transport (no reverse shells).
- Requires authenticated users.
- Admin-only host management.
- Host key checking uses Paramiko `RejectPolicy` (host keys must be known in `~/.ssh/known_hosts`).

## Local setup (Python 3.12)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Initialize database and create admin:

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
3. Install dependencies with your app virtualenv pip:
   ```bash
   ~/virtualenv/<cpanel_user>/<app_root>/3.12/bin/pip install -r ~/<cpanel_user>/<app_root>/requirements.txt
   ```
4. Ensure environment variables are configured in cPanel (at least `SECRET_KEY`, `DATABASE_URL`, `ADMIN_PASSWORD`).
5. Use `passenger_wsgi.py` as the startup file.
6. Execute migrations from terminal with that app's Python:
   ```bash
   source ~/virtualenv/<cpanel_user>/<app_root>/3.12/bin/activate
   flask --app app db upgrade
   ADMIN_PASSWORD='strong-password' flask --app app create-admin
   ```
7. Restart the Python app from cPanel.

## Production hardening checklist

- Put the app behind HTTPS only.
- Use MySQL/PostgreSQL instead of SQLite.
- Enforce strong password policy and MFA at your SSO boundary.
- Restrict source IPs to company management ranges.
- Configure centralized logs and alerting.
- Rotate SSH keys and app secrets regularly.
- Backup the database and test restoration.


## cPanel "No such application" troubleshooting

If cPanel shows:

- `No such application (or application not configured) "raahul/c2_manager"`

this is usually a **cPanel app registration/path mapping** issue (not Flask code itself).

Use this checklist:

1. In **cPanel → Setup Python App**, confirm:
   - **Application root** exactly matches the folder path (`raahul/c2_manager`).
   - **Startup file** is `passenger_wsgi.py`.
   - **Entry point** is `application`.
2. Click **Save** then **Restart** the app in cPanel.
3. Reinstall requirements using the app's virtualenv from cPanel UI or terminal, then restart:
   ```bash
   ~/virtualenv/raahul/c2_manager/3.12/bin/pip install -r ~/raahul/c2_manager/requirements.txt
   ```
4. If your host creates/uses `.htaccess` Passenger directives, ensure it points to the same app root.
5. Check Passenger and app error logs in cPanel metrics/log sections for path mismatches.
6. If cloning replaced files after app creation, remove and recreate the Python App entry in cPanel so Passenger re-registers the app path.

### Important note for this repo

`passenger_wsgi.py` is now path-agnostic and does not hardcode `~/virtualenv/python_proj/...`.
If you need to pin interpreter manually, set `APP_VENV_PYTHON` in cPanel environment variables.
