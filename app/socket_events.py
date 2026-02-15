"""WebSocket event handlers for real-time interactive terminal sessions.

Provides bidirectional I/O between the browser (xterm.js) and remote shells
(reverse shell sockets or SSH paramiko channels).
"""
from __future__ import annotations

import socket
import threading
from typing import Dict

import paramiko
from flask import current_app, request
from flask_login import current_user
from flask_socketio import SocketIO, disconnect, emit

from app.extensions import db
from app.models import Host, ReverseShell
from app.shell_service import get_listener
from app.ssh_service import SSHEndpoint, _connect_client

# Active WebSocket terminal sessions keyed by Flask-SocketIO session id (request.sid)
_ws_sessions: Dict[str, dict] = {}
_ws_lock = threading.Lock()


def register_events(sio: SocketIO) -> None:
    """Register all SocketIO event handlers."""

    # ── Reverse Shell Events ─────────────────────────────────────────────

    @sio.on("reverse_connect")
    def on_reverse_connect(data: dict) -> None:
        """Client wants to attach to a reverse shell for real-time I/O."""
        if not current_user.is_authenticated:
            emit("shell_output", {"data": "\r\n⚠ Not authenticated\r\n"})
            disconnect()
            return

        shell_id = data.get("shell_id")
        if not shell_id:
            emit("shell_output", {"data": "\r\n⚠ Missing shell_id\r\n"})
            return

        app = current_app._get_current_object()
        listener = get_listener(app)

        with listener.lock:
            conn = listener.connections.get(shell_id)

        if not conn or not conn.is_active:
            emit("shell_output", {"data": "\r\n⚠ Shell is not connected\r\n"})
            emit("shell_status", {"connected": False})
            return

        # Mark connection as WebSocket-attached so keepalive is paused
        conn.ws_attached = True

        emit("shell_status", {"connected": True})
        emit("shell_output", {"data": "\r\n"})

        # Clean up any existing session for this SID before starting a new one
        sid = request.sid
        with _ws_lock:
            old = _ws_sessions.get(sid)
            if old:
                old["active"] = False  # Signal old reader thread to stop

        # Give old reader thread time to notice the stop signal
        import time as _time
        _time.sleep(0.6)

        with _ws_lock:
            _ws_sessions[sid] = {
                "type": "reverse",
                "shell_id": shell_id,
                "active": True,
            }

        def _reader() -> None:
            """Background thread: read from reverse-shell socket → emit to browser."""
            try:
                while True:
                    with _ws_lock:
                        info = _ws_sessions.get(sid)
                        if not info or not info.get("active"):
                            break

                    with listener.lock:
                        c = listener.connections.get(shell_id)
                    if not c or not c.is_active:
                        sio.emit("shell_status", {"connected": False}, to=sid)
                        sio.emit("shell_output", {"data": "\r\n⚠ Shell disconnected\r\n"}, to=sid)
                        break

                    try:
                        c.conn.settimeout(0.5)
                        chunk = c.conn.recv(4096)
                        if not chunk:
                            sio.emit("shell_status", {"connected": False}, to=sid)
                            sio.emit("shell_output", {"data": "\r\n⚠ Shell disconnected\r\n"}, to=sid)
                            break
                        sio.emit("shell_output", {"data": chunk.decode("utf-8", errors="replace")}, to=sid)
                    except socket.timeout:
                        continue
                    except (BrokenPipeError, ConnectionResetError):
                        sio.emit("shell_status", {"connected": False}, to=sid)
                        sio.emit("shell_output", {"data": "\r\n⚠ Shell connection lost\r\n"}, to=sid)
                        break
                    except OSError:
                        sio.emit("shell_status", {"connected": False}, to=sid)
                        break
            finally:
                with _ws_lock:
                    info = _ws_sessions.get(sid)
                    if info:
                        info["active"] = False

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        with _ws_lock:
            _ws_sessions[sid]["reader"] = reader_thread

    @sio.on("reverse_input")
    def on_reverse_input(data: dict) -> None:
        """Client typed something → send to reverse shell."""
        if not current_user.is_authenticated:
            return

        sid = request.sid
        with _ws_lock:
            info = _ws_sessions.get(sid)

        if not info or info.get("type") != "reverse" or not info.get("active"):
            return

        shell_id = info["shell_id"]
        app = current_app._get_current_object()
        listener = get_listener(app)

        with listener.lock:
            conn = listener.connections.get(shell_id)

        if not conn or not conn.is_active:
            emit("shell_status", {"connected": False})
            return

        raw = data.get("data", "")
        if raw:
            try:
                conn.conn.sendall(raw.encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                emit("shell_status", {"connected": False})
                emit("shell_output", {"data": "\r\n⚠ Shell connection lost\r\n"})

    @sio.on("reverse_resize")
    def on_reverse_resize(data: dict) -> None:
        """Terminal resized – not applicable for raw sockets, but accepted silently."""
        pass

    @sio.on("reverse_disconnect_host")
    def on_reverse_disconnect_host(data: dict) -> None:
        """Forcefully disconnect a reverse shell."""
        if not current_user.is_authenticated:
            return

        shell_id = data.get("shell_id")
        if not shell_id:
            return

        app = current_app._get_current_object()
        listener = get_listener(app)

        with listener.lock:
            conn = listener.connections.get(shell_id)
            if conn:
                conn.close()
                del listener.connections[shell_id]

        with app.app_context():
            from datetime import datetime
            shell = db.session.get(ReverseShell, shell_id)
            if shell:
                shell.status = "disconnected"
                shell.disconnected_at = datetime.utcnow()
                db.session.commit()

        emit("shell_status", {"connected": False})
        emit("shell_output", {"data": "\r\n⚠ Shell forcefully disconnected\r\n"})

    # ── SSH Events ───────────────────────────────────────────────────────

    @sio.on("ssh_connect")
    def on_ssh_connect(data: dict) -> None:
        """Open an interactive SSH shell channel (PTY) for real-time I/O."""
        if not current_user.is_authenticated:
            emit("shell_output", {"data": "\r\n⚠ Not authenticated\r\n"})
            disconnect()
            return

        host_id = data.get("host_id")
        cols = data.get("cols", 120)
        rows = data.get("rows", 40)
        if not host_id:
            emit("shell_output", {"data": "\r\n⚠ Missing host_id\r\n"})
            return

        app = current_app._get_current_object()

        with app.app_context():
            host = db.session.get(Host, host_id)
            if not host:
                emit("shell_output", {"data": "\r\n⚠ Host not found\r\n"})
                return

            target = SSHEndpoint(
                host=host.address,
                username=host.username,
                port=host.port,
                auth_mode=host.auth_mode,
                key_path=host.key_path,
                password=host.password_encrypted,
            )
            jump_host = None
            if host.use_jump_host:
                jump_host = SSHEndpoint(
                    host=host.jump_address or "",
                    username=host.jump_username or "",
                    port=host.jump_port or 22,
                    auth_mode=host.jump_auth_mode,
                    key_path=host.jump_key_path,
                    password=host.jump_password_encrypted,
                )

        sid = request.sid

        # Clean up any existing session for this SID before starting a new one
        _cleanup_session(sid)

        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            strict = host.strict_host_key if host else True
            if strict:
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            jump_client = None
            timeout = 15

            if jump_host:
                jump_client = paramiko.SSHClient()
                jump_client.load_system_host_keys()
                if strict:
                    jump_client.set_missing_host_key_policy(paramiko.RejectPolicy())
                else:
                    jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                _connect_client(jump_client, jump_host, timeout)
                jump_transport = jump_client.get_transport()
                if not jump_transport:
                    emit("shell_output", {"data": "\r\n⚠ Jump host transport unavailable\r\n"})
                    return
                sock = jump_transport.open_channel(
                    "direct-tcpip", (target.host, target.port), ("127.0.0.1", 0),
                )
                _connect_client(client, target, timeout, sock=sock)
            else:
                _connect_client(client, target, timeout)

            channel = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
            channel.settimeout(0.5)

        except Exception as exc:
            emit("shell_output", {"data": f"\r\n⚠ SSH connection failed: {exc}\r\n"})
            emit("shell_status", {"connected": False})
            return

        emit("shell_status", {"connected": True})

        with _ws_lock:
            _ws_sessions[sid] = {
                "type": "ssh",
                "host_id": host_id,
                "client": client,
                "jump_client": jump_client,
                "channel": channel,
                "active": True,
            }

        def _ssh_reader() -> None:
            """Background thread: read from SSH channel → emit to browser."""
            try:
                while True:
                    with _ws_lock:
                        info = _ws_sessions.get(sid)
                        if not info or not info.get("active"):
                            break
                    chan = info.get("channel")
                    if not chan:
                        break
                    try:
                        if chan.recv_ready():
                            chunk = chan.recv(4096)
                            if not chunk:
                                break
                            sio.emit("shell_output", {"data": chunk.decode("utf-8", errors="replace")}, to=sid)
                        elif chan.exit_status_ready():
                            sio.emit("shell_output", {"data": "\r\n⚠ SSH session ended\r\n"}, to=sid)
                            sio.emit("shell_status", {"connected": False}, to=sid)
                            break
                        else:
                            import time
                            time.sleep(0.05)
                    except socket.timeout:
                        continue
                    except OSError:
                        sio.emit("shell_status", {"connected": False}, to=sid)
                        break
            finally:
                with _ws_lock:
                    info = _ws_sessions.get(sid)
                    if info:
                        info["active"] = False

        reader_thread = threading.Thread(target=_ssh_reader, daemon=True)
        reader_thread.start()

        with _ws_lock:
            _ws_sessions[sid]["reader"] = reader_thread

    @sio.on("ssh_input")
    def on_ssh_input(data: dict) -> None:
        """Client typed something → send to SSH channel."""
        if not current_user.is_authenticated:
            return

        sid = request.sid
        with _ws_lock:
            info = _ws_sessions.get(sid)

        if not info or info.get("type") != "ssh" or not info.get("active"):
            return

        channel = info.get("channel")
        if not channel:
            return

        raw = data.get("data", "")
        if raw:
            try:
                channel.send(raw)
            except OSError:
                emit("shell_status", {"connected": False})

    @sio.on("ssh_resize")
    def on_ssh_resize(data: dict) -> None:
        """Terminal resized → resize SSH PTY."""
        if not current_user.is_authenticated:
            return

        sid = request.sid
        with _ws_lock:
            info = _ws_sessions.get(sid)

        if not info or info.get("type") != "ssh" or not info.get("active"):
            return

        channel = info.get("channel")
        if not channel:
            return

        cols = data.get("cols", 120)
        rows = data.get("rows", 40)
        try:
            channel.resize_pty(width=cols, height=rows)
        except Exception:
            pass

    @sio.on("ssh_disconnect_host")
    def on_ssh_disconnect_host(data: dict) -> None:
        """Forcefully close the SSH session."""
        if not current_user.is_authenticated:
            return

        sid = request.sid
        _cleanup_session(sid)
        emit("shell_status", {"connected": False})
        emit("shell_output", {"data": "\r\n⚠ SSH session forcefully disconnected\r\n"})

    # ── Common ───────────────────────────────────────────────────────────

    @sio.on("disconnect")
    def on_disconnect() -> None:
        """Client WebSocket disconnected — clean up."""
        _cleanup_session(request.sid)


def _cleanup_session(sid: str) -> None:
    """Clean up resources for a WebSocket session."""
    with _ws_lock:
        info = _ws_sessions.pop(sid, None)

    if not info:
        return

    info["active"] = False

    if info.get("type") == "reverse":
        # Unmark ws_attached so keepalive resumes
        shell_id = info.get("shell_id")
        if shell_id:
            try:
                from flask import current_app
                app = current_app._get_current_object()
                listener = get_listener(app)
                with listener.lock:
                    conn = listener.connections.get(shell_id)
                    if conn:
                        conn.ws_attached = False
            except Exception:
                pass

    elif info.get("type") == "ssh":
        channel = info.get("channel")
        client = info.get("client")
        jump_client = info.get("jump_client")
        try:
            if channel:
                channel.close()
        except Exception:
            pass
        try:
            if client:
                client.close()
        except Exception:
            pass
        try:
            if jump_client:
                jump_client.close()
        except Exception:
            pass
