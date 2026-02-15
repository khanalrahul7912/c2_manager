from __future__ import annotations

import socket
from dataclasses import dataclass

import paramiko

from app.utils import strip_ansi_codes


@dataclass
class SSHResult:
    stdout: str
    stderr: str
    return_code: int


@dataclass
class SSHEndpoint:
    host: str
    username: str
    port: int = 22
    auth_mode: str = "key"
    key_path: str | None = None
    password: str | None = None


def _connect_client(
    client: paramiko.SSHClient,
    endpoint: SSHEndpoint,
    timeout: int,
    sock=None,
) -> None:
    connect_kwargs: dict[str, object] = {
        "hostname": endpoint.host,
        "port": endpoint.port,
        "username": endpoint.username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }
    if sock is not None:
        connect_kwargs["sock"] = sock

    if endpoint.auth_mode == "password":
        connect_kwargs["password"] = endpoint.password or ""
        connect_kwargs["allow_agent"] = False
        connect_kwargs["look_for_keys"] = False
    else:
        if endpoint.key_path:
            connect_kwargs["key_filename"] = endpoint.key_path

    client.connect(**connect_kwargs)


def run_ssh_command(
    target: SSHEndpoint,
    command: str,
    timeout: int = 30,
    strict_host_key: bool = True,
    jump_host: SSHEndpoint | None = None,
) -> SSHResult:
    client = paramiko.SSHClient()
    jump_client = None
    client.load_system_host_keys()
    if strict_host_key:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if jump_host:
            jump_client = paramiko.SSHClient()
            jump_client.load_system_host_keys()
            if strict_host_key:
                jump_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            _connect_client(jump_client, jump_host, timeout)
            jump_transport = jump_client.get_transport()
            if not jump_transport:
                return SSHResult(stdout="", stderr="Jump host transport unavailable", return_code=255)
            sock = jump_transport.open_channel(
                "direct-tcpip",
                (target.host, target.port),
                ("127.0.0.1", 0),
            )
            _connect_client(client, target, timeout, sock=sock)
        else:
            _connect_client(client, target, timeout)

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
        del stdin
        out = strip_ansi_codes(stdout.read().decode("utf-8", errors="replace"))
        err = strip_ansi_codes(stderr.read().decode("utf-8", errors="replace"))
        code = stdout.channel.recv_exit_status()
        return SSHResult(stdout=out, stderr=err, return_code=code)
    except paramiko.ssh_exception.BadHostKeyException as exc:
        return SSHResult(stdout="", stderr=f"Host key verification failed: {exc}", return_code=255)
    except paramiko.ssh_exception.AuthenticationException as exc:
        return SSHResult(stdout="", stderr=f"SSH authentication failed: {exc}", return_code=255)
    except paramiko.ssh_exception.SSHException as exc:
        message = f"SSH execution failed: {exc}"
        if "not found in known_hosts" in str(exc):
            message += " | Tip: add host key to known_hosts or disable strict host key validation for this host."
        return SSHResult(stdout="", stderr=message, return_code=255)
    except (socket.error, TimeoutError, ValueError) as exc:
        return SSHResult(stdout="", stderr=f"Network/configuration error: {exc}", return_code=255)
    finally:
        client.close()
        if jump_client:
            jump_client.close()
