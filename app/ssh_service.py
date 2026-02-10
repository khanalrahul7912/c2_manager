from __future__ import annotations

import socket
from dataclasses import dataclass

import paramiko


@dataclass
class SSHResult:
    stdout: str
    stderr: str
    return_code: int


def run_ssh_command(
    host: str,
    username: str,
    command: str,
    port: int = 22,
    key_path: str | None = None,
    timeout: int = 30,
    strict_host_key: bool = True,
) -> SSHResult:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if strict_host_key:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict[str, object] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "banner_timeout": timeout,
        "auth_timeout": timeout,
    }
    if key_path:
        connect_kwargs["key_filename"] = key_path

    try:
        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        del stdin
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
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
    except (socket.error, TimeoutError) as exc:
        return SSHResult(stdout="", stderr=f"Network/timeout error: {exc}", return_code=255)
    finally:
        client.close()
