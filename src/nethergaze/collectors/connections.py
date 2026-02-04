"""TCP connection collector reading /proc/net/tcp and /proc/net/tcp6."""

from __future__ import annotations

import os
from pathlib import Path

from nethergaze.models import Connection, TCPState
from nethergaze.utils import (
    is_private_ip,
    parse_hex_ipv4,
    parse_hex_ipv6,
    parse_hex_port,
)


def get_connections(
    include_private: bool = False,
    proc_path: str = "/proc",
) -> list[Connection]:
    """Read active TCP connections from /proc/net/tcp and tcp6.

    Returns a list of Connection objects for non-listening, non-local connections.
    """
    inode_to_pid = _build_inode_pid_map(proc_path)
    connections: list[Connection] = []

    for proto_file, parser in [
        ("net/tcp", _parse_tcp4_line),
        ("net/tcp6", _parse_tcp6_line),
    ]:
        filepath = Path(proc_path) / proto_file
        if not filepath.exists():
            continue
        try:
            lines = filepath.read_text().splitlines()
        except PermissionError:
            continue

        for line in lines[1:]:  # Skip header
            conn = parser(line.strip())
            if conn is None:
                continue
            # Skip listening sockets
            if conn.state == TCPState.LISTEN:
                continue
            # Skip loopback
            if conn.remote_ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                continue
            # Optionally skip private IPs
            if not include_private and is_private_ip(conn.remote_ip):
                continue
            # Map inode to PID
            pid_info = inode_to_pid.get(conn.inode)
            if pid_info:
                conn.pid, conn.process_name = pid_info
            connections.append(conn)

    return connections


def _parse_tcp4_line(line: str) -> Connection | None:
    """Parse a single line from /proc/net/tcp."""
    try:
        fields = line.split()
        if len(fields) < 10:
            return None

        local_addr, local_port_hex = fields[1].split(":")
        remote_addr, remote_port_hex = fields[2].split(":")
        state_hex = fields[3]
        inode = int(fields[9])

        return Connection(
            local_ip=parse_hex_ipv4(local_addr),
            local_port=parse_hex_port(local_port_hex),
            remote_ip=parse_hex_ipv4(remote_addr),
            remote_port=parse_hex_port(remote_port_hex),
            state=TCPState.from_hex(state_hex),
            inode=inode,
        )
    except (ValueError, IndexError):
        return None


def _parse_tcp6_line(line: str) -> Connection | None:
    """Parse a single line from /proc/net/tcp6."""
    try:
        fields = line.split()
        if len(fields) < 10:
            return None

        local_addr, local_port_hex = fields[1].split(":")
        remote_addr, remote_port_hex = fields[2].split(":")
        state_hex = fields[3]
        inode = int(fields[9])

        return Connection(
            local_ip=parse_hex_ipv6(local_addr),
            local_port=parse_hex_port(local_port_hex),
            remote_ip=parse_hex_ipv6(remote_addr),
            remote_port=parse_hex_port(remote_port_hex),
            state=TCPState.from_hex(state_hex),
            inode=inode,
        )
    except (ValueError, IndexError):
        return None


def _build_inode_pid_map(proc_path: str = "/proc") -> dict[int, tuple[int, str]]:
    """Build a mapping of socket inode -> (PID, process_name).

    Scans /proc/[pid]/fd/ for socket links and /proc/[pid]/comm for names.
    """
    inode_map: dict[int, tuple[int, str]] = {}
    proc = Path(proc_path)

    if not proc.exists():
        return inode_map

    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        fd_dir = pid_dir / "fd"

        try:
            comm = (pid_dir / "comm").read_text().strip()
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            comm = "?"

        try:
            for fd_link in fd_dir.iterdir():
                try:
                    target = os.readlink(str(fd_link))
                    if target.startswith("socket:["):
                        inode = int(target[8:-1])
                        inode_map[inode] = (pid, comm)
                except (PermissionError, FileNotFoundError, ProcessLookupError, ValueError):
                    continue
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue

    return inode_map
