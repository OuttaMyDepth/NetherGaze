"""SSH/auth log watcher with rotation detection."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from nethergaze.models import AuthEntry, AuthEventType

# Timestamp capture: ISO 8601 (single token) or syslog (three tokens: Mon DD HH:MM:SS)
_TS_ISO = r"(\d{4}-\S+)"
_TS_SYSLOG = r"(\w+\s+\d+\s+\d+:\d+:\d+)"
_TS = rf"(?:{_TS_ISO}|{_TS_SYSLOG})"

# sshd service name variants: sshd[1234] or sshd-session[1234]
_SSHD = r"sshd(?:-session)?\[\d+\]"

# Regex patterns for sshd log entries
# Note: _TS produces 2 groups (iso, syslog) — only one will be non-None
_FAILED_PW = re.compile(
    _TS + r"\s+\S+\s+" + _SSHD + r":\s+"
    r"Failed password for (?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
)
_INVALID_USER = re.compile(
    _TS + r"\s+\S+\s+" + _SSHD + r":\s+"
    r"Invalid user\s+(\S+)\s+from\s+(\S+)"
)
_CONN_CLOSED = re.compile(
    _TS + r"\s+\S+\s+" + _SSHD + r":\s+"
    r"(?:Connection closed by|Disconnected from)"
    r"\s+(?:authenticating\s+|invalid\s+)?user\s+(\S+)\s+(\S+)"
)
_ACCEPTED = re.compile(
    _TS + r"\s+\S+\s+" + _SSHD + r":\s+"
    r"Accepted (?:password|publickey) for\s+(\S+)\s+from\s+(\S+)"
)

# (pattern, event_type, username_group, ip_group)
# Timestamp is always groups 1+2 (iso, syslog) — extracted by _extract_timestamp
_PATTERNS = [
    (_FAILED_PW, AuthEventType.FAILED_PASSWORD, 3, 4),
    (_INVALID_USER, AuthEventType.INVALID_USER, 3, 4),
    (_CONN_CLOSED, AuthEventType.CONNECTION_CLOSED, 3, 4),
    (_ACCEPTED, AuthEventType.ACCEPTED_PASSWORD, 3, 4),
]


def parse_auth_line(line: str) -> AuthEntry | None:
    """Parse a single auth.log line for SSH events."""
    if not line:
        return None
    for pattern, event_type, user_grp, ip_grp in _PATTERNS:
        match = pattern.search(line)
        if match:
            # Groups 1 and 2 are the timestamp alternation (iso, syslog)
            ts_str = match.group(1) or match.group(2)
            timestamp = _parse_timestamp(ts_str)
            return AuthEntry(
                remote_ip=match.group(ip_grp),
                timestamp=timestamp,
                event_type=event_type,
                username=match.group(user_grp),
                raw_line=line,
            )
    return None


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse a timestamp from auth log — supports syslog and ISO 8601 formats."""
    now = datetime.now().astimezone()

    # Try ISO 8601 first (e.g. "2026-03-22T10:15:30.123456+00:00")
    if "T" in ts_str:
        try:
            return datetime.fromisoformat(ts_str)
        except ValueError:
            pass

    # Traditional syslog format (e.g. "Mar 22 10:15:30")
    try:
        dt = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=now.tzinfo)
    except ValueError:
        return now


class AuthLogWatcher:
    """Tails auth log for SSH-related events."""

    def __init__(
        self, log_path: str = "/var/log/auth.log", max_entries_per_ip: int = 50
    ):
        self.log_path = Path(log_path)
        self.max_entries_per_ip = max_entries_per_ip
        self._file = None
        self._inode: int | None = None
        self._position: int = 0
        self._first_open: bool = True

    def poll(self) -> list[AuthEntry]:
        """Poll for new auth log lines. Returns newly parsed entries."""
        if not self.log_path.exists():
            return []

        try:
            stat = self.log_path.stat()
        except FileNotFoundError:
            return []

        current_inode = stat.st_ino
        current_size = stat.st_size

        if self._inode is not None and (
            current_inode != self._inode or current_size < self._position
        ):
            self._close()
            self._position = 0

        if self._file is None:
            try:
                self._file = open(self.log_path, errors="replace")
                self._inode = current_inode
                if self._first_open:
                    self._file.seek(0, os.SEEK_END)
                    self._position = self._file.tell()
                    self._first_open = False
                else:
                    self._file.seek(self._position)
            except (PermissionError, FileNotFoundError):
                return []

        new_entries: list[AuthEntry] = []
        while True:
            line = self._file.readline()
            if not line:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            entry = parse_auth_line(line)
            if entry:
                new_entries.append(entry)

        self._position = self._file.tell()
        return new_entries

    def _close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
            self._inode = None

    def close(self) -> None:
        """Clean shutdown."""
        self._close()
