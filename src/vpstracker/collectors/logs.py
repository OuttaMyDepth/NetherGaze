"""Nginx access log tailer with rotation detection."""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

from vpstracker.models import LogEntry

# Nginx combined log format regex
_LOG_PATTERN = re.compile(
    r'(?P<remote_ip>\S+)\s+'         # client IP
    r'\S+\s+'                         # ident (always -)
    r'\S+\s+'                         # auth user
    r'\[(?P<timestamp>[^\]]+)\]\s+'   # [timestamp]
    r'"(?P<method>\S+)\s+'            # "METHOD
    r'(?P<path>\S+)\s+'              # /path
    r'(?P<protocol>[^"]+)"\s+'       # HTTP/1.1"
    r'(?P<status>\d{3})\s+'          # status code
    r'(?P<bytes>\d+|-)\s+'           # bytes sent
    r'"(?P<referrer>[^"]*)"\s+'      # "referrer"
    r'"(?P<user_agent>[^"]*)"'       # "user agent"
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogWatcher:
    """Tails nginx access log, detects rotation, yields new entries."""

    def __init__(self, log_path: str, max_entries_per_ip: int = 100):
        self.log_path = Path(log_path)
        self.max_entries_per_ip = max_entries_per_ip
        self._file = None
        self._inode: int | None = None
        self._position: int = 0
        self._first_open: bool = True
        self._ip_buffers: dict[str, list[LogEntry]] = {}

    def poll(self) -> list[LogEntry]:
        """Poll for new log lines. Returns newly parsed entries."""
        if not self.log_path.exists():
            return []

        # Check for log rotation (inode change or file truncation)
        try:
            stat = self.log_path.stat()
        except FileNotFoundError:
            return []

        current_inode = stat.st_ino
        current_size = stat.st_size

        if self._inode is not None and (
            current_inode != self._inode or current_size < self._position
        ):
            # Log was rotated — reopen from start
            self._close()
            self._position = 0

        if self._file is None:
            try:
                self._file = open(self.log_path, "r", errors="replace")
                self._inode = current_inode
                # Seek to end on first open (only tail new lines)
                if self._first_open:
                    self._file.seek(0, os.SEEK_END)
                    self._position = self._file.tell()
                    self._first_open = False
                else:
                    self._file.seek(self._position)
            except (PermissionError, FileNotFoundError):
                return []

        new_entries: list[LogEntry] = []
        for line in self._file:
            line = line.rstrip("\n")
            if not line:
                continue
            entry = parse_log_line(line)
            if entry:
                new_entries.append(entry)
                # Maintain per-IP buffer
                buf = self._ip_buffers.setdefault(entry.remote_ip, [])
                buf.append(entry)
                if len(buf) > self.max_entries_per_ip:
                    self._ip_buffers[entry.remote_ip] = buf[-self.max_entries_per_ip :]

        self._position = self._file.tell()
        return new_entries

    def get_entries_for_ip(self, ip: str) -> list[LogEntry]:
        """Get buffered log entries for a specific IP."""
        return list(self._ip_buffers.get(ip, []))

    def _close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
            self._inode = None

    def close(self) -> None:
        """Clean shutdown."""
        self._close()


def parse_log_line(line: str) -> LogEntry | None:
    """Parse a single nginx combined format log line."""
    match = _LOG_PATTERN.match(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match.group("timestamp"), _TIMESTAMP_FORMAT)
    except ValueError:
        timestamp = datetime.now().astimezone()

    bytes_str = match.group("bytes")
    bytes_sent = int(bytes_str) if bytes_str != "-" else 0

    return LogEntry(
        remote_ip=match.group("remote_ip"),
        timestamp=timestamp,
        method=match.group("method"),
        path=match.group("path"),
        protocol=match.group("protocol"),
        status_code=int(match.group("status")),
        bytes_sent=bytes_sent,
        referrer=match.group("referrer"),
        user_agent=match.group("user_agent"),
        raw_line=line,
    )
