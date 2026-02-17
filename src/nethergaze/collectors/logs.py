"""HTTP server access log tailer with rotation detection."""

from __future__ import annotations

import glob as _glob
import json as _json
import os
import re
from datetime import datetime
from enum import Enum
from pathlib import Path

from nethergaze.models import LogEntry


class LogFormat(Enum):
    """Supported log format types."""

    AUTO = "auto"
    COMBINED = "combined"
    COMMON = "common"
    JSON = "json"


# Combined log format regex (nginx combined / Apache combined — CLF-derived)
_COMBINED_PATTERN = re.compile(
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

# Common log format regex (same as combined but ends after bytes — no referrer/user-agent)
_COMMON_PATTERN = re.compile(
    r'(?P<remote_ip>\S+)\s+'         # client IP
    r'\S+\s+'                         # ident (always -)
    r'\S+\s+'                         # auth user
    r'\[(?P<timestamp>[^\]]+)\]\s+'   # [timestamp]
    r'"(?P<method>\S+)\s+'            # "METHOD
    r'(?P<path>\S+)\s+'              # /path
    r'(?P<protocol>[^"]+)"\s+'       # HTTP/1.1"
    r'(?P<status>\d{3})\s+'          # status code
    r'(?P<bytes>\d+|-)\s*$'          # bytes sent (end of line)
)

_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogWatcher:
    """Tails HTTP server access log, detects rotation, yields new entries."""

    def __init__(self, log_path: str, max_entries_per_ip: int = 100, log_format: str = "auto"):
        self.log_path = Path(log_path)
        self.max_entries_per_ip = max_entries_per_ip
        self.log_format = LogFormat(log_format)
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
            entry = parse_log_line(line, self.log_format)
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


class MultiLogWatcher:
    """Watches multiple log files, expanding glob patterns.

    Periodically re-expands the glob to pick up new files (e.g. after vhost addition).
    Presents the same interface as LogWatcher (poll / close).
    """

    def __init__(
        self,
        log_path_pattern: str,
        max_entries_per_ip: int = 100,
        log_format: str = "auto",
    ):
        self._pattern = log_path_pattern
        self._max_entries_per_ip = max_entries_per_ip
        self._log_format = log_format
        self._watchers: dict[str, LogWatcher] = {}
        self._ip_buffers: dict[str, list[LogEntry]] = {}
        self._rescan()

    def _rescan(self) -> None:
        """Expand glob and create watchers for any new files."""
        paths = sorted(_glob.glob(self._pattern))
        for p in paths:
            if p not in self._watchers:
                self._watchers[p] = LogWatcher(
                    p,
                    max_entries_per_ip=self._max_entries_per_ip,
                    log_format=self._log_format,
                )

    def poll(self) -> list[LogEntry]:
        """Poll all watched log files and return combined new entries."""
        all_entries: list[LogEntry] = []
        for watcher in list(self._watchers.values()):
            all_entries.extend(watcher.poll())
        # Merge per-IP buffers from all watchers
        self._ip_buffers.clear()
        for watcher in self._watchers.values():
            for ip, entries in watcher._ip_buffers.items():
                buf = self._ip_buffers.setdefault(ip, [])
                buf.extend(entries)
                if len(buf) > self._max_entries_per_ip:
                    self._ip_buffers[ip] = buf[-self._max_entries_per_ip:]
        # Sort combined entries by timestamp
        all_entries.sort(key=lambda e: e.timestamp)
        return all_entries

    def rescan(self) -> None:
        """Re-expand glob to pick up new log files."""
        self._rescan()

    def get_entries_for_ip(self, ip: str) -> list[LogEntry]:
        """Get buffered log entries for a specific IP across all files."""
        return list(self._ip_buffers.get(ip, []))

    def close(self) -> None:
        """Clean shutdown of all watchers."""
        for watcher in self._watchers.values():
            watcher.close()
        self._watchers.clear()


def parse_log_line(line: str, log_format: LogFormat = LogFormat.AUTO) -> LogEntry | None:
    """Parse a single HTTP server access log line.

    Supports combined (nginx/Apache), common (CLF), and JSON (Caddy-style) formats.
    In AUTO mode, tries combined -> common -> JSON in order.
    """
    if log_format == LogFormat.COMBINED:
        return _parse_combined(line)
    elif log_format == LogFormat.COMMON:
        return _parse_common(line)
    elif log_format == LogFormat.JSON:
        return _parse_json_line(line)
    else:
        # AUTO: try combined first (preserves backward compat), then common, then JSON
        entry = _parse_combined(line)
        if entry:
            return entry
        entry = _parse_common(line)
        if entry:
            return entry
        return _parse_json_line(line)


def _parse_combined(line: str) -> LogEntry | None:
    """Parse a combined format log line (nginx/Apache combined)."""
    match = _COMBINED_PATTERN.match(line)
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


def _parse_common(line: str) -> LogEntry | None:
    """Parse a common log format (CLF) line — no referrer/user-agent fields."""
    match = _COMMON_PATTERN.match(line)
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
        referrer="",
        user_agent="",
        raw_line=line,
    )


def _parse_json_line(line: str) -> LogEntry | None:
    """Parse a JSON-formatted log line (Caddy-style nested or flat key format)."""
    try:
        data = _json.loads(line)
    except (ValueError, _json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    # Extract remote IP — support nested (Caddy) and flat formats
    remote_ip = (
        data.get("request", {}).get("remote_ip")
        or data.get("request", {}).get("remote_addr")
        or data.get("remote_ip")
        or data.get("remote_addr")
    )
    if not remote_ip:
        return None

    # Strip port from remote_addr (e.g. "1.2.3.4:12345" -> "1.2.3.4")
    if ":" in remote_ip:
        # Handle IPv4:port but not bare IPv6
        parts = remote_ip.rsplit(":", 1)
        if parts[-1].isdigit():
            remote_ip = parts[0]

    # Extract request fields — nested or flat
    request = data.get("request", {})
    method = request.get("method") or data.get("method") or ""
    path = request.get("uri") or data.get("uri") or data.get("path") or ""
    protocol = request.get("proto") or data.get("proto") or data.get("protocol") or ""

    # Status and size
    status = data.get("status") or data.get("resp_status") or 0
    size = data.get("size") or data.get("resp_size") or data.get("bytes_sent") or 0

    # Referrer and user-agent — nested headers or flat
    headers = request.get("headers", {})
    referrer = ""
    user_agent = ""
    if isinstance(headers, dict):
        ref_list = headers.get("Referer") or headers.get("referer") or []
        if isinstance(ref_list, list) and ref_list:
            referrer = ref_list[0]
        elif isinstance(ref_list, str):
            referrer = ref_list
        ua_list = headers.get("User-Agent") or headers.get("user-agent") or []
        if isinstance(ua_list, list) and ua_list:
            user_agent = ua_list[0]
        elif isinstance(ua_list, str):
            user_agent = ua_list
    # Flat fallbacks
    if not referrer:
        referrer = data.get("referrer") or data.get("referer") or ""
    if not user_agent:
        user_agent = data.get("user_agent") or data.get("user-agent") or ""

    # Timestamp
    ts_str = data.get("ts") or data.get("timestamp") or data.get("time")
    timestamp = datetime.now().astimezone()
    if isinstance(ts_str, (int, float)):
        try:
            timestamp = datetime.fromtimestamp(ts_str).astimezone()
        except (OSError, ValueError):
            pass
    elif isinstance(ts_str, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", _TIMESTAMP_FORMAT):
            try:
                timestamp = datetime.strptime(ts_str, fmt)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.astimezone()
                break
            except ValueError:
                continue

    return LogEntry(
        remote_ip=remote_ip,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status_code=int(status),
        bytes_sent=int(size),
        referrer=referrer,
        user_agent=user_agent,
        raw_line=line,
    )
