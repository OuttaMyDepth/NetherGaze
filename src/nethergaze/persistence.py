"""SQLite-backed historical IP profile persistence."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from nethergaze.models import IPProfile
from nethergaze.utils import format_bytes


class HistoryDB:
    """Thread-safe SQLite store for historical IP data."""

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._session_recorded_ips: set[str] = set()
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_history (
                ip TEXT PRIMARY KEY,
                first_seen_ever TEXT NOT NULL,
                last_seen_ever TEXT NOT NULL,
                total_historical_requests INTEGER DEFAULT 0,
                total_historical_bytes INTEGER DEFAULT 0,
                sessions_seen INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                country_code TEXT DEFAULT '?',
                as_org TEXT DEFAULT '?',
                last_paths TEXT DEFAULT ''
            )
        """)
        self._conn.commit()

    def record_session(self, profile: IPProfile, is_suspicious: bool = False) -> None:
        """Record first sighting of an IP in this session (increments sessions_seen)."""
        now = datetime.now().astimezone().isoformat()
        with self._lock:
            if not self._conn:
                return
            row = self._conn.execute(
                "SELECT sessions_seen, total_historical_requests, "
                "total_historical_bytes, suspicious_count, first_seen_ever "
                "FROM ip_history WHERE ip = ?",
                (profile.ip,),
            ).fetchone()

            last_paths = ",".join(e.path for e in profile.log_entries[-5:])
            cc = profile.country_code
            org = profile.as_org

            if row:
                sessions, hist_reqs, hist_bytes, sus_count, _first = row
                self._conn.execute(
                    """
                    UPDATE ip_history SET
                        last_seen_ever = ?,
                        total_historical_requests = ?,
                        total_historical_bytes = ?,
                        sessions_seen = ?,
                        suspicious_count = ?,
                        country_code = ?,
                        as_org = ?,
                        last_paths = ?
                    WHERE ip = ?
                    """,
                    (
                        now,
                        hist_reqs + profile.total_requests,
                        hist_bytes + profile.total_bytes_sent,
                        sessions + 1,
                        sus_count + (1 if is_suspicious else 0),
                        cc,
                        org,
                        last_paths,
                        profile.ip,
                    ),
                )
            else:
                first_seen = (
                    profile.first_seen.isoformat() if profile.first_seen else now
                )
                self._conn.execute(
                    """
                    INSERT INTO ip_history
                    (ip, first_seen_ever, last_seen_ever, total_historical_requests,
                     total_historical_bytes, sessions_seen, suspicious_count,
                     country_code, as_org, last_paths)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        profile.ip,
                        first_seen,
                        now,
                        profile.total_requests,
                        profile.total_bytes_sent,
                        1 if is_suspicious else 0,
                        cc,
                        org,
                        last_paths,
                    ),
                )
            self._conn.commit()
            self._session_recorded_ips.add(profile.ip)

    def update_in_session(self, profile: IPProfile) -> None:
        """Update an IP's data within the current session (does NOT increment sessions_seen)."""
        now = datetime.now().astimezone().isoformat()
        with self._lock:
            if not self._conn:
                return
            last_paths = ",".join(e.path for e in profile.log_entries[-5:])
            self._conn.execute(
                """
                UPDATE ip_history SET
                    last_seen_ever = ?,
                    total_historical_requests = total_historical_requests
                        + ? - COALESCE((SELECT total_historical_requests FROM ip_history WHERE ip = ?), 0)
                        + COALESCE((SELECT total_historical_requests FROM ip_history WHERE ip = ?), 0),
                    country_code = ?,
                    as_org = ?,
                    last_paths = ?
                WHERE ip = ?
                """,
                (
                    now,
                    profile.total_requests,
                    profile.ip,
                    profile.ip,
                    profile.country_code,
                    profile.as_org,
                    last_paths,
                    profile.ip,
                ),
            )
            self._conn.commit()

    def get_history(self, ip: str) -> dict | None:
        """Get historical data for an IP."""
        with self._lock:
            if not self._conn:
                return None
            row = self._conn.execute(
                "SELECT * FROM ip_history WHERE ip = ?", (ip,)
            ).fetchone()
        if not row:
            return None
        cols = [
            "ip",
            "first_seen_ever",
            "last_seen_ever",
            "total_historical_requests",
            "total_historical_bytes",
            "sessions_seen",
            "suspicious_count",
            "country_code",
            "as_org",
            "last_paths",
        ]
        return dict(zip(cols, row))

    def get_recurring_offenders(self, min_sessions: int = 2) -> list[dict]:
        """Get IPs seen in multiple sessions."""
        with self._lock:
            if not self._conn:
                return []
            rows = self._conn.execute(
                "SELECT * FROM ip_history WHERE sessions_seen >= ? "
                "ORDER BY sessions_seen DESC",
                (min_sessions,),
            ).fetchall()
        cols = [
            "ip",
            "first_seen_ever",
            "last_seen_ever",
            "total_historical_requests",
            "total_historical_bytes",
            "sessions_seen",
            "suspicious_count",
            "country_code",
            "as_org",
            "last_paths",
        ]
        return [dict(zip(cols, row)) for row in rows]

    def get_session_count(self, ip: str) -> int:
        """Get the number of sessions an IP has been seen in."""
        with self._lock:
            if not self._conn:
                return 0
            row = self._conn.execute(
                "SELECT sessions_seen FROM ip_history WHERE ip = ?", (ip,)
            ).fetchone()
        return row[0] if row else 0

    def is_new_to_session(self, ip: str) -> bool:
        """Check if an IP hasn't been recorded in this session yet."""
        return ip not in self._session_recorded_ips

    def format_history_line(self, ip: str) -> str:
        """Format a human-readable one-line summary of an IP's history."""
        hist = self.get_history(ip)
        if not hist:
            return "History: first session"
        return (
            f"History: seen {hist['sessions_seen']}x | "
            f"First ever: {hist['first_seen_ever'][:10]} | "
            f"Total reqs: {hist['total_historical_requests']} | "
            f"Total bytes: {format_bytes(hist['total_historical_bytes'])}"
            + (
                f" | Suspicious: {hist['suspicious_count']}x"
                if hist["suspicious_count"]
                else ""
            )
        )

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
