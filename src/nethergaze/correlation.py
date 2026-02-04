"""Correlation engine joining connections, logs, geo, and whois into IPProfiles."""

from __future__ import annotations

import threading
import time
from datetime import datetime

from nethergaze.models import (
    AggregateStats,
    BandwidthStats,
    Connection,
    GeoInfo,
    IPProfile,
    LogEntry,
    TCPState,
    WhoisInfo,
)


class CorrelationEngine:
    """Thread-safe engine that correlates all data sources into IPProfile records."""

    def __init__(self):
        self._lock = threading.Lock()
        self._profiles: dict[str, IPProfile] = {}
        self._bandwidth: BandwidthStats | None = None
        self._request_timestamps: list[float] = []

    def update_connections(self, connections: list[Connection]) -> None:
        """Update connection data. Replaces all connection lists per IP."""
        # Group connections by remote IP
        by_ip: dict[str, list[Connection]] = {}
        for conn in connections:
            by_ip.setdefault(conn.remote_ip, []).append(conn)

        with self._lock:
            # Clear old connections from all profiles
            for profile in self._profiles.values():
                profile.connections = []

            # Apply new connections
            for ip, conns in by_ip.items():
                profile = self._profiles.setdefault(ip, IPProfile(ip=ip))
                profile.connections = conns
                now = datetime.now().astimezone()
                if profile.first_seen is None:
                    profile.first_seen = now
                profile.last_seen = now

    def update_log_entries(self, entries: list[LogEntry]) -> None:
        """Add new log entries to the appropriate IP profiles."""
        now = time.time()
        with self._lock:
            for entry in entries:
                ip = entry.remote_ip
                profile = self._profiles.setdefault(ip, IPProfile(ip=ip))
                profile.log_entries.append(entry)
                profile.total_requests += 1
                profile.total_bytes_sent += entry.bytes_sent
                if profile.first_seen is None:
                    profile.first_seen = entry.timestamp
                profile.last_seen = entry.timestamp
                self._request_timestamps.append(now)

            # Trim request timestamps older than 60 seconds
            cutoff = now - 60
            self._request_timestamps = [
                t for t in self._request_timestamps if t > cutoff
            ]

    def update_geo(self, ip: str, geo: GeoInfo) -> None:
        """Update GeoIP data for an IP."""
        with self._lock:
            profile = self._profiles.setdefault(ip, IPProfile(ip=ip))
            profile.geo = geo

    def update_whois(self, ip: str, whois: WhoisInfo) -> None:
        """Update whois data for an IP."""
        with self._lock:
            profile = self._profiles.setdefault(ip, IPProfile(ip=ip))
            profile.whois = whois

    def update_bandwidth(self, stats: BandwidthStats) -> None:
        """Update bandwidth statistics."""
        with self._lock:
            self._bandwidth = stats

    def get_profiles(self) -> list[IPProfile]:
        """Get all IP profiles, sorted by active connections (desc)."""
        with self._lock:
            profiles = list(self._profiles.values())
        # Sort: active connections desc, then total requests desc
        profiles.sort(key=lambda p: (p.active_connections, p.total_requests), reverse=True)
        return profiles

    def get_profile(self, ip: str) -> IPProfile | None:
        """Get a single IP profile."""
        with self._lock:
            return self._profiles.get(ip)

    def get_aggregate_stats(self) -> AggregateStats:
        """Compute aggregate dashboard stats."""
        with self._lock:
            profiles = list(self._profiles.values())
            bandwidth = self._bandwidth
            req_count = len(self._request_timestamps)

        total_conns = sum(len(p.connections) for p in profiles)
        established = sum(
            sum(1 for c in p.connections if c.state == TCPState.ESTABLISHED)
            for p in profiles
        )
        unique_ips = len([p for p in profiles if p.connections or p.log_entries])
        total_requests = sum(p.total_requests for p in profiles)
        total_bytes = sum(p.total_bytes_sent for p in profiles)

        return AggregateStats(
            total_connections=total_conns,
            established_connections=established,
            unique_ips=unique_ips,
            total_requests=total_requests,
            requests_per_minute=req_count,  # Count in last 60s = per minute
            total_bytes_sent=total_bytes,
            bandwidth=bandwidth,
        )

    def trim_stale_profiles(self, max_age_seconds: int = 300) -> None:
        """Remove profiles with no connections and no recent log entries."""
        cutoff = datetime.now().astimezone()
        with self._lock:
            to_remove = []
            for ip, profile in self._profiles.items():
                if profile.connections:
                    continue
                if profile.last_seen and (cutoff - profile.last_seen).total_seconds() > max_age_seconds:
                    to_remove.append(ip)
            for ip in to_remove:
                del self._profiles[ip]
