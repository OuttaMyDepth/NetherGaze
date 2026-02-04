"""Data models for VPSTracker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TCPState(Enum):
    """TCP connection states from /proc/net/tcp."""

    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11

    @classmethod
    def from_hex(cls, hex_str: str) -> TCPState:
        return cls(int(hex_str, 16))


@dataclass
class Connection:
    """A single TCP connection from /proc/net/tcp."""

    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: TCPState
    inode: int
    pid: int | None = None
    process_name: str | None = None


@dataclass
class LogEntry:
    """A parsed nginx access log entry."""

    remote_ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    bytes_sent: int
    referrer: str
    user_agent: str
    raw_line: str = ""


@dataclass
class GeoInfo:
    """GeoIP lookup result for an IP address."""

    country_code: str = "?"
    country_name: str = "Unknown"
    city: str = "?"
    latitude: float = 0.0
    longitude: float = 0.0
    asn: int | None = None
    as_org: str = "?"


@dataclass
class WhoisInfo:
    """Whois/RDAP lookup result for an IP address."""

    network_name: str = "?"
    network_cidr: str = "?"
    description: str = ""
    abuse_contact: str = ""
    last_updated: datetime | None = None


@dataclass
class IPProfile:
    """Aggregated profile for a single IP address across all data sources."""

    ip: str
    connections: list[Connection] = field(default_factory=list)
    log_entries: list[LogEntry] = field(default_factory=list)
    geo: GeoInfo | None = None
    whois: WhoisInfo | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_bytes_sent: int = 0
    total_requests: int = 0

    @property
    def active_connections(self) -> int:
        return sum(1 for c in self.connections if c.state == TCPState.ESTABLISHED)

    @property
    def country_code(self) -> str:
        if self.geo and self.geo.country_code != "?":
            return self.geo.country_code
        # Fall back to whois CIDR as a hint
        return "?"

    @property
    def as_org(self) -> str:
        if self.geo and self.geo.as_org != "?":
            return self.geo.as_org
        # Fall back to whois network name
        if self.whois and self.whois.network_name != "?":
            return self.whois.network_name
        return "?"


@dataclass
class BandwidthStats:
    """Monthly bandwidth statistics from vnstat."""

    rx_bytes: int = 0
    tx_bytes: int = 0
    month: str = ""
    year: int = 0


@dataclass
class AggregateStats:
    """Aggregate dashboard statistics."""

    total_connections: int = 0
    established_connections: int = 0
    unique_ips: int = 0
    total_requests: int = 0
    requests_per_minute: float = 0.0
    total_bytes_sent: int = 0
    bandwidth: BandwidthStats | None = None
