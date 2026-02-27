"""Filter state and predicate logic for dashboard views."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from nethergaze.models import IPProfile, LogEntry, TCPState

# Known scanner/bot user-agent substrings
SCANNER_PATTERNS = [
    "zgrab",
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "nuclei",
    "httpx",
    "censys",
    "shodan",
]


def has_scanner_ua(user_agent: str) -> bool:
    """Check if user-agent matches known scanner patterns."""
    ua_lower = user_agent.lower()
    return any(p in ua_lower for p in SCANNER_PATTERNS)


def ip_in_networks(
    ip: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Check if an IP is contained in any of the given networks."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def parse_cidr_list(
    cidrs: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a list of CIDR strings into network objects, skipping invalid."""
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            pass
    return nets


def parse_status_code_spec(spec: str) -> list[tuple[int, int]] | None:
    """Parse status code spec like '4xx,5xx' or '400-499,500-599'.

    Returns list of (lo, hi) inclusive ranges, or None if empty/invalid.
    """
    if not spec or not spec.strip():
        return None
    ranges: list[tuple[int, int]] = []
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        if part == "2xx":
            ranges.append((200, 299))
        elif part == "3xx":
            ranges.append((300, 399))
        elif part == "4xx":
            ranges.append((400, 499))
        elif part == "5xx":
            ranges.append((500, 599))
        elif "-" in part:
            try:
                lo, hi = part.split("-", 1)
                ranges.append((int(lo.strip()), int(hi.strip())))
            except ValueError:
                pass
        else:
            try:
                code = int(part)
                ranges.append((code, code))
            except ValueError:
                pass
    return ranges if ranges else None


def parse_tcp_states(spec: str) -> set[TCPState] | None:
    """Parse TCP state spec like 'SYN_RECV,ESTABLISHED'.

    Returns set of TCPState values, or None if empty/invalid.
    """
    if not spec or not spec.strip():
        return None
    states: set[TCPState] = set()
    for name in spec.split(","):
        name = name.strip().upper()
        if not name:
            continue
        try:
            states.add(TCPState[name])
        except KeyError:
            pass
    return states if states else None


@dataclass
class FilterState:
    """Composable filter predicates for dashboard views.

    Normal mode: all active criteria AND-composed.
    Suspicious mode: matches any suspicious pattern (OR logic).
    """

    tcp_states: set[TCPState] | None = None
    status_codes: list[tuple[int, int]] | None = None
    min_request_rate: float | None = None
    cidr_allow: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    cidr_deny: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    text_filter: str | None = None
    suspicious_mode: bool = False

    # Suspicious mode thresholds (configurable)
    suspicious_burst_rpm: float = 60.0
    suspicious_min_conns: int = 5
    extra_scanner_patterns: list[str] = field(default_factory=list)

    @property
    def is_active(self) -> bool:
        return (
            self.tcp_states is not None
            or self.status_codes is not None
            or self.min_request_rate is not None
            or bool(self.cidr_allow)
            or bool(self.cidr_deny)
            or self.text_filter is not None
            or self.suspicious_mode
        )

    def matches_profile(self, profile: IPProfile) -> bool:
        """Return True if profile passes all active filters."""
        if self.suspicious_mode:
            return self._is_suspicious(profile)

        if self.cidr_allow and not ip_in_networks(profile.ip, self.cidr_allow):
            return False
        if self.cidr_deny and ip_in_networks(profile.ip, self.cidr_deny):
            return False
        if self.tcp_states is not None:
            conn_states = {c.state for c in profile.connections}
            if not conn_states & self.tcp_states:
                return False
        if self.min_request_rate is not None:
            if profile.request_rate_per_min < self.min_request_rate:
                return False
        if self.text_filter is not None:
            text = f"{profile.ip} {profile.as_org}".lower()
            if self.text_filter not in text:
                return False
        return True

    def matches_log_entry(self, entry: LogEntry) -> bool:
        """Return True if log entry passes active filters."""
        if self.cidr_allow and not ip_in_networks(entry.remote_ip, self.cidr_allow):
            return False
        if self.cidr_deny and ip_in_networks(entry.remote_ip, self.cidr_deny):
            return False
        if self.status_codes is not None:
            if not any(lo <= entry.status_code <= hi for lo, hi in self.status_codes):
                return False
        if self.text_filter is not None:
            text = (
                f"{entry.remote_ip} {entry.status_code} {entry.method} {entry.path}"
            ).lower()
            if self.text_filter not in text:
                return False
        return True

    def _is_suspicious(self, profile: IPProfile) -> bool:
        """Check any suspicious pattern (OR logic)."""
        # SYN_RECV with no completed requests
        if profile.total_requests == 0 and any(
            c.state == TCPState.SYN_RECV for c in profile.connections
        ):
            return True
        # High connections, zero/low requests
        if (
            len(profile.connections) >= self.suspicious_min_conns
            and profile.total_requests <= 1
        ):
            return True
        # Burst request rate
        if profile.request_rate_per_min > self.suspicious_burst_rpm:
            return True
        # Scanner user-agent
        if profile.log_entries:
            ua = profile.log_entries[-1].user_agent
            if ua and _has_any_scanner_ua(ua, self.extra_scanner_patterns):
                return True
        return False

    def describe(self) -> str:
        """Short human-readable summary of active filters."""
        if self.suspicious_mode:
            return "SUSPICIOUS"
        parts: list[str] = []
        if self.tcp_states:
            parts.append("state:" + ",".join(s.name for s in self.tcp_states))
        if self.status_codes:
            parts.append(
                "status:" + ",".join(f"{lo}-{hi}" for lo, hi in self.status_codes)
            )
        if self.min_request_rate is not None:
            parts.append(f"rate>={self.min_request_rate:.0f}/m")
        if self.cidr_allow:
            parts.append(f"allow:{len(self.cidr_allow)}")
        if self.cidr_deny:
            parts.append(f"deny:{len(self.cidr_deny)}")
        if self.text_filter:
            parts.append(f'"{self.text_filter}"')
        return " + ".join(parts)


def _has_any_scanner_ua(user_agent: str, extra: list[str]) -> bool:
    ua_lower = user_agent.lower()
    patterns = SCANNER_PATTERNS + [p.lower() for p in extra]
    return any(p in ua_lower for p in patterns)
