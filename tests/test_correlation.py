"""Tests for nethergaze.correlation."""

from datetime import datetime, timezone

from nethergaze.correlation import CorrelationEngine
from nethergaze.models import (
    BandwidthStats,
    Connection,
    GeoInfo,
    LogEntry,
    TCPState,
    WhoisInfo,
)


def _make_connection(ip: str, state: TCPState = TCPState.ESTABLISHED) -> Connection:
    return Connection(
        local_ip="0.0.0.0",
        local_port=80,
        remote_ip=ip,
        remote_port=12345,
        state=state,
        inode=1000,
    )


def _make_log_entry(ip: str, path: str = "/", status: int = 200) -> LogEntry:
    return LogEntry(
        remote_ip=ip,
        timestamp=datetime.now(timezone.utc),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        bytes_sent=1024,
        referrer="-",
        user_agent="test",
    )


class TestCorrelationEngine:
    def test_update_connections(self):
        engine = CorrelationEngine()
        conns = [
            _make_connection("1.2.3.4"),
            _make_connection("1.2.3.4", TCPState.TIME_WAIT),
            _make_connection("5.6.7.8"),
        ]
        engine.update_connections(conns)
        profiles = engine.get_profiles()
        assert len(profiles) == 2

        # 1.2.3.4 has 2 connections (1 ESTABLISHED)
        p1 = engine.get_profile("1.2.3.4")
        assert p1 is not None
        assert len(p1.connections) == 2
        assert p1.active_connections == 1

    def test_update_log_entries(self):
        engine = CorrelationEngine()
        entries = [
            _make_log_entry("1.2.3.4", "/page1"),
            _make_log_entry("1.2.3.4", "/page2"),
            _make_log_entry("9.9.9.9", "/other"),
        ]
        engine.update_log_entries(entries)

        p = engine.get_profile("1.2.3.4")
        assert p is not None
        assert p.total_requests == 2
        assert p.total_bytes_sent == 2048

    def test_connections_replaced_each_update(self):
        engine = CorrelationEngine()
        engine.update_connections([_make_connection("1.2.3.4")])
        assert len(engine.get_profile("1.2.3.4").connections) == 1

        # Second update with no connections clears them
        engine.update_connections([])
        p = engine.get_profile("1.2.3.4")
        assert p is not None
        assert len(p.connections) == 0

    def test_update_geo(self):
        engine = CorrelationEngine()
        geo = GeoInfo(country_code="US", country_name="United States", city="New York")
        engine.update_geo("1.2.3.4", geo)
        p = engine.get_profile("1.2.3.4")
        assert p.geo.country_code == "US"
        assert p.country_code == "US"

    def test_update_whois(self):
        engine = CorrelationEngine()
        whois = WhoisInfo(network_name="EXAMPLE-NET", network_cidr="1.2.3.0/24")
        engine.update_whois("1.2.3.4", whois)
        p = engine.get_profile("1.2.3.4")
        assert p.whois.network_name == "EXAMPLE-NET"

    def test_update_bandwidth(self):
        engine = CorrelationEngine()
        bw = BandwidthStats(rx_bytes=1000000, tx_bytes=500000)
        engine.update_bandwidth(bw)
        stats = engine.get_aggregate_stats()
        assert stats.bandwidth is not None
        assert stats.bandwidth.rx_bytes == 1000000

    def test_aggregate_stats(self):
        engine = CorrelationEngine()
        engine.update_connections(
            [
                _make_connection("1.2.3.4"),
                _make_connection("5.6.7.8"),
                _make_connection("5.6.7.8", TCPState.TIME_WAIT),
            ]
        )
        engine.update_log_entries(
            [
                _make_log_entry("1.2.3.4"),
                _make_log_entry("1.2.3.4"),
            ]
        )

        stats = engine.get_aggregate_stats()
        assert stats.total_connections == 3
        assert stats.established_connections == 2
        assert stats.unique_ips == 2
        assert stats.total_requests == 2

    def test_get_profiles_sorted(self):
        engine = CorrelationEngine()
        engine.update_connections(
            [
                _make_connection("1.1.1.1"),
                _make_connection("2.2.2.2"),
                _make_connection("2.2.2.2"),
            ]
        )
        profiles = engine.get_profiles()
        # 2.2.2.2 should be first (more connections)
        assert profiles[0].ip == "2.2.2.2"

    def test_get_nonexistent_profile(self):
        engine = CorrelationEngine()
        assert engine.get_profile("9.9.9.9") is None
