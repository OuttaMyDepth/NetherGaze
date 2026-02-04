"""Tests for nethergaze.collectors.connections."""

from nethergaze.collectors.connections import get_connections
from nethergaze.models import TCPState


class TestGetConnections:
    def test_parse_proc_tcp(self, tmp_proc):
        connections = get_connections(include_private=True, proc_path=str(tmp_proc))
        # We should get at least the non-LISTEN, non-loopback entries
        # Entry 0: 127.0.0.1:80 <- 192.168.1.100:12345 ESTABLISHED — remote is private
        # Entry 1: 0.0.0.0:443 <- 192.168.1.1:54321 ESTABLISHED — remote is private
        # Entry 2: LISTEN — should be skipped
        assert len(connections) >= 1

    def test_skip_listen(self, tmp_proc):
        connections = get_connections(include_private=True, proc_path=str(tmp_proc))
        for conn in connections:
            assert conn.state != TCPState.LISTEN

    def test_skip_private_by_default(self, tmp_proc):
        connections = get_connections(include_private=False, proc_path=str(tmp_proc))
        # All sample entries have private remote IPs, so none should match
        assert len(connections) == 0

    def test_nonexistent_proc(self, tmp_path):
        connections = get_connections(proc_path=str(tmp_path / "nonexistent"))
        assert connections == []

    def test_established_state(self, tmp_proc):
        connections = get_connections(include_private=True, proc_path=str(tmp_proc))
        established = [c for c in connections if c.state == TCPState.ESTABLISHED]
        assert len(established) >= 1
