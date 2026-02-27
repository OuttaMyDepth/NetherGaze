"""Shared test fixtures for Nethergaze tests."""

from __future__ import annotations

import textwrap

import pytest

from nethergaze.config import AppConfig


@pytest.fixture
def tmp_proc(tmp_path):
    """Create a mock /proc filesystem structure."""
    # /proc/net/tcp with sample entries
    net_dir = tmp_path / "net"
    net_dir.mkdir()

    # Sample /proc/net/tcp content
    # Entry: 127.0.0.1:80 <- 192.168.1.100:12345, ESTABLISHED, inode 12345
    tcp_content = textwrap.dedent("""\
        sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
         0: 0100007F:0050 6401A8C0:3039 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
         1: 00000000:01BB 0101A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
         2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
    """)
    (net_dir / "tcp").write_text(tcp_content)

    # /proc/net/tcp6 (empty but valid)
    tcp6_content = textwrap.dedent("""\
        sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    """)
    (net_dir / "tcp6").write_text(tcp6_content)

    return tmp_path


@pytest.fixture
def sample_log_lines():
    """Sample HTTP server combined format log lines."""
    return [
        '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '93.184.216.34 - - [01/Jan/2025:12:00:01 +0000] "POST /api/data HTTP/1.1" 201 567 "https://example.com" "curl/7.68.0"',
        '198.51.100.1 - - [01/Jan/2025:12:00:02 +0000] "GET /missing HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
        '203.0.113.50 - - [01/Jan/2025:12:00:03 +0000] "GET /error HTTP/1.1" 500 0 "-" "Mozilla/5.0"',
        '93.184.216.34 - - [01/Jan/2025:12:00:04 +0000] "GET /style.css HTTP/1.1" 304 0 "-" "Mozilla/5.0"',
    ]


@pytest.fixture
def sample_config(tmp_path):
    """Create a sample config file and return its path."""
    config_content = textwrap.dedent("""\
        log_path = "/var/log/nginx/access.log"
        interface = "ens3"

        [refresh]
        connections_interval = 2.0
        log_interval = 1.0

        [geoip]
        enabled = false

        [whois]
        enabled = false
    """)
    config_file = tmp_path / "config.toml"
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def default_config():
    """Return a default AppConfig."""
    return AppConfig()
