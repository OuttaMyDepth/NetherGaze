"""Tests for vpstracker.utils."""

from vpstracker.utils import (
    format_bytes,
    format_duration,
    is_private_ip,
    parse_hex_ipv4,
    parse_hex_ipv6,
    parse_hex_port,
)


class TestParseHexIPv4:
    def test_loopback(self):
        assert parse_hex_ipv4("0100007F") == "127.0.0.1"

    def test_any(self):
        assert parse_hex_ipv4("00000000") == "0.0.0.0"

    def test_real_ip(self):
        # 192.168.1.100 in little-endian hex: C0=192, A8=168, 01=1, 64=100
        # Little-endian: 6401A8C0
        assert parse_hex_ipv4("6401A8C0") == "192.168.1.100"

    def test_public_ip(self):
        # 1.1.1.1 in little-endian: 01010101
        assert parse_hex_ipv4("01010101") == "1.1.1.1"


class TestParseHexIPv6:
    def test_loopback(self):
        assert parse_hex_ipv6("00000000000000000000000001000000") == "::1"

    def test_any(self):
        assert parse_hex_ipv6("00000000000000000000000000000000") == "::"


class TestParseHexPort:
    def test_http(self):
        assert parse_hex_port("0050") == 80

    def test_https(self):
        assert parse_hex_port("01BB") == 443

    def test_high_port(self):
        assert parse_hex_port("C000") == 49152


class TestFormatBytes:
    def test_zero(self):
        assert format_bytes(0) == "0 B"

    def test_bytes(self):
        assert format_bytes(500) == "500 B"

    def test_kib(self):
        assert format_bytes(1024) == "1.0 KiB"

    def test_mib(self):
        assert format_bytes(1048576) == "1.0 MiB"

    def test_gib(self):
        assert format_bytes(1073741824) == "1.0 GiB"

    def test_negative(self):
        assert format_bytes(-1024) == "-1.0 KiB"


class TestFormatDuration:
    def test_seconds(self):
        assert format_duration(45) == "45s"

    def test_minutes(self):
        assert format_duration(125) == "2m 5s"

    def test_hours(self):
        assert format_duration(3661) == "1h 1m"

    def test_days(self):
        assert format_duration(86400) == "1d 0h"

    def test_negative(self):
        assert format_duration(-5) == "0s"

    def test_zero(self):
        assert format_duration(0) == "0s"


class TestIsPrivateIP:
    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_rfc1918_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert is_private_ip("192.168.1.1") is True

    def test_public(self):
        assert is_private_ip("8.8.8.8") is False

    def test_ipv6_loopback(self):
        assert is_private_ip("::1") is True

    def test_invalid(self):
        assert is_private_ip("not-an-ip") is False

    def test_link_local(self):
        assert is_private_ip("169.254.1.1") is True
