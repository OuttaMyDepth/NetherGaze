"""Utility functions for IP parsing, formatting, and classification."""

from __future__ import annotations

import ipaddress
import struct


def parse_hex_ipv4(hex_str: str) -> str:
    """Parse a hex-encoded IPv4 address from /proc/net/tcp (little-endian).

    /proc/net/tcp stores IPv4 as a little-endian 32-bit hex string.
    E.g., "0100007F" -> 127.0.0.1
    """
    packed = struct.pack("<I", int(hex_str, 16))
    return str(ipaddress.IPv4Address(packed))


def parse_hex_ipv6(hex_str: str) -> str:
    """Parse a hex-encoded IPv6 address from /proc/net/tcp6.

    /proc/net/tcp6 stores IPv6 as four little-endian 32-bit words.
    E.g., "00000000000000000000000001000000" -> ::1
    """
    words = [hex_str[i : i + 8] for i in range(0, 32, 8)]
    packed = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return str(ipaddress.IPv6Address(packed))


def parse_hex_port(hex_str: str) -> int:
    """Parse a hex-encoded port number (big-endian)."""
    return int(hex_str, 16)


def format_bytes(num_bytes: int | float) -> str:
    """Format byte count to human-readable string.

    Examples:
        format_bytes(0) -> "0 B"
        format_bytes(1023) -> "1023 B"
        format_bytes(1024) -> "1.0 KiB"
        format_bytes(1048576) -> "1.0 MiB"
    """
    if num_bytes < 0:
        return f"-{format_bytes(-num_bytes)}"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num_bytes) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(num_bytes)} {unit}"
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TiB"


def format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration string.

    Examples:
        format_duration(45) -> "45s"
        format_duration(125) -> "2m 5s"
        format_duration(3661) -> "1h 1m"
        format_duration(86400) -> "1d 0h"
    """
    if seconds < 0:
        return "0s"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def is_private_ip(ip_str: str) -> bool:
    """Check whether an IP address is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_link_local
        )
    except ValueError:
        return False
