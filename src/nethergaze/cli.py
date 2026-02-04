"""CLI entry point for Nethergaze."""

from __future__ import annotations

import argparse
import sys

from nethergaze import __version__
from nethergaze.config import AppConfig


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="nethergaze",
        description="Real-time VPS network traffic dashboard",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"nethergaze {__version__}",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to TOML config file",
    )
    parser.add_argument(
        "--log-path",
        metavar="PATH",
        help="Path to nginx access log (overrides config)",
    )
    parser.add_argument(
        "--refresh-interval",
        type=float,
        metavar="SECS",
        help="Connection refresh interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        help="Network interface for bandwidth stats (default: eth0)",
    )
    parser.add_argument(
        "--no-geoip",
        action="store_true",
        help="Disable GeoIP lookups",
    )
    parser.add_argument(
        "--no-whois",
        action="store_true",
        help="Disable whois lookups",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    args = parse_args(argv)

    # Build CLI overrides dict
    overrides: dict = {}
    if args.log_path:
        overrides["log_path"] = args.log_path
    if args.refresh_interval:
        overrides["connections_interval"] = args.refresh_interval
    if args.interface:
        overrides["interface"] = args.interface
    if args.no_geoip:
        overrides["geoip_enabled"] = False
    if args.no_whois:
        overrides["whois_enabled"] = False

    config = AppConfig.load(config_path=args.config, cli_overrides=overrides)

    from nethergaze.app import NethergazeApp

    app = NethergazeApp(config)
    app.run()


if __name__ == "__main__":
    main()
