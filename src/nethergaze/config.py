"""Configuration loading and management."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AppConfig:
    """Application configuration with sensible defaults."""

    # HTTP server access log path (supports glob patterns, e.g. /var/log/nginx/*.access.log)
    log_path: str = "/var/log/nginx/*.access.log"
    log_format: str = "auto"

    # Refresh intervals (seconds)
    connections_interval: float = 1.0
    log_interval: float = 0.5
    bandwidth_interval: float = 30.0

    # GeoIP
    geoip_enabled: bool = True
    geoip_city_db: str = "/usr/share/GeoIP/GeoLite2-City.mmdb"
    geoip_asn_db: str = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

    # Whois
    whois_enabled: bool = True
    whois_cache_ttl: int = 86400  # 24 hours
    whois_max_workers: int = 3

    # Network interface for bandwidth
    interface: str = "eth0"

    # Display
    max_log_lines: int = 500
    max_log_entries_per_ip: int = 100
    show_private_ips: bool = False

    # Filters
    cidr_allow: list[str] = field(default_factory=list)
    cidr_deny: list[str] = field(default_factory=list)
    suspicious_burst_rpm: float = 60.0
    suspicious_min_conns: int = 5
    scanner_user_agents: list[str] = field(default_factory=list)

    # Actions
    enable_block_execution: bool = False
    action_hooks: list[dict] = field(default_factory=list)

    # Paths
    cache_dir: str = field(default_factory=lambda: str(Path.home() / ".cache" / "nethergaze"))

    @classmethod
    def load(
        cls,
        config_path: str | None = None,
        cli_overrides: dict | None = None,
    ) -> AppConfig:
        """Load config from TOML file with CLI overrides.

        Resolution order: CLI flag > env var > config file > defaults
        """
        config = cls()

        # Try loading from TOML file
        toml_path = _resolve_config_path(config_path)
        if toml_path and toml_path.exists():
            with open(toml_path, "rb") as f:
                data = tomllib.load(f)
            _apply_toml(config, data)

        # Apply environment variables
        _apply_env(config)

        # Apply CLI overrides
        if cli_overrides:
            _apply_overrides(config, cli_overrides)

        return config


def _resolve_config_path(explicit_path: str | None) -> Path | None:
    """Resolve config file path."""
    if explicit_path:
        return Path(explicit_path)
    # Check XDG / default locations
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    candidates = [
        Path(xdg) / "nethergaze" / "config.toml",
        Path.home() / ".nethergaze.toml",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _apply_toml(config: AppConfig, data: dict) -> None:
    """Apply TOML data to config."""
    section_map = {
        "log": ["log_path", "log_format", "max_log_lines", "max_log_entries_per_ip"],
        "refresh": ["connections_interval", "log_interval", "bandwidth_interval"],
        "geoip": ["geoip_enabled", "geoip_city_db", "geoip_asn_db"],
        "whois": ["whois_enabled", "whois_cache_ttl", "whois_max_workers"],
        "cache": ["cache_dir"],
    }

    # Handle [filters] section
    if "filters" in data:
        filt = data["filters"]
        for key in ("cidr_allow", "cidr_deny", "scanner_user_agents"):
            if key in filt:
                setattr(config, key, filt[key])
        if "suspicious_burst_rpm" in filt:
            config.suspicious_burst_rpm = float(filt["suspicious_burst_rpm"])
        if "suspicious_min_conns" in filt:
            config.suspicious_min_conns = int(filt["suspicious_min_conns"])

    # Handle [actions] section
    if "actions" in data:
        act = data["actions"]
        if "enable_block_execution" in act:
            config.enable_block_execution = bool(act["enable_block_execution"])
        if "hooks" in act:
            config.action_hooks = act["hooks"]
    # Handle flat keys
    for key in (
        "log_path",
        "log_format",
        "interface",
        "show_private_ips",
    ):
        if key in data:
            setattr(config, key, data[key])

    # Handle sectioned keys
    for section, keys in section_map.items():
        if section in data:
            for key in keys:
                # Map section keys: e.g., geoip.enabled -> geoip_enabled
                short_key = key.removeprefix(f"{section}_") if key.startswith(f"{section}_") else key
                if short_key in data[section]:
                    setattr(config, key, data[section][short_key])


def _apply_env(config: AppConfig) -> None:
    """Apply environment variable overrides (NETHERGAZE_ prefix)."""
    env_map = {
        "NETHERGAZE_LOG_PATH": ("log_path", str),
        "NETHERGAZE_LOG_FORMAT": ("log_format", str),
        "NETHERGAZE_INTERFACE": ("interface", str),
        "NETHERGAZE_GEOIP_ENABLED": ("geoip_enabled", lambda v: v.lower() in ("1", "true", "yes")),
        "NETHERGAZE_WHOIS_ENABLED": ("whois_enabled", lambda v: v.lower() in ("1", "true", "yes")),
        "NETHERGAZE_GEOIP_CITY_DB": ("geoip_city_db", str),
        "NETHERGAZE_GEOIP_ASN_DB": ("geoip_asn_db", str),
    }
    for env_key, (attr, converter) in env_map.items():
        val = os.environ.get(env_key)
        if val is not None:
            setattr(config, attr, converter(val))


def _apply_overrides(config: AppConfig, overrides: dict) -> None:
    """Apply CLI argument overrides."""
    for key, value in overrides.items():
        if value is not None and hasattr(config, key):
            setattr(config, key, value)
