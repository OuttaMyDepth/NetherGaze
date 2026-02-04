"""Tests for nethergaze.config."""

from nethergaze.config import AppConfig


class TestAppConfig:
    def test_defaults(self, default_config):
        assert default_config.log_path == "/var/log/nginx/access.log"
        assert default_config.connections_interval == 1.0
        assert default_config.geoip_enabled is True
        assert default_config.whois_enabled is True
        assert default_config.interface == "eth0"

    def test_load_from_toml(self, sample_config):
        config = AppConfig.load(config_path=str(sample_config))
        assert config.interface == "ens3"
        assert config.connections_interval == 2.0
        assert config.log_interval == 1.0
        assert config.geoip_enabled is False
        assert config.whois_enabled is False

    def test_cli_overrides(self, sample_config):
        config = AppConfig.load(
            config_path=str(sample_config),
            cli_overrides={"interface": "wlan0", "geoip_enabled": True},
        )
        # CLI should override TOML
        assert config.interface == "wlan0"
        assert config.geoip_enabled is True

    def test_load_nonexistent_config(self):
        # Should fall back to defaults gracefully
        config = AppConfig.load(config_path="/nonexistent/path.toml")
        assert config.log_path == "/var/log/nginx/access.log"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("NETHERGAZE_LOG_PATH", "/custom/log")
        monkeypatch.setenv("NETHERGAZE_INTERFACE", "lo")
        config = AppConfig.load()
        assert config.log_path == "/custom/log"
        assert config.interface == "lo"
