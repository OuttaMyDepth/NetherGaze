"""Tests for nethergaze.actions."""

from __future__ import annotations

from unittest.mock import patch

from nethergaze.actions import detect_firewall, generate_block_command


class TestDetectFirewall:
    def test_ufw_preferred(self):
        with patch("shutil.which", side_effect=lambda t: "/usr/sbin/ufw" if t == "ufw" else None):
            assert detect_firewall() == "ufw"

    def test_nft_fallback(self):
        def which(tool):
            if tool == "nft":
                return "/usr/sbin/nft"
            return None
        with patch("shutil.which", side_effect=which):
            assert detect_firewall() == "nft"

    def test_iptables_fallback(self):
        def which(tool):
            if tool == "iptables":
                return "/usr/sbin/iptables"
            return None
        with patch("shutil.which", side_effect=which):
            assert detect_firewall() == "iptables"

    def test_unknown(self):
        with patch("shutil.which", return_value=None):
            assert detect_firewall() == "unknown"


class TestGenerateBlockCommand:
    def test_ufw(self):
        cmd = generate_block_command("1.2.3.4", firewall="ufw")
        assert cmd == "sudo ufw insert 1 deny from 1.2.3.4"

    def test_nft(self):
        cmd = generate_block_command("1.2.3.4", firewall="nft")
        assert "nft add rule" in cmd
        assert "1.2.3.4" in cmd

    def test_iptables(self):
        cmd = generate_block_command("1.2.3.4", firewall="iptables")
        assert "iptables -I INPUT" in cmd
        assert "1.2.3.4" in cmd

    def test_unknown(self):
        cmd = generate_block_command("1.2.3.4", firewall="unknown")
        assert "manually" in cmd.lower() or "#" in cmd
