"""Tests for nethergaze.collectors.auth."""

from __future__ import annotations

from nethergaze.collectors.auth import AuthLogWatcher, parse_auth_line
from nethergaze.models import AuthEventType


# --- Traditional syslog format (Mar 22 10:15:30 hostname sshd[PID]) ---


class TestParseAuthLineSyslog:
    def test_failed_password(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Failed password for admin from 1.2.3.4 port 54321 ssh2"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.remote_ip == "1.2.3.4"
        assert entry.event_type == AuthEventType.FAILED_PASSWORD
        assert entry.username == "admin"

    def test_failed_password_invalid_user(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Failed password for invalid user test from 1.2.3.4 port 54321 ssh2"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.FAILED_PASSWORD
        assert entry.username == "test"
        assert entry.remote_ip == "1.2.3.4"

    def test_invalid_user(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Invalid user hacker from 5.6.7.8 port 12345"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.INVALID_USER
        assert entry.username == "hacker"
        assert entry.remote_ip == "5.6.7.8"

    def test_accepted_password(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Accepted password for ubuntu from 10.0.0.1 port 22 ssh2"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.ACCEPTED_PASSWORD
        assert entry.username == "ubuntu"
        assert entry.remote_ip == "10.0.0.1"

    def test_accepted_publickey(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Accepted publickey for deploy from 192.168.1.5 port 44444 ssh2"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.ACCEPTED_PASSWORD
        assert entry.username == "deploy"

    def test_connection_closed_authenticating(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Connection closed by authenticating user root 1.2.3.4 port 54321"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.CONNECTION_CLOSED
        assert entry.username == "root"

    def test_disconnected_from(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Disconnected from authenticating user admin 5.6.7.8 port 12345"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.CONNECTION_CLOSED
        assert entry.username == "admin"

    def test_timestamp_parsed(self):
        line = "Mar 22 10:15:30 myhost sshd[1234]: Failed password for admin from 1.2.3.4 port 54321 ssh2"
        entry = parse_auth_line(line)
        assert entry.timestamp.month == 3
        assert entry.timestamp.day == 22
        assert entry.timestamp.hour == 10
        assert entry.timestamp.minute == 15


# --- ISO 8601 format with sshd-session (Ubuntu 24.10+) ---


class TestParseAuthLineISO:
    def test_invalid_user_sshd_session(self):
        line = "2026-03-23T03:10:16.671254+00:00 vps-2bae6cbe sshd-session[1557541]: Invalid user centos from 186.96.145.241 port 45756"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.INVALID_USER
        assert entry.username == "centos"
        assert entry.remote_ip == "186.96.145.241"

    def test_accepted_publickey_sshd_session(self):
        line = "2026-03-23T03:11:36.081734+00:00 vps-2bae6cbe sshd-session[1557599]: Accepted publickey for ubuntu from 104.188.171.173 port 34782 ssh2: ED25519 SHA256:xyz"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.ACCEPTED_PASSWORD
        assert entry.username == "ubuntu"
        assert entry.remote_ip == "104.188.171.173"

    def test_connection_closed_by_invalid_user(self):
        line = "2026-03-23T03:10:29.839579+00:00 vps-2bae6cbe sshd-session[1557546]: Connection closed by invalid user solana 195.178.110.30 port 43472 [preauth]"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.CONNECTION_CLOSED
        assert entry.username == "solana"
        assert entry.remote_ip == "195.178.110.30"

    def test_connection_closed_authenticating_user(self):
        line = "2026-03-23T03:11:24.939617+00:00 vps-2bae6cbe sshd-session[1557597]: Connection closed by authenticating user root 45.148.10.121 port 45596 [preauth]"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.CONNECTION_CLOSED
        assert entry.username == "root"
        assert entry.remote_ip == "45.148.10.121"

    def test_failed_password_sshd_session(self):
        line = "2026-03-23T10:00:00.000000+00:00 myhost sshd-session[9999]: Failed password for admin from 1.2.3.4 port 54321 ssh2"
        entry = parse_auth_line(line)
        assert entry is not None
        assert entry.event_type == AuthEventType.FAILED_PASSWORD
        assert entry.username == "admin"

    def test_iso_timestamp_parsed(self):
        line = "2026-03-23T03:10:16.671254+00:00 vps sshd-session[1234]: Invalid user test from 1.2.3.4 port 12345"
        entry = parse_auth_line(line)
        assert entry.timestamp.year == 2026
        assert entry.timestamp.month == 3
        assert entry.timestamp.day == 23
        assert entry.timestamp.hour == 3
        assert entry.timestamp.minute == 10


# --- Edge cases ---


class TestParseAuthLineEdgeCases:
    def test_irrelevant_line(self):
        line = (
            "Mar 22 10:15:30 myhost CRON[5678]: pam_unix(cron:session): session opened"
        )
        assert parse_auth_line(line) is None

    def test_empty_line(self):
        assert parse_auth_line("") is None

    def test_systemd_logind_ignored(self):
        line = "2026-03-23T03:11:49.394892+00:00 vps systemd-logind[984]: New session 4076 of user ubuntu."
        assert parse_auth_line(line) is None


# --- AuthLogWatcher ---


class TestAuthLogWatcher:
    def test_poll_new_lines(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text("")
        watcher = AuthLogWatcher(str(log_file))
        entries = watcher.poll()
        assert entries == []
        with open(log_file, "a") as f:
            f.write(
                "Mar 22 10:15:30 myhost sshd[1234]: "
                "Failed password for admin from 1.2.3.4 port 54321 ssh2\n"
            )
        entries = watcher.poll()
        assert len(entries) == 1
        assert entries[0].remote_ip == "1.2.3.4"
        watcher.close()

    def test_nonexistent_log(self, tmp_path):
        watcher = AuthLogWatcher(str(tmp_path / "nope.log"))
        assert watcher.poll() == []

    def test_multiple_entries(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text("")
        watcher = AuthLogWatcher(str(log_file))
        watcher.poll()  # initial seek to end
        with open(log_file, "a") as f:
            f.write(
                "Mar 22 10:15:30 myhost sshd[1234]: "
                "Failed password for admin from 1.2.3.4 port 54321 ssh2\n"
            )
            f.write(
                "Mar 22 10:15:31 myhost sshd[1234]: "
                "Invalid user hacker from 5.6.7.8 port 12345\n"
            )
            f.write(
                "Mar 22 10:15:32 myhost CRON[5678]: "
                "pam_unix(cron:session): session opened\n"
            )
        entries = watcher.poll()
        assert len(entries) == 2
        assert entries[0].event_type == AuthEventType.FAILED_PASSWORD
        assert entries[1].event_type == AuthEventType.INVALID_USER
        watcher.close()

    def test_iso_format_entries(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text("")
        watcher = AuthLogWatcher(str(log_file))
        watcher.poll()  # initial seek to end
        with open(log_file, "a") as f:
            f.write(
                "2026-03-23T03:10:16.671254+00:00 vps sshd-session[1234]: "
                "Invalid user centos from 186.96.145.241 port 45756\n"
            )
            f.write(
                "2026-03-23T03:10:29.839579+00:00 vps sshd-session[1235]: "
                "Connection closed by invalid user solana 195.178.110.30 port 43472 [preauth]\n"
            )
        entries = watcher.poll()
        assert len(entries) == 2
        assert entries[0].event_type == AuthEventType.INVALID_USER
        assert entries[0].remote_ip == "186.96.145.241"
        assert entries[1].event_type == AuthEventType.CONNECTION_CLOSED
        assert entries[1].remote_ip == "195.178.110.30"
        watcher.close()
