"""Tests for nethergaze.collectors.logs."""

import json

from nethergaze.collectors.logs import (
    LogFormat,
    LogWatcher,
    MultiLogWatcher,
    parse_log_line,
)


class TestParseLogLine:
    def test_valid_200(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.remote_ip == "93.184.216.34"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status_code == 200
        assert entry.bytes_sent == 1234
        assert entry.protocol == "HTTP/1.1"

    def test_valid_404(self):
        line = '198.51.100.1 - - [01/Jan/2025:12:00:02 +0000] "GET /missing HTTP/1.1" 404 0 "-" "Mozilla/5.0"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.status_code == 404
        assert entry.bytes_sent == 0

    def test_post_with_referrer(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:01 +0000] "POST /api/data HTTP/1.1" 201 567 "https://example.com" "curl/7.68.0"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.method == "POST"
        assert entry.status_code == 201
        assert entry.referrer == "https://example.com"
        assert entry.user_agent == "curl/7.68.0"

    def test_dash_bytes(self):
        line = '10.0.0.1 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "Mozilla/5.0"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.bytes_sent == 0

    def test_invalid_line(self):
        assert parse_log_line("this is not a log line") is None

    def test_empty_line(self):
        assert parse_log_line("") is None

    def test_timestamp_parsing(self):
        line = '1.2.3.4 - - [15/Mar/2025:08:30:45 +0100] "GET / HTTP/1.1" 200 100 "-" "test"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.timestamp.hour == 8
        assert entry.timestamp.minute == 30


class TestParseCommonFormat:
    def test_valid_common_line(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        entry = parse_log_line(line, LogFormat.COMMON)
        assert entry is not None
        assert entry.remote_ip == "93.184.216.34"
        assert entry.method == "GET"
        assert entry.path == "/index.html"
        assert entry.status_code == 200
        assert entry.bytes_sent == 1234
        assert entry.referrer == ""
        assert entry.user_agent == ""

    def test_dash_bytes_common(self):
        line = '10.0.0.1 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 304 -'
        entry = parse_log_line(line, LogFormat.COMMON)
        assert entry is not None
        assert entry.bytes_sent == 0

    def test_common_line_does_not_match_combined_regex(self):
        """Common format line should NOT parse as combined (no referrer/UA fields)."""
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
        entry = parse_log_line(line, LogFormat.COMBINED)
        assert entry is None


class TestParseJsonFormat:
    def test_caddy_style_nested(self):
        data = {
            "request": {
                "remote_ip": "1.2.3.4",
                "method": "GET",
                "uri": "/test",
                "proto": "HTTP/2.0",
                "headers": {
                    "User-Agent": ["Mozilla/5.0"],
                    "Referer": ["https://example.com"],
                },
            },
            "status": 200,
            "size": 4567,
            "ts": 1704067200.0,
        }
        line = json.dumps(data)
        entry = parse_log_line(line, LogFormat.JSON)
        assert entry is not None
        assert entry.remote_ip == "1.2.3.4"
        assert entry.method == "GET"
        assert entry.path == "/test"
        assert entry.protocol == "HTTP/2.0"
        assert entry.status_code == 200
        assert entry.bytes_sent == 4567
        assert entry.referrer == "https://example.com"
        assert entry.user_agent == "Mozilla/5.0"

    def test_flat_json(self):
        data = {
            "remote_ip": "5.6.7.8",
            "method": "POST",
            "uri": "/api",
            "proto": "HTTP/1.1",
            "status": 201,
            "size": 100,
            "referrer": "https://test.com",
            "user_agent": "curl/7.68.0",
        }
        line = json.dumps(data)
        entry = parse_log_line(line, LogFormat.JSON)
        assert entry is not None
        assert entry.remote_ip == "5.6.7.8"
        assert entry.method == "POST"
        assert entry.path == "/api"
        assert entry.status_code == 201
        assert entry.referrer == "https://test.com"
        assert entry.user_agent == "curl/7.68.0"

    def test_invalid_json(self):
        assert parse_log_line("not json {", LogFormat.JSON) is None

    def test_missing_ip(self):
        data = {"method": "GET", "status": 200}
        assert parse_log_line(json.dumps(data), LogFormat.JSON) is None

    def test_remote_addr_with_port_stripping(self):
        data = {
            "remote_addr": "1.2.3.4:12345",
            "method": "GET",
            "uri": "/",
            "status": 200,
            "size": 0,
        }
        line = json.dumps(data)
        entry = parse_log_line(line, LogFormat.JSON)
        assert entry is not None
        assert entry.remote_ip == "1.2.3.4"


class TestAutoDetection:
    def test_auto_detects_combined(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        entry = parse_log_line(line, LogFormat.AUTO)
        assert entry is not None
        assert entry.remote_ip == "93.184.216.34"
        assert entry.user_agent == "Mozilla/5.0"

    def test_auto_detects_common(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 100'
        entry = parse_log_line(line, LogFormat.AUTO)
        assert entry is not None
        assert entry.remote_ip == "93.184.216.34"
        assert entry.referrer == ""
        assert entry.user_agent == ""

    def test_auto_detects_json(self):
        data = {
            "remote_ip": "1.2.3.4",
            "method": "GET",
            "uri": "/",
            "status": 200,
            "size": 0,
        }
        entry = parse_log_line(json.dumps(data), LogFormat.AUTO)
        assert entry is not None
        assert entry.remote_ip == "1.2.3.4"

    def test_default_arg_is_auto(self):
        line = '93.184.216.34 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        entry = parse_log_line(line)
        assert entry is not None
        assert entry.remote_ip == "93.184.216.34"


class TestLogWatcher:
    def test_poll_new_lines(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text("")
        watcher = LogWatcher(str(log_file))
        # First poll — seek to end
        entries = watcher.poll()
        assert entries == []

        # Append new lines (simulates nginx writing)
        with open(log_file, "a") as f:
            f.write(
                '1.2.3.4 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n'
            )

        entries = watcher.poll()
        assert len(entries) == 1
        assert entries[0].remote_ip == "1.2.3.4"
        watcher.close()

    def test_nonexistent_log(self, tmp_path):
        watcher = LogWatcher(str(tmp_path / "nope.log"))
        assert watcher.poll() == []

    def test_per_ip_buffer(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text("")
        watcher = LogWatcher(str(log_file), max_entries_per_ip=2)
        watcher.poll()  # init — seek to end

        # Append 5 lines for same IP
        with open(log_file, "a") as f:
            for i in range(5):
                f.write(
                    f'1.2.3.4 - - [01/Jan/2025:12:00:0{i} +0000] "GET /p{i} HTTP/1.1" 200 100 "-" "test"\n'
                )

        watcher.poll()

        buffered = watcher.get_entries_for_ip("1.2.3.4")
        assert len(buffered) == 2  # capped at max_entries_per_ip
        watcher.close()

    def test_poll_json_format(self, tmp_path):
        log_file = tmp_path / "access.log"
        log_file.write_text("")
        watcher = LogWatcher(str(log_file), log_format="json")
        watcher.poll()  # init — seek to end

        data = {
            "remote_ip": "5.6.7.8",
            "method": "GET",
            "uri": "/api",
            "status": 200,
            "size": 42,
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(data) + "\n")

        entries = watcher.poll()
        assert len(entries) == 1
        assert entries[0].remote_ip == "5.6.7.8"
        assert entries[0].path == "/api"
        watcher.close()


class TestMultiLogWatcher:
    def test_rescan_picks_up_new_files(self, tmp_path):
        # Start with one log file
        log1 = tmp_path / "site1.access.log"
        log1.write_text("")
        pattern = str(tmp_path / "*.access.log")
        watcher = MultiLogWatcher(pattern)
        assert len(watcher._watchers) == 1

        # Add a second file and rescan
        log2 = tmp_path / "site2.access.log"
        log2.write_text("")
        watcher.rescan()
        assert len(watcher._watchers) == 2
        assert str(log2) in watcher._watchers
        watcher.close()

    def test_rescan_removes_deleted_files(self, tmp_path):
        log1 = tmp_path / "site1.access.log"
        log1.write_text("")
        log2 = tmp_path / "site2.access.log"
        log2.write_text("")
        pattern = str(tmp_path / "*.access.log")
        watcher = MultiLogWatcher(pattern)
        assert len(watcher._watchers) == 2

        # Delete one file and rescan
        log2.unlink()
        watcher.rescan()
        assert len(watcher._watchers) == 1
        assert str(log1) in watcher._watchers
        assert str(log2) not in watcher._watchers
        watcher.close()

    def test_poll_across_multiple_files(self, tmp_path):
        log1 = tmp_path / "site1.access.log"
        log2 = tmp_path / "site2.access.log"
        log1.write_text("")
        log2.write_text("")
        pattern = str(tmp_path / "*.access.log")
        watcher = MultiLogWatcher(pattern)
        # First poll — seek to end
        watcher.poll()

        with open(log1, "a") as f:
            f.write(
                '1.2.3.4 - - [01/Jan/2025:12:00:00 +0000] "GET /a HTTP/1.1" 200 100 "-" "test"\n'
            )
        with open(log2, "a") as f:
            f.write(
                '5.6.7.8 - - [01/Jan/2025:12:00:01 +0000] "GET /b HTTP/1.1" 200 200 "-" "test"\n'
            )

        entries = watcher.poll()
        assert len(entries) == 2
        ips = {e.remote_ip for e in entries}
        assert ips == {"1.2.3.4", "5.6.7.8"}
        watcher.close()
