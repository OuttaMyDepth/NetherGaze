"""Tests for nethergaze.collectors.logs."""

from nethergaze.collectors.logs import LogWatcher, parse_log_line


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
            f.write('1.2.3.4 - - [01/Jan/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n')

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
                f.write(f'1.2.3.4 - - [01/Jan/2025:12:00:0{i} +0000] "GET /p{i} HTTP/1.1" 200 100 "-" "test"\n')

        watcher.poll()

        buffered = watcher.get_entries_for_ip("1.2.3.4")
        assert len(buffered) == 2  # capped at max_entries_per_ip
        watcher.close()
