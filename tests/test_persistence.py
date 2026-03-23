"""Tests for nethergaze.persistence."""

from __future__ import annotations

from nethergaze.models import IPProfile
from nethergaze.persistence import HistoryDB


class TestHistoryDB:
    def test_record_and_retrieve(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        profile = IPProfile(ip="1.2.3.4", total_requests=10, total_bytes_sent=5000)
        db.record_session(profile)
        hist = db.get_history("1.2.3.4")
        assert hist is not None
        assert hist["sessions_seen"] == 1
        assert hist["total_historical_requests"] == 10
        assert hist["total_historical_bytes"] == 5000
        db.close()

    def test_recurring_offender(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        profile = IPProfile(ip="1.2.3.4", total_requests=5, total_bytes_sent=1000)
        db.record_session(profile)
        # Reset session tracking to simulate a new session
        db._session_recorded_ips.clear()
        db.record_session(profile)
        assert db.get_session_count("1.2.3.4") == 2
        offenders = db.get_recurring_offenders(min_sessions=2)
        assert len(offenders) == 1
        assert offenders[0]["ip"] == "1.2.3.4"
        db.close()

    def test_nonexistent_ip(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        assert db.get_history("9.9.9.9") is None
        assert db.get_session_count("9.9.9.9") == 0
        db.close()

    def test_suspicious_count(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        profile = IPProfile(ip="1.2.3.4", total_requests=10, total_bytes_sent=5000)
        db.record_session(profile, is_suspicious=True)
        hist = db.get_history("1.2.3.4")
        assert hist["suspicious_count"] == 1
        db.close()

    def test_update_in_session_no_increment(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        profile = IPProfile(ip="1.2.3.4", total_requests=5, total_bytes_sent=1000)
        db.record_session(profile)
        assert db.get_session_count("1.2.3.4") == 1
        # update_in_session should NOT increment sessions_seen
        profile.total_requests = 10
        db.update_in_session(profile)
        assert db.get_session_count("1.2.3.4") == 1
        db.close()

    def test_is_new_to_session(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        assert db.is_new_to_session("1.2.3.4") is True
        profile = IPProfile(ip="1.2.3.4", total_requests=5, total_bytes_sent=1000)
        db.record_session(profile)
        assert db.is_new_to_session("1.2.3.4") is False
        db.close()

    def test_format_history_line_first_session(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        line = db.format_history_line("9.9.9.9")
        assert "first session" in line
        db.close()

    def test_format_history_line_recurring(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        profile = IPProfile(ip="1.2.3.4", total_requests=100, total_bytes_sent=50000)
        db.record_session(profile)
        db._session_recorded_ips.clear()
        db.record_session(profile)
        line = db.format_history_line("1.2.3.4")
        assert "2x" in line
        assert "Total reqs:" in line
        db.close()

    def test_close_and_reopen(self, tmp_path):
        db_path = tmp_path / "test.db"
        db = HistoryDB(db_path)
        profile = IPProfile(ip="1.2.3.4", total_requests=5, total_bytes_sent=1000)
        db.record_session(profile)
        db.close()
        # Reopen
        db2 = HistoryDB(db_path)
        assert db2.get_session_count("1.2.3.4") == 1
        db2.close()

    def test_get_recurring_offenders_min_sessions(self, tmp_path):
        db = HistoryDB(tmp_path / "test.db")
        p1 = IPProfile(ip="1.1.1.1", total_requests=5, total_bytes_sent=1000)
        p2 = IPProfile(ip="2.2.2.2", total_requests=10, total_bytes_sent=2000)
        db.record_session(p1)
        db.record_session(p2)
        # Only p2 gets a second session
        db._session_recorded_ips.clear()
        db.record_session(p2)
        offenders = db.get_recurring_offenders(min_sessions=2)
        assert len(offenders) == 1
        assert offenders[0]["ip"] == "2.2.2.2"
        db.close()
