"""Tests for formatting utilities."""

from datetime import timedelta

from servonaut.utils.formatting import (
    format_timedelta,
    truncate_string,
    format_file_size,
)


class TestFormatTimedelta:

    def test_seconds_only(self):
        assert format_timedelta(timedelta(seconds=30)) == '30s'

    def test_zero(self):
        assert format_timedelta(timedelta(0)) == '0s'

    def test_minutes_only(self):
        # Seconds are omitted when minutes are present
        assert format_timedelta(timedelta(minutes=3, seconds=42)) == '3m'

    def test_hours_and_minutes(self):
        assert format_timedelta(timedelta(hours=2, minutes=15)) == '2h 15m'

    def test_days_hours_minutes(self):
        assert format_timedelta(timedelta(days=2, hours=3, minutes=15)) == '2d 3h 15m'

    def test_days_only(self):
        assert format_timedelta(timedelta(days=5)) == '5d 0s'

    def test_one_hour_exact(self):
        assert format_timedelta(timedelta(hours=1)) == '1h'


class TestTruncateString:

    def test_short_string(self):
        assert truncate_string('short') == 'short'

    def test_exact_length(self):
        s = 'x' * 40
        assert truncate_string(s) == s

    def test_long_string(self):
        result = truncate_string('this is a very long string that will be truncated', 20)
        assert result == 'this is a very lo...'
        assert len(result) == 20

    def test_custom_length(self):
        assert truncate_string('hello world', 8) == 'hello...'

    def test_empty_string(self):
        assert truncate_string('') == ''


class TestFormatFileSize:

    def test_bytes(self):
        assert format_file_size(500) == '500 B'

    def test_zero_bytes(self):
        assert format_file_size(0) == '0 B'

    def test_kilobytes(self):
        assert format_file_size(1024) == '1.0 KB'

    def test_kilobytes_fractional(self):
        assert format_file_size(1536) == '1.5 KB'

    def test_megabytes(self):
        assert format_file_size(1048576) == '1.0 MB'

    def test_gigabytes(self):
        assert format_file_size(1073741824) == '1.0 GB'
