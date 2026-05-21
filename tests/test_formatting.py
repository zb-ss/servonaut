"""Tests for formatting utilities."""

from datetime import timedelta

from servonaut.utils.formatting import (
    escape_cell,
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


# ---------------------------------------------------------------------------
# [MEDIUM-2] escape_cell — markup injection guard
# ---------------------------------------------------------------------------

class TestEscapeCell:
    """escape_cell must neutralise Rich markup in cloud-origin strings.

    Rich's markup.escape() converts '[' → '\\[', which causes Rich's renderer
    to treat it as a literal '[' rather than the start of a markup tag.
    """

    def test_plain_string_unchanged(self) -> None:
        assert escape_cell("my-bucket") == "my-bucket"

    def test_markup_tag_opening_bracket_escaped(self) -> None:
        """Opening bracket of a markup tag must be backslash-escaped."""
        result = escape_cell("[red]x[/]")
        # Rich escapes '[' to '\[', so the tag opener becomes '\[red]'
        assert result.startswith("\\[red]"), (
            f"Expected '\\\\[red]...' but got: {result!r}"
        )
        assert "red" in result  # text content preserved

    def test_non_markup_brackets_passed_through(self) -> None:
        """Numeric bracket sequences like [1] are not valid Rich markup tags
        so rich.markup.escape leaves them as-is (no injection risk)."""
        result = escape_cell("bucket[1]")
        # [1] is not a markup tag — Rich leaves it unchanged.
        assert result == "bucket[1]"

    def test_empty_string(self) -> None:
        assert escape_cell("") == ""

    def test_markup_injection_neutralised(self) -> None:
        """A crafted name like '[bold red]evil[/bold red]' must not parse as markup.

        After escape_cell the string starts with '\\[' so Rich sees it as a
        literal '[' rather than a tag opener — the injection is neutralised.
        """
        injected = "[bold red]evil[/bold red]"
        escaped = escape_cell(injected)
        # The key property: the result is NOT equal to the raw injected string
        # AND the opening character sequence is now the escaped form.
        assert escaped != injected
        assert escaped.startswith("\\[bold red]"), (
            f"Expected escaped form to start with '\\\\[bold red]' but got: {escaped!r}"
        )
