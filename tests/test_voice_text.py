"""Tests for the speakable-text transformer.

Pure function, no mocks: every case pins exact output, because the
transformer's whole contract is deterministic text-in text-out. The cases
mirror what assistant replies actually contain — markdown prose, fenced
code, tables, links — plus the malformed shapes a cut-off streamed reply
produces.
"""

from __future__ import annotations

import pytest

from servonaut.services.voice_text import (
    CODE_BLOCK_PLACEHOLDER,
    TABLE_PLACEHOLDER,
    speakable_text,
)


class TestEmptyAndPlain:

    @pytest.mark.parametrize("text", ["", "   ", "\n\n", "\t \n "])
    def test_empty_and_whitespace_yield_nothing(self, text):
        assert speakable_text(text) == ""

    def test_plain_prose_passes_through(self):
        assert speakable_text("The disk is 82% full.") == "The disk is 82% full."

    def test_multiline_prose_keeps_line_structure(self):
        assert speakable_text("First point.\nSecond point.") == \
            "First point.\nSecond point."

    def test_blank_lines_are_dropped(self):
        assert speakable_text("One.\n\n\nTwo.") == "One.\nTwo."

    def test_intra_line_whitespace_is_collapsed(self):
        assert speakable_text("spaced    out\ttext") == "spaced out text"


class TestFencedCode:

    def test_fenced_block_becomes_a_placeholder(self):
        text = "Run this:\n```bash\nsystemctl restart nginx\n```\nThen check."
        assert speakable_text(text) == \
            f"Run this:\n{CODE_BLOCK_PLACEHOLDER}\nThen check."

    def test_tilde_fences_are_recognised(self):
        text = "~~~\nx = 1\n~~~"
        assert speakable_text(text) == CODE_BLOCK_PLACEHOLDER

    def test_unterminated_fence_swallows_the_rest(self):
        """A reply cut off mid-block must not have its code read aloud."""
        text = "Before.\n```python\nimport os\nos.remove('x')"
        assert speakable_text(text) == f"Before.\n{CODE_BLOCK_PLACEHOLDER}"

    def test_two_blocks_produce_two_placeholders(self):
        text = "```\na\n```\nbetween\n```\nb\n```"
        assert speakable_text(text) == \
            f"{CODE_BLOCK_PLACEHOLDER}\nbetween\n{CODE_BLOCK_PLACEHOLDER}"

    def test_markdown_inside_a_fence_is_not_processed(self):
        """Table/heading syntax inside code must not leak placeholders."""
        text = "```\n| a | b |\n|---|---|\n# not a heading\n```"
        assert speakable_text(text) == CODE_BLOCK_PLACEHOLDER

    def test_indented_fence_is_recognised(self):
        text = "  ```\n  code\n  ```"
        assert speakable_text(text) == CODE_BLOCK_PLACEHOLDER


class TestInlineCode:

    def test_inline_code_keeps_its_content(self):
        assert speakable_text("Run `df -h` to check.") == "Run df -h to check."

    def test_empty_inline_code_disappears(self):
        assert speakable_text("weird `` marks") == "weird marks"


class TestTables:

    TABLE = "| host | disk |\n|------|------|\n| web-1 | 82% |"

    def test_table_becomes_a_placeholder(self):
        assert speakable_text(self.TABLE) == TABLE_PLACEHOLDER

    def test_prose_around_a_table_survives(self):
        text = f"Usage per host:\n{self.TABLE}\nAct on the full ones."
        assert speakable_text(text) == \
            f"Usage per host:\n{TABLE_PLACEHOLDER}\nAct on the full ones."

    def test_a_lone_pipe_in_prose_is_not_a_table(self):
        text = "Use grep | sort to filter."
        assert speakable_text(text) == "Use grep | sort to filter."

    def test_pipe_lines_without_a_separator_are_not_a_table(self):
        text = "a | b\nc | d"
        assert speakable_text(text) == "a | b\nc | d"

    def test_two_tables_produce_two_placeholders(self):
        text = f"{self.TABLE}\n\n{self.TABLE}"
        assert speakable_text(text) == f"{TABLE_PLACEHOLDER}\n{TABLE_PLACEHOLDER}"


class TestUrls:

    def test_bare_url_collapses_to_its_host(self):
        assert speakable_text("See https://github.com/zb-ss/servonaut/issues/1") == \
            "See github.com"

    def test_query_string_is_dropped_too(self):
        assert speakable_text("https://example.com/search?q=errors&page=2 has it") == \
            "example.com has it"

    def test_sentence_punctuation_after_a_url_survives(self):
        assert speakable_text("Check https://example.com/docs.") == "Check example.com."

    def test_port_and_credentials_are_dropped(self):
        assert speakable_text("at https://admin@example.com:8443/panel") == \
            "at example.com"

    def test_markdown_link_keeps_the_link_text(self):
        assert speakable_text("See [the docs](https://example.com/docs) first.") == \
            "See the docs first."

    def test_markdown_image_keeps_the_alt_text(self):
        assert speakable_text("![diagram](https://example.com/d.png)") == "diagram"


class TestMarkdownSyntax:

    @pytest.mark.parametrize("text,expected", [
        ("# Heading", "Heading"),
        ("### Deep heading", "Deep heading"),
        ("**bold** words", "bold words"),
        ("__also bold__ words", "also bold words"),
        ("*emphasis* here", "emphasis here"),
        ("_emphasis_ here", "emphasis here"),
        ("~~gone~~ kept", "gone kept"),
        ("> quoted line", "quoted line"),
        (">> nested quote", "nested quote"),
        ("- bullet item", "bullet item"),
        ("* starred item", "starred item"),
        ("+ plus item", "plus item"),
    ])
    def test_syntax_is_stripped_content_kept(self, text, expected):
        assert speakable_text(text) == expected

    def test_nested_markdown_resolves(self):
        assert speakable_text("## **Bold heading** with *emphasis*") == \
            "Bold heading with emphasis"

    def test_bold_link_in_a_bullet(self):
        text = "- **Important:** read [this](https://example.com/x)"
        assert speakable_text(text) == "Important: read this"

    def test_snake_case_identifiers_are_not_de_emphasised(self):
        """Underscores inside words are identifiers, not emphasis."""
        assert speakable_text("set max_recording_seconds to 60") == \
            "set max_recording_seconds to 60"

    def test_horizontal_rules_are_dropped(self):
        assert speakable_text("above\n---\nbelow") == "above\nbelow"

    def test_numbered_lists_keep_their_numbers(self):
        assert speakable_text("1. first\n2. second") == "1. first\n2. second"


class TestToolNoise:

    @pytest.mark.parametrize("noise", [
        "Tool result run_command (ok)",
        "Running tool disk_usage",
        "Calling tool get_logs...",
        "Executing tool check_status",
        "[tool: run_command]",
        "⏺ run_command finished",
        "⚙ working",
    ])
    def test_tool_status_lines_are_dropped(self, noise):
        text = f"Before.\n{noise}\nAfter."
        assert speakable_text(text) == "Before.\nAfter."

    def test_prose_mentioning_tools_survives(self):
        """Only status-line shapes are dropped, not sentences about tools."""
        text = "The tool result shows the disk is full."
        assert speakable_text(text) == "The tool result shows the disk is full."

    def test_all_noise_yields_empty(self):
        assert speakable_text("⏺ step one\n⏺ step two") == ""


class TestComposite:

    def test_a_realistic_reply(self):
        text = (
            "## Disk check\n"
            "\n"
            "The volume on **web-1** is nearly full:\n"
            "\n"
            "| mount | used |\n"
            "|-------|------|\n"
            "| / | 91% |\n"
            "\n"
            "Free space with:\n"
            "```bash\njournalctl --vacuum-size=200M\n```\n"
            "Details at https://example.com/runbooks/disk-pressure.\n"
        )
        assert speakable_text(text) == (
            "Disk check\n"
            "The volume on web-1 is nearly full:\n"
            f"{TABLE_PLACEHOLDER}\n"
            "Free space with:\n"
            f"{CODE_BLOCK_PLACEHOLDER}\n"
            "Details at example.com."
        )

    def test_determinism(self):
        text = "# A\n**b** `c` https://d.example/e\n```\nf\n```"
        assert speakable_text(text) == speakable_text(text)
