"""Tests for the incremental sentence chunker behind streaming speech.

The chunker is pure and dependency-free, so everything here is exact:
feed deltas in, pin the emitted sentences. Delta boundaries are the
point — the same text split at different offsets must produce the same
sentences.
"""

from __future__ import annotations

import pytest

from servonaut.services.voice_stream_chunker import (
    HOLD_BUFFER_CAP,
    VoiceStreamChunker,
)
from servonaut.services.voice_text import CODE_BLOCK_PLACEHOLDER, TABLE_PLACEHOLDER


def _run(deltas, **kwargs):
    """Feed every delta, then flush; return all emitted sentences."""
    chunker = VoiceStreamChunker(**kwargs)
    out = []
    for delta in deltas:
        out.extend(chunker.feed(delta))
    out.extend(chunker.flush())
    return out


# ---------------------------------------------------------------------------
# Sentence boundaries
# ---------------------------------------------------------------------------


class TestSentenceBoundaries:

    def test_one_sentence_completes_on_the_trailing_space(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("The disk is fine.") == []
        assert chunker.feed(" ") == ["The disk is fine."]

    def test_terminator_without_whitespace_is_held(self):
        """A delta can end mid-token: the dot alone proves nothing."""
        chunker = VoiceStreamChunker()
        assert chunker.feed("Version 2") == []
        assert chunker.feed(".") == []
        assert chunker.feed("3 shipped") == []

    @pytest.mark.parametrize("terminator", [".", "!", "?"])
    def test_all_three_terminators_split(self, terminator):
        assert _run([f"First{terminator} Second."]) == [
            f"First{terminator}", "Second.",
        ]

    def test_split_survives_any_delta_offsets(self):
        """The same text must chunk identically however it is sliced."""
        text = "One is done. Two follows! Three ends? Four."
        expected = ["One is done.", "Two follows!", "Three ends?", "Four."]
        for size in (1, 2, 3, 5, 7, 100):
            deltas = [text[i:i + size] for i in range(0, len(text), size)]
            assert _run(deltas) == expected, f"delta size {size}"

    def test_closing_quotes_stay_with_their_sentence(self):
        assert _run(['He said "stop." Then left. ']) == [
            'He said "stop."', "Then left.",
        ]

    def test_newline_confirms_a_terminator(self):
        assert _run(["First line.\nSecond"]) == ["First line.", "Second"]

    def test_paragraph_break_splits_without_punctuation(self):
        assert _run(["## Heading\n\nBody text. "]) == ["Heading", "Body text."]

    def test_single_newline_without_punctuation_does_not_split(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("- item one\n- item two\n") == []
        assert chunker.flush() == ["item one", "item two"]

    def test_flush_releases_the_remainder(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("Done. Trailing words") == ["Done."]
        assert chunker.flush() == ["Trailing words"]

    def test_flush_on_empty_is_empty(self):
        assert VoiceStreamChunker().flush() == []

    def test_empty_delta_is_a_noop(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("") == []
        assert chunker.feed("Hi there. ") == ["Hi there."]

    def test_bare_punctuation_is_never_emitted(self):
        assert _run(["... ! ? Done. "]) == ["Done."]

    def test_ellipsis_splits_after_the_run(self):
        assert _run(["Wait... okay. "]) == ["Wait...", "okay."]


# ---------------------------------------------------------------------------
# Abbreviation and number tolerance
# ---------------------------------------------------------------------------


class TestDotTolerance:

    @pytest.mark.parametrize("text,expected", [
        # File names: dot followed by letters, no whitespace.
        ("Run file.py. Then check. ", ["Run file.py.", "Then check."]),
        # Version numbers: dot followed by a digit.
        ("v2.3 is out. Upgrade now. ", ["v2.3 is out.", "Upgrade now."]),
        # IP addresses.
        ("Ping 10.0.0.1 first. Then stop. ", ["Ping 10.0.0.1 first.", "Then stop."]),
        # e.g. / i.e. — single-letter rule.
        ("Use tags, e.g. web or db. Done. ", ["Use tags, e.g. web or db.", "Done."]),
        ("The cap, i.e. the limit. Done. ", ["The cap, i.e. the limit.", "Done."]),
        # Common abbreviations.
        ("Ask Dr. Smith about it. Done. ", ["Ask Dr. Smith about it.", "Done."]),
        ("Cats, dogs, etc. still apply. Done. ",
         ["Cats, dogs, etc. still apply.", "Done."]),
        ("Speed vs. safety matters. Done. ", ["Speed vs. safety matters.", "Done."]),
        # Initials.
        ("Written by J. Smith today. Done. ",
         ["Written by J. Smith today.", "Done."]),
    ])
    def test_dots_that_must_not_split(self, text, expected):
        assert _run([text]) == expected

    def test_a_sentence_ending_in_a_number_still_splits(self):
        assert _run(["The port is 8080. Next step. "]) == [
            "The port is 8080.", "Next step.",
        ]

    def test_abbreviation_split_across_deltas(self):
        assert _run(["Use tags, e.", "g. web. Done. "]) == [
            "Use tags, e.g. web.", "Done.",
        ]


# ---------------------------------------------------------------------------
# Fenced code blocks
# ---------------------------------------------------------------------------


class TestFences:

    def test_fence_interior_is_never_emitted(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("```python\nsecret = 1. Yes. \n") == []
        assert chunker.feed("more = 2. Sure. \n") == []
        out = chunker.feed("```\n")
        assert out == [CODE_BLOCK_PLACEHOLDER]

    def test_prose_before_the_fence_emits_with_the_placeholder(self):
        out = _run(["Here is the fix:\n```py\nx = 1\n```\nDone. "])
        assert out == ["Here is the fix:", CODE_BLOCK_PLACEHOLDER, "Done."]

    def test_fence_opened_in_one_delta_closed_three_later(self):
        chunker = VoiceStreamChunker()
        assert chunker.feed("```bash\n") == []
        assert chunker.feed("echo one\n") == []
        assert chunker.feed("echo two\n") == []
        assert chunker.feed("```\nAfter. ") == [CODE_BLOCK_PLACEHOLDER, "After."]

    def test_fence_marker_split_across_deltas(self):
        """The three backticks may arrive one at a time."""
        out = _run(["Before:\n``", "`\ncode = 1\n`", "``\nAfter. "])
        assert out == ["Before:", CODE_BLOCK_PLACEHOLDER, "After."]

    def test_unclosed_fence_flushes_to_the_placeholder(self):
        """A reply cut off mid-block still announces the block once."""
        out = _run(["Look:\n```\nhalf a listing"])
        assert out == ["Look:", CODE_BLOCK_PLACEHOLDER]

    def test_tilde_fences_work_too(self):
        out = _run(["~~~\ncode\n~~~\nAfter. "])
        assert out == [CODE_BLOCK_PLACEHOLDER, "After."]

    def test_inline_backticks_are_not_a_fence(self):
        assert _run(["Run `ls -la` now. Done. "]) == ["Run ls -la now.", "Done."]

    def test_mid_line_backticks_after_a_cut_are_not_a_fence(self):
        """A sentence cut leaves the remainder mid-line; backticks there
        must not be promoted to a line-initial fence."""
        out = _run(["First. ``x`` is quoted. "])
        assert out == ["First.", "x is quoted."]

    def test_mixed_prose_and_code_keeps_order(self):
        out = _run([
            "Step one. Now run:\n```\ncmd\n```\nStep two. Finally done. ",
        ])
        assert out == [
            "Step one.",
            "Now run:", CODE_BLOCK_PLACEHOLDER,
            "Step two.", "Finally done.",
        ]


# ---------------------------------------------------------------------------
# Markdown handling parity with final-reply speech
# ---------------------------------------------------------------------------


class TestSpeakableParity:

    def test_emphasis_is_stripped(self):
        assert _run(["**Bold** and *soft* text. "]) == ["Bold and soft text."]

    def test_urls_collapse_to_their_host(self):
        out = _run(["See https://example.com/deep/path?q=1 for docs. "])
        assert out == ["See example.com for docs."]

    def test_tables_collapse_to_the_placeholder(self):
        out = _run(["| a | b |\n| --- | --- |\n| 1 | 2 |\n\nDone. "])
        assert out == [TABLE_PLACEHOLDER, "Done."]

    def test_sentence_punctuation_inside_a_cell_does_not_split_the_table(self):
        """A '. ' inside a cell must not cut the run — the rows after the
        cut would lose their separator and be spoken as prose, diverging
        from the final-reply path's single placeholder."""
        out = _run([
            "| host | notes |\n"
            "| --- | --- |\n"
            "| web-1 | Rebooted. Fine now |\n"
            "| web-2 | OK |\n"
            "\nDone. ",
        ])
        assert out == [TABLE_PLACEHOLDER, "Done."]

    def test_a_table_at_stream_end_still_collapses(self):
        """No trailing blank line: the flush must release the held run
        whole so the separator still travels with the rows."""
        out = _run([
            "Summary follows.\n"
            "| host | notes |\n"
            "| --- | --- |\n"
            "| web-1 | Rebooted. Fine now |",
        ])
        assert out == ["Summary follows.", TABLE_PLACEHOLDER]

    def test_a_table_split_across_deltas_collapses_once(self):
        out = _run([
            "| host | not",
            "es |\n| --- | --- |\n| web-1 | Rebooted. ",
            "Fine now |\n\nDone. ",
        ])
        assert out == [TABLE_PLACEHOLDER, "Done."]


# ---------------------------------------------------------------------------
# Hold-buffer cap
# ---------------------------------------------------------------------------


class TestHoldCap:

    def test_default_cap_matches_the_module_constant(self):
        chunker = VoiceStreamChunker()
        assert chunker._hold_cap == HOLD_BUFFER_CAP

    def test_boundary_free_text_is_emitted_at_the_cap(self):
        """A pathological stream cannot grow the buffer without bound."""
        chunker = VoiceStreamChunker(hold_cap=50)
        out = chunker.feed("word " * 20)  # 100 chars, no terminator
        assert len(out) == 1
        assert out[0].startswith("word word")
        assert len(chunker._buffer) <= 50

    def test_overflowing_fence_emits_the_placeholder_once(self):
        chunker = VoiceStreamChunker(hold_cap=40)
        out = []
        out.extend(chunker.feed("```\n"))
        for _ in range(10):
            out.extend(chunker.feed("filler line inside the block\n"))
        out.extend(chunker.feed("```\nAfter. "))
        out.extend(chunker.flush())
        assert out.count(CODE_BLOCK_PLACEHOLDER) == 1
        assert out[-1] == "After."
        # None of the fence interior may ever be spoken.
        assert not any("filler" in sentence for sentence in out)

    def test_overflowing_fence_never_closed_stays_silent_after_the_placeholder(self):
        chunker = VoiceStreamChunker(hold_cap=40)
        out = []
        out.extend(chunker.feed("```\n"))
        for _ in range(10):
            out.extend(chunker.feed("filler line inside the block\n"))
        out.extend(chunker.flush())
        assert out.count(CODE_BLOCK_PLACEHOLDER) == 1
        assert not any("filler" in sentence for sentence in out)

    def test_overflow_close_marker_split_across_deltas(self):
        """The closer may arrive in pieces while the interior is being
        discarded; it must still be recognised."""
        chunker = VoiceStreamChunker(hold_cap=40)
        out = []
        out.extend(chunker.feed("```\n"))
        for _ in range(10):
            out.extend(chunker.feed("filler line inside the block\n"))
        out.extend(chunker.feed("``"))
        out.extend(chunker.feed("`\nAfter. "))
        out.extend(chunker.flush())
        assert out.count(CODE_BLOCK_PLACEHOLDER) == 1
        assert out[-1] == "After."

    def test_normal_prose_never_touches_the_cap_path(self):
        chunker = VoiceStreamChunker(hold_cap=40)
        out = chunker.feed("Short one. Short two. ")
        assert out == ["Short one.", "Short two."]
