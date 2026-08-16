"""Incremental sentence chunking for speaking a streamed reply mid-flight.

Spoken replies used to wait for the whole message; with streaming
providers the text arrives as token deltas, and speech can start as soon
as the first complete sentence exists. :class:`VoiceStreamChunker` is
the boundary-finding half of that: token deltas go in through
:meth:`feed`, complete speakable sentences come out, and :meth:`flush`
releases whatever remains when the stream ends.

Emitted sentences are already reduced to prose via
:func:`~servonaut.services.voice_text.speakable_text`, so URLs, markdown
syntax, tables and code fences are handled identically to final-reply
speech (that function is idempotent on prose, so downstream cleaning
passes are harmless).

The rules that make mid-stream splitting safe:

* A boundary is sentence punctuation (``.``, ``!``, ``?``) followed by
  whitespace, or a paragraph break. The trailing whitespace is required
  — a delta can end mid-token, and ``file.py``, ``v2.3`` or an IP
  address must never be split at their inner dots. A dot closing a
  known abbreviation (``e.g.``, ``etc.``, initials) is not a boundary.
* Text inside an unclosed fenced code block is NEVER emitted. The block
  is held until its closing fence arrives, then collapses into the one
  spoken placeholder ``speakable_text`` uses for fences.
* A markdown table run is held as a unit: sentence punctuation inside a
  cell must not cut the buffer mid-table, because ``speakable_text``
  can only collapse a table (to its one spoken placeholder) when the
  rows and separator travel together. Lines starting with ``|`` are
  skipped over until a non-table line, paragraph break or the end of
  the stream closes the run.
* The hold buffer is capped (:data:`HOLD_BUFFER_CAP`): a pathological
  stream with no boundaries cannot grow memory without bound. On
  overflow the held text is emitted through ``speakable_text`` as-is;
  an overflowing code block keeps being discarded until its closing
  fence so its interior is never read aloud.

Deliberately a pure, deterministic, zero-dependency module with no I/O:
it must be unit-testable on an install with no audio stack at all.
Instances are single-turn and single-threaded — build one per streamed
reply and never share it across threads.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .voice_text import speakable_text

# Ceiling on text held while waiting for a sentence boundary. Generous
# enough that real prose never hits it (sentences are tens of chars),
# small enough that a boundary-free stream cannot grow memory unbounded.
HOLD_BUFFER_CAP = 2000

# Sentence-ending punctuation. A dot gets the abbreviation check below;
# question and exclamation marks are unambiguous.
_TERMINATORS = ".!?"

# Characters allowed between the terminator and its confirming
# whitespace: closing quotes and brackets ('He said "stop." Then...').
_CLOSERS = "\"')]}”’»"

_WHITESPACE = " \t\n"

# Words whose trailing dot is an abbreviation, not a sentence end.
# Single-letter words (initials, the tails of "e.g." / "i.e.") are
# handled by a length rule, so only multi-letter forms are listed.
_ABBREVIATIONS = frozenset({
    "etc", "vs", "cf", "mr", "mrs", "ms", "dr", "prof", "st",
    "jr", "sr", "inc", "ltd", "dept", "fig", "eg", "ie", "approx",
})


def _is_fence_line(stripped: str) -> bool:
    """Whether a complete line opens (or closes) a fenced code block."""
    return stripped.startswith("```") or stripped.startswith("~~~")


def _could_become_fence(stripped: str) -> bool:
    """Whether an INCOMPLETE line might still turn into a fence marker.

    A partial line consisting only of one or two backticks (or tildes)
    is ambiguous — the next delta may complete the marker — so the
    chunker holds rather than guessing.
    """
    if _is_fence_line(stripped):
        return True
    return stripped in ("`", "``", "~", "~~")


def _sentences_from(segment: str) -> List[str]:
    """Reduce one emitted segment to its speakable sentence lines.

    Lines with no alphanumeric content (a bare ellipsis, stray
    punctuation) are dropped — synthesising them is noise.
    """
    spoken = speakable_text(segment)
    if not spoken:
        return []
    return [
        line.strip()
        for line in spoken.splitlines()
        if line.strip() and any(ch.isalnum() for ch in line)
    ]


class VoiceStreamChunker:
    """Turns streamed reply deltas into complete speakable sentences.

    Usage, per streamed reply::

        chunker = VoiceStreamChunker()
        for delta in stream:
            for sentence in chunker.feed(delta):
                ...speak sentence...
        for sentence in chunker.flush():
            ...speak sentence...
    """

    def __init__(self, *, hold_cap: int = HOLD_BUFFER_CAP) -> None:
        """Build a chunker for one streamed reply.

        Args:
            hold_cap: Overrides :data:`HOLD_BUFFER_CAP`; exposed for
                tests, which should not need kilobytes of fixture text
                to exercise the overflow path.
        """
        self._buffer = ""
        # Whether the buffer's first character sits at a line start in
        # the original stream. Fence markers are only fences at a line
        # start, and a mid-line cut must not promote the remainder.
        self._starts_line = True
        self._hold_cap = max(1, int(hold_cap))
        # Overflow-inside-a-fence state: the placeholder has already
        # been emitted, so the interior is discarded (never buffered,
        # never spoken) until the closing marker arrives.
        self._skipping_fence = False
        self._skip_marker = ""
        self._skip_tail = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def feed(self, delta: str) -> List[str]:
        """Advance the stream by one delta.

        Args:
            delta: The next chunk of streamed reply text. Deltas may cut
                anywhere — mid-word, mid-fence-marker, mid-abbreviation.

        Returns:
            Every sentence completed by this delta, in order — usually
            empty, occasionally one or more speakable sentences.
        """
        if not delta:
            return []
        if self._skipping_fence:
            delta = self._consume_skipped_fence(delta)
            if not delta:
                return []
        self._buffer += delta
        out = self._drain()
        out.extend(self._enforce_cap())
        return out

    def flush(self) -> List[str]:
        """The stream ended: release whatever is still held.

        An unterminated fence collapses to its spoken placeholder (the
        same behaviour ``speakable_text`` applies to a cut-off reply).
        The chunker is reset and may in principle be reused, though
        callers build one per reply.

        Returns:
            The remaining speakable sentences, possibly empty.
        """
        out = self._drain()
        buffer = self._buffer
        was_skipping = self._skipping_fence
        self._buffer = ""
        self._starts_line = True
        self._skipping_fence = False
        self._skip_marker = ""
        self._skip_tail = ""
        if was_skipping:
            # The fence overflowed earlier: its placeholder is already
            # out, and the discarded interior must stay unspoken.
            return out
        out.extend(_sentences_from(buffer))
        return out

    # ------------------------------------------------------------------
    # Draining
    # ------------------------------------------------------------------

    def _drain(self) -> List[str]:
        """Emit every completed segment currently in the buffer."""
        out: List[str] = []
        while True:
            cut = self._next_cut()
            if cut is None:
                return out
            emit_end, resume, starts_line = cut
            segment = self._buffer[:emit_end]
            self._buffer = self._buffer[resume:]
            self._starts_line = starts_line
            out.extend(_sentences_from(segment))

    def _next_cut(self) -> Optional[Tuple[int, int, bool]]:
        """Find the earliest safe boundary in the buffer.

        Returns:
            ``(emit_end, resume, resume_starts_line)`` — emit
            ``buffer[:emit_end]``, keep ``buffer[resume:]`` — or None
            when nothing can be emitted yet.
        """
        buffer = self._buffer
        n = len(buffer)
        pos = 0
        at_line_start = self._starts_line
        in_fence = False
        fence_marker = ""
        while pos < n:
            nl = buffer.find("\n", pos)
            complete = nl != -1
            line_end = nl if complete else n
            stripped = buffer[pos:line_end].lstrip()

            if in_fence:
                # Inside a fence nothing is emittable until the closing
                # marker's line is COMPLETE — a partial line might still
                # become the closer.
                if complete and stripped.startswith(fence_marker):
                    return (nl + 1, nl + 1, True)
                if not complete:
                    return None
                pos = nl + 1
                at_line_start = True
                continue

            if at_line_start and _is_fence_line(stripped):
                if not complete:
                    # The opener line may still be growing (its info
                    # string, say); hold until it is whole.
                    return None
                in_fence = True
                fence_marker = stripped[:3]
                pos = nl + 1
                continue

            if at_line_start and not complete and _could_become_fence(stripped):
                return None

            if at_line_start and stripped.startswith("|"):
                # A table row: no sentence cut may land inside the run —
                # punctuation in a cell ("Rebooted. Fine now") would
                # split the table from its separator row and the
                # remainder would be spoken as prose instead of
                # collapsing to the table placeholder. A complete row is
                # skipped (the run keeps growing); an incomplete one may
                # still be growing, so hold. The run is emitted by the
                # first non-table line, blank line or flush, whole.
                if not complete:
                    return None
                pos = nl + 1
                at_line_start = True
                continue

            cut = self._sentence_cut(pos, line_end)
            if cut is not None:
                return cut

            if complete and not stripped:
                # A blank line: paragraph break. Everything before it is
                # a finished segment even without sentence punctuation
                # (headings, list items).
                return (pos, self._skip_whitespace(pos)[0], True)

            if not complete:
                return None
            pos = nl + 1
            at_line_start = True
        return None

    def _sentence_cut(self, start: int, line_end: int) -> Optional[Tuple[int, int, bool]]:
        """Find the earliest sentence boundary within one line span."""
        buffer = self._buffer
        n = len(buffer)
        i = start
        while i < line_end:
            ch = buffer[i]
            if ch in _TERMINATORS:
                j = i + 1
                while j < line_end and buffer[j] in _CLOSERS:
                    j += 1
                # The boundary is only confirmed by whitespace AFTER the
                # punctuation (the newline closing the line counts).
                # Without it the dot may be file.py / v2.3 / an IP — or
                # simply the last char of a delta cut mid-token.
                if (
                    j < n
                    and buffer[j] in _WHITESPACE
                    and not (ch == "." and self._is_abbreviation_dot(i))
                ):
                    resume, saw_newline = self._skip_whitespace(j)
                    return (j, resume, saw_newline)
            i += 1
        return None

    def _skip_whitespace(self, pos: int) -> Tuple[int, bool]:
        """Consume the whitespace run at *pos*; report if it broke a line."""
        buffer = self._buffer
        n = len(buffer)
        saw_newline = False
        while pos < n and buffer[pos] in _WHITESPACE:
            saw_newline = saw_newline or buffer[pos] == "\n"
            pos += 1
        return pos, saw_newline

    def _is_abbreviation_dot(self, i: int) -> bool:
        """Whether the dot at *i* closes an abbreviation, not a sentence.

        Single-letter words are treated as initials ("J. Smith") — that
        rule also covers the internal dots of "e.g." and "i.e." without
        listing every spelling.
        """
        buffer = self._buffer
        k = i - 1
        while k >= 0 and buffer[k].isalpha():
            k -= 1
        word = buffer[k + 1:i]
        if not word:
            return False
        return len(word) == 1 or word.lower() in _ABBREVIATIONS

    # ------------------------------------------------------------------
    # Overflow
    # ------------------------------------------------------------------

    def _enforce_cap(self) -> List[str]:
        """Emit the whole hold buffer when it outgrew the cap.

        Only reached when :meth:`_drain` found no boundary, i.e. one
        run-on construct exceeded the cap. Everything held is emitted
        through ``speakable_text`` as-is; if an open fence caused the
        overflow, the placeholder is emitted once now and the interior
        keeps being discarded until the closing marker.
        """
        if len(self._buffer) <= self._hold_cap:
            return []
        buffer = self._buffer
        marker = self._open_fence_marker()
        if marker is not None:
            # Keep the trailing partial line: it may be the closing
            # marker arriving in pieces, and emitting half of it would
            # make the closer undetectable forever.
            last_nl = buffer.rfind("\n")
            self._skip_tail = buffer[last_nl + 1:]
            buffer = buffer[:last_nl + 1]
            self._skipping_fence = True
            self._skip_marker = marker
            self._buffer = ""
            self._starts_line = True
            return _sentences_from(buffer)
        self._buffer = ""
        self._starts_line = buffer.endswith("\n")
        return _sentences_from(buffer)

    def _open_fence_marker(self) -> Optional[str]:
        """The marker of the fence left open by the buffer, if any."""
        buffer = self._buffer
        pos = 0
        at_line_start = self._starts_line
        in_fence = False
        marker = ""
        while True:
            nl = buffer.find("\n", pos)
            if nl == -1:
                return marker if in_fence else None
            stripped = buffer[pos:nl].lstrip()
            if in_fence:
                if stripped.startswith(marker):
                    in_fence = False
            elif at_line_start and _is_fence_line(stripped):
                in_fence = True
                marker = stripped[:3]
            pos = nl + 1
            at_line_start = True

    def _consume_skipped_fence(self, delta: str) -> str:
        """Discard overflowed fence interior until the closing marker.

        Returns:
            The text after the closing marker's line (normal chunking
            resumes there), or an empty string while still inside.
        """
        text = self._skip_tail + delta
        pos = 0
        while True:
            nl = text.find("\n", pos)
            if nl == -1:
                tail = text[pos:]
                stripped = tail.lstrip()
                if stripped and not self._skip_marker.startswith(stripped[:3]) \
                        and not stripped.startswith(self._skip_marker):
                    # This line already cannot be the closer; a single
                    # non-marker character preserves that fact in O(1)
                    # memory however long the line grows.
                    tail = "x"
                self._skip_tail = tail
                return ""
            if text[pos:nl].lstrip().startswith(self._skip_marker):
                self._skipping_fence = False
                self._skip_marker = ""
                self._skip_tail = ""
                self._starts_line = True
                return text[nl + 1:]
            pos = nl + 1
