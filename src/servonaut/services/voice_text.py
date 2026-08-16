"""Turn assistant reply text into something worth reading aloud.

Assistant replies are written for a screen: markdown emphasis, fenced
code, tables, raw URLs and tool-status chatter all make sense rendered,
and all of them are noise (or worse, minutes of noise) when synthesised.
:func:`speakable_text` reduces a reply to its prose.

Deliberately a pure function with no optional dependencies and no I/O:
it must be importable — and unit-testable — on an install that has no
audio stack at all, and its output must be a deterministic function of
its input so tests can pin exact expectations.
"""

from __future__ import annotations

import re

# Spoken stand-ins for content that is meaningless read aloud. Full
# sentences on purpose — a bare "omitted" mid-stream sounds like an error.
CODE_BLOCK_PLACEHOLDER = "Code block shown on screen."
TABLE_PLACEHOLDER = "Table shown on screen."

# Lines that are tool-execution chatter rather than the reply itself.
# Matched per line so one status row never suppresses surrounding prose.
_TOOL_NOISE_PATTERNS = (
    re.compile(r"^\s*tool result\b", re.IGNORECASE),
    re.compile(r"^\s*(?:running|calling|executing|used)\s+tool\b", re.IGNORECASE),
    re.compile(r"^\s*\[tool[\s:\]]", re.IGNORECASE),
    re.compile(r"^\s*[⏺⚙🔧▸⌛✻]"),
)

# Markdown link or image: keep the human text, drop the target.
_MD_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")

# Bare URL: collapse to its host. Reading a path and query string aloud
# helps nobody; the host at least says where the link points. The tail
# must end on a non-punctuation character so sentence punctuation after
# the URL survives ("see example.com." keeps its full stop).
_BARE_URL = re.compile(
    r"\bhttps?://(?:[^@/\s]+@)?([\w.-]+)(?::\d+)?"
    r"(?:[^\s<>\[\]()\"']*[^\s<>\[\]()\"'.,;:!?])?"
)

# Inline emphasis and code spans: strip the syntax, keep the content.
_BOLD = re.compile(r"(\*\*|__)(.+?)\1")
_EMPHASIS = re.compile(r"(?<![\w*_])([*_])([^*_\n]+?)\1(?![\w*_])")
_STRIKETHROUGH = re.compile(r"~~(.+?)~~")
_INLINE_CODE = re.compile(r"`([^`\n]*)`")

# Structural line prefixes: headings, blockquotes, bullets.
_HEADING_PREFIX = re.compile(r"^\s{0,3}#{1,6}\s+")
_BLOCKQUOTE_PREFIX = re.compile(r"^\s{0,3}(?:>\s?)+")
_BULLET_PREFIX = re.compile(r"^\s*[-*+]\s+")

# A horizontal rule is purely visual.
_HORIZONTAL_RULE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")

# A table separator row: only pipes, dashes, colons and spaces, with at
# least one of each of the characters that make it a separator. Its
# presence is what distinguishes a markdown table from prose that happens
# to contain a pipe.
_TABLE_SEPARATOR = re.compile(r"^\s*\|?[\s:|-]*-{3,}[\s:|-]*\|?\s*$")


def speakable_text(text: str) -> str:
    """Reduce markdown-ish reply text to prose fit for speech synthesis.

    Fenced code blocks and tables become short spoken placeholders,
    URLs collapse to their host, markdown syntax is stripped (content
    kept), tool-status chatter is dropped, and whitespace is normalised.

    Args:
        text: Raw reply text, possibly containing markdown.

    Returns:
        Prose with one line per spoken chunk, or an empty string when
        nothing speakable remains.
    """
    if not text or not text.strip():
        return ""

    lines = _replace_fenced_code(text.splitlines())
    lines = _replace_tables(lines)

    spoken: list = []
    for line in lines:
        if line in (CODE_BLOCK_PLACEHOLDER, TABLE_PLACEHOLDER):
            spoken.append(line)
            continue
        if _HORIZONTAL_RULE.match(line):
            continue
        if any(pattern.match(line) for pattern in _TOOL_NOISE_PATTERNS):
            continue
        cleaned = _clean_line(line)
        if cleaned:
            spoken.append(cleaned)

    return "\n".join(spoken)


def _replace_fenced_code(lines: list) -> list:
    """Collapse every fenced code block into one placeholder line.

    An unterminated fence swallows the rest of the text — the reply was
    cut off mid-block, and reading half a code listing aloud is the exact
    failure this module exists to prevent.
    """
    result: list = []
    in_fence = False
    fence = ""
    for line in lines:
        stripped = line.lstrip()
        if not in_fence and (stripped.startswith("```") or stripped.startswith("~~~")):
            in_fence = True
            fence = stripped[:3]
            result.append(CODE_BLOCK_PLACEHOLDER)
            continue
        if in_fence:
            if stripped.startswith(fence):
                in_fence = False
            continue
        result.append(line)
    return result


def _replace_tables(lines: list) -> list:
    """Collapse each markdown table into one placeholder line.

    A table is a run of consecutive pipe-bearing lines containing a
    separator row. Runs without a separator are left alone: prose with a
    pipe in it is still prose.
    """
    result: list = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if "|" not in line or not line.strip():
            result.append(line)
            index += 1
            continue

        run_end = index
        while run_end < len(lines) and "|" in lines[run_end] and lines[run_end].strip():
            run_end += 1
        run = lines[index:run_end]

        if len(run) >= 2 and any(_TABLE_SEPARATOR.match(row) for row in run):
            result.append(TABLE_PLACEHOLDER)
        else:
            result.extend(run)
        index = run_end
    return result


def _clean_line(line: str) -> str:
    """Strip markdown syntax and collapse whitespace on one prose line."""
    line = _HEADING_PREFIX.sub("", line)
    line = _BLOCKQUOTE_PREFIX.sub("", line)
    line = _BULLET_PREFIX.sub("", line)
    line = _MD_LINK.sub(r"\1", line)
    line = _BARE_URL.sub(r"\1", line)
    # Bold before emphasis: ** is two emphasis markers to a regex that
    # runs first, which would leave stray asterisks behind.
    line = _BOLD.sub(r"\2", line)
    line = _EMPHASIS.sub(r"\2", line)
    line = _STRIKETHROUGH.sub(r"\1", line)
    line = _INLINE_CODE.sub(r"\1", line)
    return " ".join(line.split())
