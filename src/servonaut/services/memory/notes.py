"""A server's free-form notes (``annotations.md``): the template and what counts as notes.

Opening the notes for the first time seeds a short template: a title, a
primer comment and empty Purpose / Runbook / Ownership sections. Saved as it
is, that file holds no notes. :func:`has_notes` is the one place that tells
the two apart, so the Memory screen, the summary, the MCP tools and sync all
agree on whether a server has notes.
"""
from __future__ import annotations

import re

#: Section headings the template seeds. On their own they are not notes.
TEMPLATE_HEADINGS = ("## Purpose", "## Runbook", "## Ownership")

#: The template's first line starts with this (it then names the server).
_TITLE_PREFIX = "# Notes — "

_BLANK_RUN_RE = re.compile(r"\n{3,}")
# A fenced code block opens with three or more backticks or tildes.
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# An inline code span on one line: `code`, ``code with ` inside``.
_CODE_SPAN_RE = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)")
_BOM = "\ufeff"


def _one_line(value: str) -> str:
    """*value* as it may appear on the template's title line."""
    return " ".join(str(value).split())


def notes_template(name: str, instance_id: str, provider: str) -> str:
    """The seed content for a fresh ``annotations.md``.

    The comments say what belongs here (free-form notes) and what does not
    (machine-probed data, which is edited with Pin instead).
    """
    return (
        f"{_TITLE_PREFIX}{_one_line(name)} ({_one_line(instance_id)}) @ {_one_line(provider)}\n"
        "\n"
        "<!--\n"
        "Free-form notes about this server.  They appear in the memory\n"
        "summary alongside machine-probed data (OS, runtimes, services,\n"
        "logs), which is what the chat panel and MCP agents read.\n"
        "\n"
        "The read-only table you saw on the Memory screen is the probed\n"
        "data — edit observed values with 'p' (Pin) instead of writing\n"
        "them here.  Everything below this comment block is yours: use\n"
        "it for purpose / runbook notes / ownership / known quirks.\n"
        "\n"
        "Delete this comment block freely; it is only a one-shot primer.\n"
        "-->\n"
        "\n"
        f"{TEMPLATE_HEADINGS[0]}\n"
        "\n"
        '<!-- What does this server do? e.g. "primary billing API, '
        'reads from RDS, serves api.example.com" -->\n'
        "\n"
        f"{TEMPLATE_HEADINGS[1]}\n"
        "\n"
        "<!-- Deploy path, log locations, key commands, known quirks. -->\n"
        "\n"
        f"{TEMPLATE_HEADINGS[2]}\n"
        "\n"
        "<!-- Team, owner, Slack channel, escalation path. -->\n"
        "\n"
    )


def strip_comments(text: str) -> str:
    """*text* without HTML comments (the template's primer and hints).

    Only a comment that is closed counts, as in rendered Markdown; an opening
    ``<!--`` with no ``-->`` after it stays as text. Comments inside code
    (fenced blocks and inline code spans) are text too, so a runbook that
    shows ``<!--`` in a command keeps it. Runs of blank lines left behind
    collapse to one.
    """
    stripped = "".join(_strip_outside_fences((text or "").lstrip(_BOM)))
    return _BLANK_RUN_RE.sub("\n\n", stripped).strip()


def _strip_outside_fences(text: str):
    """Yield *text* in pieces, comments removed outside fenced code blocks."""
    prose: list = []
    fence = ""
    for line in text.splitlines(keepends=True):
        if fence:
            yield line
            if line.strip().startswith(fence):
                fence = ""
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            yield _strip_prose("".join(prose))
            prose = []
            fence = opening.group(1)
            yield line
            continue
        prose.append(line)
    yield _strip_prose("".join(prose))


def _strip_prose(text: str) -> str:
    """Remove closed comments from *text*, leaving inline code spans alone."""
    spans = [(m.start(), m.end()) for m in _CODE_SPAN_RE.finditer(text)]
    out, position = [], 0
    while True:
        start = text.find("<!--", position)
        if start < 0:
            break
        in_code = next((end for begin, end in spans if begin <= start < end), None)
        if in_code is not None:
            out.append(text[position:in_code])
            position = in_code
            continue
        end = text.find("-->", start + 4)
        if end < 0:
            break  # never closed: not a comment
        out.append(text[position:start])
        position = end + 3
    out.append(text[position:])
    return "".join(out)


def _is_template_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(_TITLE_PREFIX) or stripped in TEMPLATE_HEADINGS


def has_notes(text: str) -> bool:
    """Whether *text* holds notes someone wrote, not just the seeded template.

    Comments, the template's title and its empty section headings do not
    count; any other non-blank line does, headings included.
    """
    return any(
        line.strip() and not _is_template_line(line)
        for line in strip_comments(text).splitlines()
    )


def notes_for_display(text: str) -> str:
    """The notes as a reader should see them, or ``""`` when there are none.

    Comments go, and so do the template's title and any of its section
    headings left empty. Everything the user wrote stays as written.
    """
    if not has_notes(text):
        return ""
    lines = strip_comments(text).splitlines()
    kept = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(_TITLE_PREFIX):
            continue
        if stripped in TEMPLATE_HEADINGS and not _section_has_text(lines, index):
            continue
        kept.append(line.rstrip())
    return _BLANK_RUN_RE.sub("\n\n", "\n".join(kept)).strip()


def _section_has_text(lines: list, heading_index: int) -> bool:
    """Whether the section under the heading at *heading_index* has any text."""
    for line in lines[heading_index + 1:]:
        stripped = line.strip()
        if stripped.startswith("#"):
            return False
        if stripped:
            return True
    return False
