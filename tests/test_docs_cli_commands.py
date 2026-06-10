"""Doc-lint guard: every CLI command the docs advertise must actually parse.

Extracts ``servonaut <subcommand> [<subcommand>]`` mentions from fenced code
blocks and inline code spans in README.md and docs/*.md, then runs each
through the real argparse tree (``<cmd> --help`` in a subprocess). A doc
mentioning a subcommand that doesn't exist fails CI instead of becoming a
user-trust incident. Only command-position mentions count — ``pipx inject
servonaut httpx`` doesn't start with ``servonaut`` and is ignored.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = str(REPO_ROOT / "src")

# A subcommand token: lowercase word, hyphens allowed. Flags (`--bg`),
# placeholders (`<agent>`), pipes and shell syntax all terminate the match.
_TOKEN = r"[a-z][a-z0-9-]*"
# `servonaut` in command position followed by 1-2 subcommand tokens.
_CMD_RE = re.compile(rf"^servonaut\s+({_TOKEN})(?:\s+({_TOKEN}))?")

_FENCE_RE = re.compile(r"^(```|~~~)")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")


def _candidates_from_text(text: str) -> set[tuple[str, ...]]:
    found: set[tuple[str, ...]] = set()
    in_fence = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        snippets = [line.lstrip("$ ")] if in_fence else _INLINE_CODE_RE.findall(line)
        for snippet in snippets:
            m = _CMD_RE.match(snippet.strip())
            if m:
                found.add(tuple(t for t in m.groups() if t))
    return found


def _collect_candidates() -> set[tuple[str, ...]]:
    docs = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]
    candidates: set[tuple[str, ...]] = set()
    for doc in docs:
        candidates |= _candidates_from_text(doc.read_text(encoding="utf-8"))
    return candidates


# Runs in a subprocess: tries `servonaut <words> --help` for every candidate
# against the real parser. --help exits 0 on a valid (sub)command path and
# argparse errors with code 2 on an unknown one.
_RUNNER = """
import contextlib, io, json, sys
failures = []
for words in json.loads(sys.argv[1]):
    sys.argv = ["servonaut", *words, "--help"]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            from servonaut.main import main
            main()
        failures.append([words, "returned without exiting"])
    except SystemExit as e:
        if e.code not in (0, None):
            failures.append([words, buf.getvalue()[-300:]])
print("RESULT:" + json.dumps(failures))
"""


def test_documented_cli_commands_exist():
    candidates = sorted(_collect_candidates())
    assert candidates, "extractor found no CLI commands in the docs — regex broken?"

    result = subprocess.run(
        [sys.executable, "-c", _RUNNER, json.dumps(candidates)],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": SRC_DIR, "PATH": ""},
        timeout=120,
    )
    assert result.returncode == 0, f"runner crashed:\n{result.stdout}\n{result.stderr}"
    marker = [l for l in result.stdout.splitlines() if l.startswith("RESULT:")]
    assert marker, f"runner produced no result line:\n{result.stdout}"
    failures = json.loads(marker[0][len("RESULT:"):])
    assert not failures, (
        "docs mention CLI commands that don't parse "
        "(fix the doc or register the command):\n"
        + "\n".join(f"  servonaut {' '.join(w)} — {err.strip()}" for w, err in failures)
    )
