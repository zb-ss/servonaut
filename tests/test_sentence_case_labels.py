"""Buttons, bindings and navigation entries are written in sentence case.

Only the first word is capitalised; acronyms, product names and feature names
keep their capitals. A label that is a name on purpose goes in ``_ALLOWED``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "servonaut"

# Words that keep their capital wherever they appear.
_PROPER = frozenset({
    "AWS", "OVH", "Hetzner", "SSH", "SCP", "IP", "IPs", "DB", "AI", "MCP",
    "CloudWatch", "CloudTrail", "Bitwarden", "Servonaut", "S3", "EC2", "API",
    "TLS", "CA", "ID", "URL", "SFTP", "DNS", "WAF", "BW", "OVHcloud", "TUI",
    "CLI", "JSON", "VPS", "IAM", "Ollama", "Markdown", "Google", "GCP", "Azure",
    "Solo", "Docker",
})
# Names of products and features that are written with capitals on purpose.
_FEATURE_NAMES = ("Memory Sync", "Public Cloud", "Hetzner Cloud", "Google Cloud", "Solo plan")

# Labels that are two proper names, or keys written out.
_ALLOWED = frozenset({
    "Export to Markdown",
    "Use Recover instead",  # "Recover" is the name of the action
    "Set up Ollama",
    "Generate from Memory Sync",
    "Sign in to enable Memory Sync",
    "What is Memory Sync?",
    "Unlock Memory Sync",
    "Memory Sync",
    "Google Cloud",
    "GCP (Google Cloud)",
    "Available on Solo plan",
})

_CALLS = {
    "Binding": 2, "Button": 0, "ActionButton": 0, "LinkButton": 0, "_nav": 0,
    "SidebarSection": 0, "WorkspaceControls": 0, "add_column": 0,
}
_MANY = {"add_columns"}
_KEYWORDS = {"title", "action_label", "group", "heading"}


def _is_title_case(label: str) -> bool:
    text = re.sub(r"\[/?[^\]]*\]", "", label)
    for name in _FEATURE_NAMES:
        text = text.replace(name, "")
    words = text.split()
    start = next((i for i, w in enumerate(words) if re.search(r"[A-Za-z]", w)), len(words))
    for word in words[start + 1:]:
        core = re.sub(r"[^A-Za-z]", "", word)
        if len(core) < 2 or core in _PROPER or core.isupper():
            continue
        if core[0].isupper() and core[1:].islower():
            return True
    return False


def _strings(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    return []


def _labels() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "server_actions.py":
            continue
        rel = str(path.relative_to(SRC))
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {"TITLE", "SUB_TITLE"}:
                        found += [(rel, node.lineno, s) for s in _strings(node.value)]
            if rel == "app.py" and isinstance(node, ast.Tuple) and node.elts:
                # The command palette's navigation entries.
                found += [(rel, node.lineno, s) for s in _strings(node.elts[0])]
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            index = _CALLS.get(name)
            if index is not None and len(node.args) > index:
                found += [(rel, node.lineno, s) for s in _strings(node.args[index])]
            if name in _MANY:
                for arg in node.args:
                    found += [(rel, node.lineno, s) for s in _strings(arg)]
            for keyword in node.keywords:
                if keyword.arg in _KEYWORDS:
                    found += [(rel, node.lineno, s) for s in _strings(keyword.value)]
    return found


def test_no_button_binding_or_navigation_label_is_title_case() -> None:
    offenders = []
    for path, line, label in _labels():
        for part in label.split("\n"):
            if part.strip() and part not in _ALLOWED and _is_title_case(part):
                offenders.append(f"{path}:{line} {part!r}")
    assert not offenders, "Title Case labels:\n" + "\n".join(offenders)


@pytest.mark.parametrize("label", ["Select all", "Fleet memory", "Custom servers", "SSH keys", "Open docs"])
def test_the_check_accepts_sentence_case(label: str) -> None:
    assert not _is_title_case(label)


@pytest.mark.parametrize("label", ["Select All", "Fleet Memory", "Custom Servers", "Refresh All", "Open Docs", "Check For Update"])
def test_the_check_rejects_title_case(label: str) -> None:
    assert _is_title_case(label)
