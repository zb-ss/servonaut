"""The local QA sandbox's directories never reach git or a source package.

A sandbox root (``python -m e2e.sandbox up``), and one kept with ``--keep``
and renamed aside, hold private keys, tokens and the sandbox's whole child
environment. Source packages are built from what git does not ignore.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    "path",
    [
        ".qa-sandbox/state.json",
        ".qa-sandbox.kept-20260101-000000-4242/state.json",
        ".qa-sandbox.kept-20260101-000000-4242/ssh/client/client_ed25519",
    ],
)
def test_qa_sandbox_directories_are_ignored(path: str) -> None:
    git = shutil.which("git")
    if git is None or not (REPO / ".git").exists():
        pytest.skip("needs a git checkout")
    ignored = subprocess.run([git, "check-ignore", "-q", path], cwd=REPO, check=False)
    assert ignored.returncode == 0, f"{path} is not ignored by git"
