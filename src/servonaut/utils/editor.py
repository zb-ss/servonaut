"""The user's text editor, from ``$VISUAL`` / ``$EDITOR``."""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import List


def editor_argv(path: Path) -> List[str]:
    """Build the editor argv for *path* from ``$VISUAL`` / ``$EDITOR`` (default ``vi``).

    The variables may include flags (e.g. "emacsclient -c -a emacs" or
    "code --wait"), so they are split with shlex rather than passed as one
    program name, which subprocess would fail to find.
    """
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    try:
        argv = shlex.split(editor)
    except ValueError:
        argv = [editor]
    if not argv:
        argv = ["vi"]
    argv.append(str(path))
    return argv
