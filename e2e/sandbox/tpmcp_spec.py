"""textual-pilot-mcp spec: the local QA sandbox's TUI at 160x50.

Start a sandbox first (`python -m e2e.sandbox up`); `launch` then runs the
app of the checkout that started it, in that sandbox. See tpmcp_host.py for
how, and CONTRIBUTING.md ("Local QA sandbox") for registering the server::

    textual-pilot-mcp validate --spec e2e/sandbox/tpmcp_spec.py
"""

import importlib.util
import sys
from pathlib import Path

_HOST = "_servonaut_qa_tpmcp_host"


def _load_host():
    path = Path(__file__).resolve().with_name("tpmcp_host.py")
    module_spec = importlib.util.spec_from_file_location(_HOST, path)
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[_HOST] = module
    module_spec.loader.exec_module(module)
    return module


spec = _load_host().make_spec((160, 50))
