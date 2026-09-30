"""textual-pilot-mcp spec: the local QA sandbox's TUI at 160x50.

Start a sandbox first (`python -m e2e.sandbox up`); `launch` then runs the
app of the checkout that started it, in that sandbox. See tpmcp_host.py for
how, and CONTRIBUTING.md ("Local QA sandbox") for registering the server::

    textual-pilot-mcp validate --spec e2e/sandbox/tpmcp_spec.py

textual-pilot-mcp imports this file as ``e2e.sandbox.tpmcp_spec``; the host
beside it loads nothing from Servonaut until ``launch``.
"""

import importlib
import sys

_RELOADING = "e2e.sandbox.tpmcp_host" in sys.modules

from e2e.sandbox import tpmcp_host  # noqa: E402

if _RELOADING:  # the server's `reload` picks up changes to the host too
    tpmcp_host = importlib.reload(tpmcp_host)

spec = tpmcp_host.make_spec((160, 50))
