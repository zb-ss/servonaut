"""The remote script of ``tls_cert_check`` never runs text read from a config file.

A certificate path comes from a web server configuration file, which is not
the operator's to trust. The script is run for real under ``sh`` against a
temporary tree (``/etc`` paths redirected, ``sudo -n`` replaced by ``env``).
"""
from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import MagicMock

import pytest

from servonaut.mcp.tools import ServonautTools

CONFIG_LINES = {
    "substitution": "ssl_certificate /x$(touch${IFS}%(marker)s);",
    "backticks": "ssl_certificate /x`touch${IFS}%(marker)s`;",
    "quote": 'ssl_certificate /x"$(touch${IFS}%(marker)s)";',
}


def _run_tool(tmp_path, line: str):
    (tmp_path / "nginx/sites-enabled").mkdir(parents=True)
    marker = tmp_path / "marker"
    (tmp_path / "nginx/sites-enabled/site.conf").write_text(
        "server {\n    " + (line % {"marker": marker}) + "\n}\n"
    )
    scripts = []

    async def fake_exec(instance, remote, timeout=60):
        scripts.append(remote)
        script = (
            remote.replace("/etc/nginx", str(tmp_path / "nginx"))
            .replace("/etc/apache2", str(tmp_path / "apache2"))
            .replace("/etc/httpd", str(tmp_path / "httpd"))
            .replace("/etc/letsencrypt", str(tmp_path / "le"))
            .replace("sudo -n ", "env ")
        )
        done = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30)
        return done.stdout, done.stderr

    async def lookup(*_args, **_kwargs):
        return {"id": "i-1", "name": "web-1"}, None

    tools = ServonautTools.__new__(ServonautTools)
    tools._guard = MagicMock()
    tools._guard.check_tool.return_value = (True, "OK")
    tools._audit = MagicMock()
    tools._lookup_instance = lookup
    tools._exec_ssh = fake_exec
    asyncio.run(tools.tls_cert_check("i-1"))
    return marker, scripts


@pytest.mark.parametrize("name", CONFIG_LINES)
def test_a_cert_path_naming_a_command_runs_nothing(tmp_path, name) -> None:
    marker, scripts = _run_tool(tmp_path, CONFIG_LINES[name])
    assert scripts, "the tool did not run its script"
    assert not marker.exists()


def test_the_script_has_no_second_shell() -> None:
    import inspect

    source = inspect.getsource(ServonautTools.tls_cert_check)
    # The only nested shell is the constant certbot glob, which names no variable.
    assert source.count("sh -c") == 1
