"""Remote scripts never act on text read from a file on the server.

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


def test_a_database_name_that_looks_like_an_option_stays_a_value(tmp_path) -> None:
    """The name read from a site's config reaches mysql as ``--database=<name>``."""
    from types import SimpleNamespace

    stub = tmp_path / "bin"
    stub.mkdir()
    client = stub / "mysql"
    client.write_text("#!/bin/sh\nfor a in \"$@\"; do printf '[%s]\\n' \"$a\"; done\n")
    client.chmod(0o755)
    profile = SimpleNamespace(
        host="127.0.0.1", port=3306, user="app", database="--init-command=touch marker", engine="mysql",
    )
    tools = ServonautTools.__new__(ServonautTools)
    command = tools._build_db_command(profile, "SELECT 1", "secret")
    done = subprocess.run(
        ["sh", "-c", command], env={"PATH": f"{stub}:/usr/bin:/bin"}, cwd=tmp_path,
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert "[--database=--init-command=touch marker]" in done.stdout
    assert "[--init-command=touch marker]" not in done.stdout
