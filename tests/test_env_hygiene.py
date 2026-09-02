"""Empty forwarded environment variables are dropped at process start.

Agent configs written by ``--mcp-install`` reference forwarded variables as
``${NAME:-}``, so a name that is unset when the agent starts reaches the MCP
server as ``NAME=""``. botocore treats ``AWS_PROFILE=""`` as a profile named
"" and fails every client with ``ProfileNotFound``; the readers for the
Servonaut URLs used to accept "" as an override too.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

import servonaut.main as main_mod
from servonaut.mcp import installer
from servonaut.mcp.installer import prune_empty_forwarded_env


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


def test_prune_drops_only_empty_forwarded_names(fake_home, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "")
    monkeypatch.setenv("SSH_AUTH_SOCK", "")
    monkeypatch.setenv("AWS_REGION", "eu-west-2")
    monkeypatch.setenv("UNRELATED_EMPTY", "")

    pruned = prune_empty_forwarded_env()

    assert pruned == ("SSH_AUTH_SOCK", "AWS_PROFILE")
    assert "AWS_PROFILE" not in os.environ
    assert "SSH_AUTH_SOCK" not in os.environ
    assert os.environ["AWS_REGION"] == "eu-west-2"
    assert os.environ["UNRELATED_EMPTY"] == ""


def test_prune_covers_names_referenced_from_the_config(fake_home, monkeypatch):
    cfg_dir = fake_home / ".servonaut"
    cfg_dir.mkdir()
    (cfg_dir / "config.json").write_text(json.dumps({"ai": {"gemini_api_key": "$MY_AI_TOKEN"}}))
    monkeypatch.setenv("MY_AI_TOKEN", "")

    pruned = prune_empty_forwarded_env()

    assert "MY_AI_TOKEN" in pruned
    assert "MY_AI_TOKEN" not in os.environ


def test_prune_is_idempotent_and_quiet_when_nothing_is_empty(fake_home, monkeypatch):
    for name in installer._BASE_FORWARD_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_PROFILE", "")

    assert prune_empty_forwarded_env() == ("AWS_PROFILE",)
    assert prune_empty_forwarded_env() == ()


def test_main_prunes_before_any_command_runs(fake_home, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "")
    monkeypatch.setattr(main_mod, "_PRUNED_ENV_NAMES", ())
    monkeypatch.setattr("sys.argv", ["servonaut", "--version"])

    with pytest.raises(SystemExit) as excinfo:
        main_mod._main()

    assert excinfo.value.code == 0
    assert "AWS_PROFILE" not in os.environ
    assert main_mod._PRUNED_ENV_NAMES == ("AWS_PROFILE",)


def test_setup_logging_reports_the_pruned_names(fake_home, monkeypatch):
    monkeypatch.setattr(main_mod, "_PRUNED_ENV_NAMES", ("AWS_PROFILE", "AWS_CONFIG_FILE"))
    root = logging.getLogger()
    previous = root.handlers[:]
    try:
        log_file = main_mod._setup_logging()
        for handler in root.handlers:
            handler.flush()
        text = log_file.read_text(encoding="utf-8")
    finally:
        for handler in root.handlers[:]:
            if handler not in previous:
                handler.close()
                root.removeHandler(handler)
        for handler in previous:
            if handler not in root.handlers:
                root.addHandler(handler)

    assert "Ignoring empty environment variables: AWS_PROFILE, AWS_CONFIG_FILE" in text


@pytest.mark.parametrize(
    "module_path, func, var, default_attr",
    [
        ("servonaut.services.api_client", "_api_base", "SERVONAUT_API_URL", "_DEFAULT_API_BASE"),
        ("servonaut.services.auth_service", "_api_base", "SERVONAUT_API_URL", "_DEFAULT_API_BASE"),
        ("servonaut.mcp.remote_client", "_mcp_base", "SERVONAUT_MCP_URL", "_DEFAULT_MCP_BASE"),
    ],
)
def test_empty_url_override_falls_back_to_the_default(monkeypatch, module_path, func, var, default_attr):
    import importlib

    module = importlib.import_module(module_path)
    monkeypatch.setenv(var, "")
    assert getattr(module, func)() == getattr(module, default_attr)

    monkeypatch.setenv(var, "https://staging.example.com")
    assert getattr(module, func)() == "https://staging.example.com"


def test_installer_env_block_with_nothing_set_is_safe_for_botocore_once_pruned(fake_home, monkeypatch):
    """Cross-seam check: the installer's output meets its consumer.

    Render the env block ``--mcp-install claude`` writes, expand it the way
    the agent does when none of the variables is set (``${NAME:-}`` → ""),
    and put it in front of the AWS SDK. The installer tests only ever
    asserted the JSON shape; nothing ran the SDK under that JSON.
    """
    import botocore.session
    from botocore.exceptions import ProfileNotFound

    block = installer._env_references("claude")
    assert "AWS_PROFILE" in block
    for name, reference in block.items():
        assert reference == f"${{{name}:-}}"
        monkeypatch.setenv(name, "")

    with pytest.raises(ProfileNotFound):
        botocore.session.get_session().get_scoped_config()

    prune_empty_forwarded_env()

    botocore.session.get_session().get_scoped_config()  # no raise
    assert "AWS_PROFILE" not in os.environ
