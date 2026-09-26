"""Protocol and isolation tests for the private frozen-artifact smoke check."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import servonaut._artifact_selftest as selftest
import servonaut.main as main_mod


def _request(**overrides: object) -> bytes:
    value: dict[str, object] = {
        "schema_version": 1,
        "token": "test-token",
        "check": "tui",
    }
    value.update(overrides)
    return json.dumps(value).encode("utf-8")


def test_request_accepts_the_single_fixed_shape() -> None:
    request = selftest._read_request(io.BytesIO(_request()))

    assert request == selftest.SmokeRequest(token="test-token", check="tui")


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        _request(extra=True),
        _request(check="other"),
        _request(schema_version=True),
        _request(schema_version=2),
        _request(token=""),
        _request(token="\u4f60\u597d"),
        _request(token="a" * (selftest._MAX_TOKEN_BYTES + 1)),
        b'{"schema_version":1,"check":"tui"}',
        b"\xff",
        b'{"schema_version":1,"token":"a","token":"b","check":"tui"}',
        _request() + b" {}",
        b"[" * 10_000 + b"]" * 10_000,
    ],
)
def test_request_rejects_malformed_or_unbounded_input(payload: bytes) -> None:
    with pytest.raises(selftest._SelftestFailure, match="request-invalid"):
        selftest._read_request(io.BytesIO(payload))


def test_request_rejects_oversized_input() -> None:
    with pytest.raises(selftest._SelftestFailure, match="request-invalid"):
        selftest._read_request(io.BytesIO(b"x" * (selftest._MAX_STDIN_BYTES + 1)))


def test_authentication_is_ascii_and_does_not_echo_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "expected-token")
    selftest._authenticate(selftest.SmokeRequest("expected-token", "tui"))

    with pytest.raises(selftest._SelftestFailure, match="authentication-failed"):
        selftest._authenticate(selftest.SmokeRequest("wrong-token", "tui"))


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        _request(schema_version=2),
        b'{"schema_version":1,"check":"tui"}',
        _request(token="a" * (selftest._MAX_TOKEN_BYTES + 1)),
    ],
)
def test_invalid_request_never_starts_the_isolated_application(
    payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Input:
        buffer = io.BytesIO(payload)

    def fail_isolated_boot(_runtime: object) -> dict[str, object]:
        raise AssertionError("invalid requests must not start the isolated application")

    monkeypatch.setattr(selftest.sys, "stdin", _Input())
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "expected-token")
    monkeypatch.setattr(selftest, "_run_isolated_check", fail_isolated_boot)

    assert selftest.run_artifact_selftest(SimpleNamespace()) == 1


def test_missing_expected_token_never_starts_the_isolated_application(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Input:
        buffer = io.BytesIO(_request())

    def fail_isolated_boot(_runtime: object) -> dict[str, object]:
        raise AssertionError(
            "authentication failures must not start the isolated application"
        )

    monkeypatch.setattr(selftest.sys, "stdin", _Input())
    monkeypatch.delenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", raising=False)
    monkeypatch.setattr(selftest, "_run_isolated_check", fail_isolated_boot)

    assert selftest.run_artifact_selftest(SimpleNamespace()) == 1


def test_failure_result_is_bounded_and_does_not_echo_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Input:
        buffer = io.BytesIO(_request(token="secret-value"))

    output = io.StringIO()
    monkeypatch.setattr(selftest.sys, "stdin", _Input())
    monkeypatch.setattr(selftest.sys, "stdout", output)
    monkeypatch.setenv("SERVONAUT_ARTIFACT_SELFTEST_TOKEN", "other-value")

    assert selftest.run_artifact_selftest(SimpleNamespace()) == 1
    assert "secret-value" not in output.getvalue()
    assert "other-value" not in output.getvalue()
    assert json.loads(output.getvalue())["error"] == "authentication-failed"


def test_diagnostics_use_real_local_checks_without_external_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boto3
    import hcloud
    import keyring
    import requests

    attempts: list[str] = []

    def blocked(*_args: object, **_kwargs: object) -> object:
        attempts.append("external")
        raise AssertionError("diagnostics must not use external access")

    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    monkeypatch.setenv("OVH_ENDPOINT", "caller-canary")
    monkeypatch.setenv("OVH_APPLICATION_KEY", "caller-canary")
    monkeypatch.setenv("OVH_APPLICATION_SECRET", "caller-canary")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)
    monkeypatch.setattr(boto3.session.Session, "get_credentials", blocked)
    monkeypatch.setattr(hcloud.Client, "request", blocked)
    monkeypatch.setattr(keyring, "get_password", blocked)
    monkeypatch.setattr(keyring, "set_password", blocked)
    monkeypatch.setattr(keyring, "delete_password", blocked)
    monkeypatch.delitem(sys.modules, "ovh", raising=False)

    assert selftest._run_diagnostics() == {
        "metadata": True,
        "sdk": True,
        "crypto": True,
        "ca": True,
        "keyring": True,
    }
    assert attempts == []
    assert "ovh" not in sys.modules


def test_default_main_app_and_mcp_graph_avoids_ovh_and_external_inputs(
    tmp_path: Path,
) -> None:
    home = tmp_path / "caller-home"
    home.mkdir()
    canary = home / ".ovh.conf"
    canary.write_text("[default]\nendpoint=caller-canary\n", encoding="utf-8")
    source_root = Path(__file__).parents[2] / "src"
    script = """
import builtins
import os
from pathlib import Path
import socket
import sys

source_root = Path(sys.argv[1])
home = Path(sys.argv[2])
canary = home / ".ovh.conf"
canary_bytes = canary.read_bytes()

def blocked(*_args, **_kwargs):
    raise AssertionError("external access is forbidden")

original_open = builtins.open
def guarded_open(path, *args, **kwargs):
    if Path(path) == canary:
        raise AssertionError("OVH canary must not be read")
    return original_open(path, *args, **kwargs)

builtins.open = guarded_open
socket.socket.connect = blocked
socket.create_connection = blocked
sys.path.insert(0, str(source_root))

assert "ovh" not in sys.modules
import servonaut.main
assert "ovh" not in sys.modules
from servonaut.app import ServonautApp
app = ServonautApp()
app._init_services()
assert "ovh" not in sys.modules
from servonaut.mcp.server import create_mcp_server
assert create_mcp_server() is not None
assert "ovh" not in sys.modules
assert canary.read_bytes() == canary_bytes
print("graph-ok")
"""
    environment = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "TMPDIR": str(tmp_path),
        "TEMP": str(tmp_path),
        "TMP": str(tmp_path),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "AWS_EC2_METADATA_DISABLED": "true",
        "OVH_ENDPOINT": "caller-canary",
        "OVH_APPLICATION_KEY": "caller-canary",
        "OVH_APPLICATION_SECRET": "caller-canary",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT"):
            if os.environ.get(name):
                environment[name] = os.environ[name]

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(source_root), str(home)],
        capture_output=True,
        check=False,
        cwd=Path(__file__).parents[2],
        env=environment,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert completed.stdout == "graph-ok\n"
    assert completed.stderr == ""


def test_fixture_cache_uses_the_real_cache_service_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_root = tmp_path / ".servonaut"
    monkeypatch.setenv("HOME", str(tmp_path))
    config_path, cache_path, expected = selftest._create_fixtures(data_root)

    from servonaut.services.cache_service import CacheService

    monkeypatch.setattr(CacheService, "CACHE_PATH", cache_path)
    cache = CacheService(ttl_seconds=3600)
    assert cache.get_age() is not None
    assert cache.is_fresh() is True
    assert cache.load_any() == [selftest._FIXTURE_INSTANCE]
    assert selftest._verify_fixtures(config_path, cache_path, expected) == {
        "config": True,
        "cache": True,
    }


def test_windows_home_parts_reconstruct_the_owned_home() -> None:
    drive, home_path = selftest._windows_home_parts(Path("C:/scratch/selftest-home"))

    assert drive + home_path == r"C:\scratch\selftest-home"


def test_isolation_leaves_the_owned_home_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = Path.cwd()
    monkeypatch.setattr(selftest, "_temporary_parent", lambda: str(tmp_path))
    monkeypatch.setattr(
        selftest,
        "_isolated_environment",
        lambda home, inherited: {"HOME": str(home), "USERPROFILE": str(home)},
    )
    monkeypatch.setattr(selftest, "_require_owned_directory", lambda path: None)

    observed: dict[str, bool] = {}

    class _TemporaryDirectory:
        def __init__(self, **_kwargs: object) -> None:
            self.path = tmp_path / "owned-home"

        def __enter__(self) -> str:
            self.path.mkdir()
            return str(self.path)

        def __exit__(self, *_args: object) -> None:
            observed["left_home"] = Path.cwd() != self.path
            self.path.rmdir()

    monkeypatch.setattr(selftest.tempfile, "TemporaryDirectory", _TemporaryDirectory)

    with pytest.raises(selftest._SelftestFailure, match="runtime-invalid"):
        selftest._run_isolated_check(SimpleNamespace(product_version="fixture"))

    assert observed == {"left_home": True}
    assert Path.cwd() == previous


def test_isolation_rejects_ovh_imported_by_the_pilot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from servonaut.runtime import DistributionKind

    def detected_runtime() -> SimpleNamespace:
        home = Path(selftest.os.environ["HOME"])
        return SimpleNamespace(
            kind=DistributionKind.FROZEN_CLI,
            is_frozen=True,
            build_revision="build-1",
            data_root=home / ".servonaut",
            product_version="fixture",
        )

    def pilot_with_provider_import(*_args: object) -> dict[str, bool]:
        monkeypatch.setitem(selftest.sys.modules, "ovh", object())
        return {"main": True, "sidebar": True, "adjacent": True, "exited": True}

    monkeypatch.setattr("servonaut.runtime.detect_runtime", detected_runtime)
    monkeypatch.setattr(selftest, "_temporary_parent", lambda: str(tmp_path))
    monkeypatch.setattr(selftest, "_run_diagnostics", lambda: {"sdk": True})
    monkeypatch.setattr(selftest, "_run_tui_lifecycle", pilot_with_provider_import)

    with pytest.raises(selftest._SelftestFailure, match="diagnostic-sdk"):
        selftest._run_isolated_check(SimpleNamespace(product_version="fixture"))


def test_ovh_metadata_probe_has_a_finite_component_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_name: str) -> object:
        raise LookupError

    monkeypatch.setattr(selftest.importlib.metadata, "distribution", unavailable)

    with pytest.raises(selftest._SelftestFailure, match="diagnostic-sdk-ovh-metadata"):
        selftest._probe_ovh_metadata()


def test_ovh_metadata_probe_accepts_path_distribution_record_for_pyz_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata_directory = tmp_path / "ovh-1.2.0.dist-info"
    metadata_directory.mkdir()
    (metadata_directory / "RECORD").write_text(
        "ovh/client.py,sha256=fixture,1\n",
        encoding="utf-8",
    )
    distribution = selftest.importlib.metadata.PathDistribution(metadata_directory)

    assert not (tmp_path / "ovh" / "client.py").exists()
    assert distribution.read_text("RECORD") == "ovh/client.py,sha256=fixture,1\n"
    monkeypatch.setattr(
        selftest.importlib.metadata, "distribution", lambda _name: distribution
    )

    selftest._probe_ovh_metadata()


def test_hidden_dispatch_requires_marker_backed_frozen_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SimpleNamespace(kind=object(), is_frozen=False, build_revision=None)
    monkeypatch.setattr(main_mod.sys, "argv", ["servonaut", "--_artifact-selftest"])
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr(main_mod, "_prune_empty_env", lambda: None)

    with pytest.raises(SystemExit) as error:
        main_mod._main()

    assert error.value.code == 2


def test_hidden_dispatch_calls_only_the_frozen_marker_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from servonaut.runtime import DistributionKind

    def fail_prune() -> None:
        raise AssertionError("hidden dispatch must precede pruning")

    runtime = SimpleNamespace(
        kind=DistributionKind.FROZEN_CLI,
        is_frozen=True,
        build_revision="build-1",
    )
    monkeypatch.setattr(main_mod.sys, "argv", ["servonaut", "--_artifact-selftest"])
    monkeypatch.setattr("servonaut.runtime.detect_runtime", lambda: runtime)
    monkeypatch.setattr(
        "servonaut._artifact_selftest.run_artifact_selftest", lambda value: 0
    )
    monkeypatch.setattr(main_mod, "_prune_empty_env", fail_prune)

    with pytest.raises(SystemExit) as error:
        main_mod._main()

    assert error.value.code == 0


def test_hidden_dispatch_rejects_extra_arguments_without_private_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_private_dispatch(*_args: object) -> object:
        raise AssertionError("private dispatch must require the exact argv shape")

    monkeypatch.setattr(
        main_mod.sys,
        "argv",
        ["servonaut", "--_artifact-selftest", "extra"],
    )
    monkeypatch.setattr("servonaut.runtime.detect_runtime", fail_private_dispatch)
    monkeypatch.setattr(
        "servonaut._artifact_selftest.run_artifact_selftest", fail_private_dispatch
    )
    monkeypatch.setattr(main_mod, "_prune_empty_env", lambda: None)

    with pytest.raises(SystemExit) as error:
        main_mod._main()

    assert error.value.code == 2


def test_source_help_does_not_expose_the_private_switch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(main_mod.sys, "argv", ["servonaut", "--help"])
    monkeypatch.setattr(main_mod, "_prune_empty_env", lambda: None)

    with pytest.raises(SystemExit) as error:
        main_mod._main()

    assert error.value.code == 0
    assert "--_artifact-selftest" not in capsys.readouterr().out


def test_record_contains_ovh_client_accepts_backslash() -> None:
    record = "ovh\\client.py,sha256=fixture,1\n"
    assert selftest._record_contains_ovh_client(record)


def test_isolated_environment_sets_utf8_and_case_insensitive_windows_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inherited = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
    }
    monkeypatch.setattr(selftest.os, "name", "nt")
    monkeypatch.setattr(
        selftest,
        "_windows_home_parts",
        lambda _h: ("C:", r"\temp\scratch"),
    )
    env = selftest._isolated_environment(tmp_path, inherited)
    assert env["PYTHONUTF8"] == "1"
    assert env["PYTHONIOENCODING"] == "utf-8"
    assert env["SystemRoot"] == r"C:\Windows"
    assert env["WINDIR"] == r"C:\Windows"
    assert env["PATHEXT"] == ".COM;.EXE;.BAT;.CMD"
