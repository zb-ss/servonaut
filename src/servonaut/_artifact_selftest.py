"""Authenticated, frozen-artifact-only local smoke proof.

This module deliberately imports only the standard library at module load time.
The dispatcher validates the frozen runtime before importing it; after request
authentication this module replaces the process environment before importing
application code or optional SDKs.
"""

from __future__ import annotations

import asyncio
import csv
import gc
import hashlib
import importlib.metadata
import json
import os
import secrets
import shutil
import ssl
import stat
import sys
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import BinaryIO, TextIO

_MAX_STDIN_BYTES = 4096
_MAX_TOKEN_BYTES = 512
_REQUEST_KEYS = frozenset({"schema_version", "token", "check"})
_TUI_CHECKS = frozenset({"tui"})
_RESULT_SCHEMA_VERSION = 1
_FIXTURE_INSTANCE = {
    "id": "i-artifact-smoke",
    "name": "artifact-smoke",
    "type": "t3.micro",
    "state": "stopped",
    "public_ip": "",
    "private_ip": "",
    "region": "us-east-1",
    "key_name": "",
    "provider": "aws",
}
_DISTRIBUTIONS = (
    "mcp",
    "ovh",
    "hcloud",
    "boto3",
    "botocore",
    "cryptography",
    "PyNaCl",
    "bcrypt",
    "keyring",
    "certifi",
)


class _SelftestFailure(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SmokeRequest:
    token: str
    check: str


def run_artifact_selftest(runtime: object) -> int:
    """Run the one fixed authenticated check and write a bounded JSON result."""
    try:
        request = _read_request(sys.stdin.buffer)
        _authenticate(request)
        result = _run_isolated_check(runtime)
    except _SelftestFailure as error:
        _write_result({"schema_version": _RESULT_SCHEMA_VERSION, "ok": False, "error": error.code})
        return 1
    except Exception:
        _write_result({"schema_version": _RESULT_SCHEMA_VERSION, "ok": False, "error": "selftest-failed"})
        return 1
    _write_result(result)
    return 0


def _read_request(
    stream: BinaryIO, checks: frozenset[str] = _TUI_CHECKS
) -> SmokeRequest:
    raw = stream.read(_MAX_STDIN_BYTES + 1)
    if len(raw) > _MAX_STDIN_BYTES:
        raise _SelftestFailure("request-invalid")
    try:
        text = raw.decode("utf-8")
        payload = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise _SelftestFailure("request-invalid") from None
    if not isinstance(payload, dict) or frozenset(payload) != _REQUEST_KEYS:
        raise _SelftestFailure("request-invalid")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise _SelftestFailure("request-invalid")
    token = payload.get("token")
    check = payload.get("check")
    if (
        not isinstance(token, str)
        or not token
        or not token.isascii()
        or len(token.encode("ascii")) > _MAX_TOKEN_BYTES
        or not isinstance(check, str)
        or check not in checks
    ):
        raise _SelftestFailure("request-invalid")
    return SmokeRequest(token=token, check=check)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _authenticate(request: SmokeRequest) -> None:
    expected = os.environ.get("SERVONAUT_ARTIFACT_SELFTEST_TOKEN")
    if (
        not isinstance(expected, str)
        or not expected
        or not expected.isascii()
        or len(expected.encode("ascii")) > _MAX_TOKEN_BYTES
        or not secrets.compare_digest(request.token, expected)
    ):
        raise _SelftestFailure("authentication-failed")


def _run_isolated_check(initial_runtime: object) -> dict[str, object]:
    try:
        with isolated_home() as home:
            from servonaut.runtime import DistributionKind, detect_runtime

            runtime = detect_runtime()
            if (
                runtime.kind is not DistributionKind.FROZEN_CLI
                or not runtime.is_frozen
                or runtime.build_revision is None
                or runtime.data_root != home / ".servonaut"
                or runtime.product_version != getattr(initial_runtime, "product_version", None)
            ):
                raise _SelftestFailure("runtime-invalid")
            config_path, cache_path, expected = _create_fixtures(runtime.data_root)
            diagnostics = _run_diagnostics()
            tui = _run_tui_lifecycle(runtime, config_path)
            if "ovh" in sys.modules:
                raise _SelftestFailure("diagnostic-sdk")
            preserved = _verify_fixtures(config_path, cache_path, expected)
            if not all(preserved.values()):
                raise _SelftestFailure("fixture-modified")
            return {
                "schema_version": _RESULT_SCHEMA_VERSION,
                "ok": True,
                "check": "tui",
                "runtime": {"kind": "frozen-cli", "marker": True},
                "tui": tui,
                "fixtures": preserved,
                "diagnostics": diagnostics,
            }
    except _SelftestFailure:
        raise
    except Exception:
        raise _SelftestFailure("isolation-failed") from None


@contextmanager
def isolated_home() -> Iterator[Path]:
    """Run the enclosed block in a fresh private home, working directory and environment.

    The process environment is replaced before any application code runs, so
    no caller credentials, configuration or caches reach the checked build.
    Everything is restored and the home is emptied on the way out.
    """
    previous_environment = dict(os.environ)
    previous_cwd = Path.cwd()
    try:
        parent = _temporary_parent()
        with tempfile.TemporaryDirectory(prefix="servonaut-artifact-selftest-", dir=parent) as value:
            home = Path(value)
            try:
                _require_owned_directory(home)
                os.environ.clear()
                os.environ.update(_isolated_environment(home, previous_environment))
                os.chdir(home)
                _require_owned_directory(home)
                yield home
            finally:
                os.chdir(previous_cwd)
                _clean_directory_contents(home)
    finally:
        os.environ.clear()
        os.environ.update(previous_environment)
        os.chdir(previous_cwd)


def _clean_directory_contents(root: Path) -> None:
    gc.collect()
    for _ in range(5):
        _ensure_tree_writable(root)
        try:
            for entry in list(root.iterdir()):
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    try:
                        entry.unlink()
                    except OSError:
                        pass
        except OSError:
            pass
        try:
            if not any(root.iterdir()):
                return
        except OSError:
            pass
        gc.collect()
        time.sleep(0.05)


def _ensure_tree_writable(root: Path) -> None:
    try:
        for current, dirs, files in os.walk(root):
            for name in files:
                try:
                    os.chmod(os.path.join(current, name), stat.S_IWRITE)
                except OSError:
                    pass
            for name in dirs:
                try:
                    os.chmod(os.path.join(current, name), stat.S_IWRITE)
                except OSError:
                    pass
    except OSError:
        pass


def _temporary_parent() -> str | None:
    value = os.environ.get("TMPDIR")
    if not value:
        return None
    parent = Path(value)
    if parent.is_symlink() or not parent.is_dir():
        raise _SelftestFailure("isolation-failed")
    return str(parent)


def _lookup_env(mapping: Mapping[str, str], target: str) -> str | None:
    if target in mapping:
        return mapping[target]
    target_lower = target.lower()
    for key, value in mapping.items():
        if key.lower() == target_lower:
            return value
    return None


def _isolated_environment(home: Path, inherited: dict[str, str]) -> dict[str, str]:
    temp = home / "tmp"
    for directory in (temp, home / ".config", home / ".cache", home / ".local" / "share"):
        directory.mkdir(parents=True, exist_ok=False)
    environment = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PATH": "",
        "TMPDIR": str(temp),
        "TEMP": str(temp),
        "TMP": str(temp),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": str(home / ".aws" / "config"),
        "AWS_SHARED_CREDENTIALS_FILE": str(home / ".aws" / "credentials"),
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM"):
        if inherited.get(name):
            environment[name] = inherited[name]
    if os.name == "nt":
        drive, home_path = _windows_home_parts(home)
        environment["HOMEDRIVE"] = drive
        environment["HOMEPATH"] = home_path
        for name in ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT"):
            value = _lookup_env(inherited, name)
            if value:
                environment[name] = value
    return environment


def _windows_home_parts(home: Path) -> tuple[str, str]:
    """Return Windows home variables that reconstruct ``home`` exactly."""
    path = PureWindowsPath(str(home))
    if not path.drive or not path.root:
        raise _SelftestFailure("isolation-failed")
    relative = path.relative_to(path.anchor)
    return path.drive, "\\" + str(relative)


def _require_owned_directory(path: Path) -> None:
    try:
        status = path.lstat()
    except OSError:
        raise _SelftestFailure("isolation-failed") from None
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise _SelftestFailure("isolation-failed")


def _create_fixtures(data_root: Path) -> tuple[Path, Path, dict[Path, str]]:
    if data_root.exists() or data_root.is_symlink():
        raise _SelftestFailure("fixture-failed")
    try:
        data_root.mkdir(mode=0o700)
    except OSError:
        raise _SelftestFailure("fixture-failed") from None
    _require_owned_directory(data_root)

    from servonaut.config.schema import AppConfig
    from servonaut.services.auth_service import _api_base
    from servonaut.services.relay_manager import derive_relay_urls

    config = asdict(AppConfig())
    if config["ovh"]["enabled"] or config["hetzner"]["enabled"]:
        raise _SelftestFailure("fixture-failed")
    # The real app persists derived relay URLs when either is absent. Seed the
    # same local effective configuration up front so this preservation proof
    # does not accept an application rewrite during an otherwise read-only run.
    relay_base, relay_mercure = derive_relay_urls(_api_base())
    config["relay"]["base_url"] = relay_base
    config["relay"]["mercure_url"] = relay_mercure
    config_path = data_root / "config.json"
    cache_path = data_root / "cache.json"
    # CacheService currently stores and compares naive local ISO timestamps.
    # Match its public save format so the real initial screen can consume this
    # fresh isolated fixture without scheduling a provider fetch.
    cache = {"timestamp": datetime.now().isoformat(), "instances": [_FIXTURE_INSTANCE]}
    _write_exclusive_json(config_path, config)
    _write_exclusive_json(cache_path, cache)
    return config_path, cache_path, {config_path: _sha256(config_path), cache_path: _sha256(cache_path)}


def _write_exclusive_json(path: Path, value: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")))
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise _SelftestFailure("fixture-failed") from None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_fixtures(config_path: Path, cache_path: Path, expected: dict[Path, str]) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for label, path in (("config", config_path), ("cache", cache_path)):
        try:
            status = path.lstat()
            regular = stat.S_ISREG(status.st_mode) and not stat.S_ISLNK(status.st_mode)
            result[label] = regular and _sha256(path) == expected[path]
        except OSError:
            result[label] = False
    return result


async def _run_tui(runtime: object, config_path: Path) -> dict[str, bool]:
    from servonaut.app import ServonautApp
    from servonaut.screens.instance_list import InstanceListScreen
    from servonaut.screens.settings.base import SettingsPanel
    from servonaut.screens.settings import SettingsScreen
    from servonaut.widgets.sidebar import Sidebar
    from textual.widgets import Button, Input

    app = ServonautApp(config_path=config_path, runtime_layout=runtime)
    result = {"main": False, "sidebar": False, "adjacent": False, "exited": False}
    async with app.run_test(size=(200, 80)) as pilot:
        await pilot.pause()
        if not isinstance(app.screen, InstanceListScreen):
            raise _SelftestFailure("tui-main")
        result["main"] = True
        sidebar = app.screen.query_one(Sidebar)
        if sidebar is None:
            raise _SelftestFailure("tui-sidebar")
        result["sidebar"] = True
        from servonaut.widgets.sidebar_section import SidebarSection

        tools = sidebar.query_one("#section_tools", SidebarSection)
        await pilot.click(tools.query_one("Button.section-header", Button))
        await pilot.pause()
        await pilot.click(sidebar.query_one("#nav_settings", Button))
        await pilot.pause()
        if not isinstance(app.screen, SettingsScreen):
            raise _SelftestFailure("tui-settings")
        try:
            general = app.screen.query_one("#panel_general", SettingsPanel)
            general.query_one("#general_username", Input)
        except Exception:
            # A settings shell can exist while every panel silently fell back
            # to an unavailable placeholder. Require a mounted real control.
            raise _SelftestFailure("tui-settings") from None
        sidebar = app.screen.query_one(Sidebar)
        core = sidebar.query_one("#section_core", SidebarSection)
        await pilot.click(core.query_one("Button.section-header", Button))
        await pilot.pause()
        await pilot.click(sidebar.query_one("#nav_list", Button))
        await pilot.pause()
        if not isinstance(app.screen, InstanceListScreen):
            raise _SelftestFailure("tui-instances")
        result["adjacent"] = True
        app.exit()
        await pilot.pause()
    result["exited"] = True
    return result


def _run_tui_lifecycle(runtime: object, config_path: Path) -> dict[str, bool]:
    """Run the real pilot and explicitly drain Textual's closed-loop timers."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(_run_tui(runtime, config_path))
    finally:
        pending = tuple(asyncio.all_tasks(loop))
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


def _run_diagnostics() -> dict[str, bool]:
    _require_metadata()
    _probe_sdks()
    _probe_crypto()
    _probe_ca_bundle()
    _probe_keyring()
    return {"metadata": True, "sdk": True, "crypto": True, "ca": True, "keyring": True}


def _require_metadata() -> None:
    try:
        for name in _DISTRIBUTIONS:
            if not isinstance(importlib.metadata.version(name), str) or not importlib.metadata.version(name):
                raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-metadata") from None


def _probe_sdks() -> None:
    if "ovh" in sys.modules:
        raise _SelftestFailure("diagnostic-sdk")
    _probe_mcp_sdk()
    _probe_ovh_metadata()
    _probe_hcloud_sdk()
    _probe_botocore_sdk()
    if "ovh" in sys.modules:
        raise _SelftestFailure("diagnostic-sdk")


def _probe_mcp_sdk() -> None:
    try:
        from mcp.server import Server

        if Server("artifact-selftest").create_initialization_options() is None:
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-sdk-mcp") from None


def _probe_ovh_metadata() -> None:
    try:
        record = importlib.metadata.distribution("ovh").read_text("RECORD")
        if not _record_contains_ovh_client(record):
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-sdk-ovh-metadata") from None


def _record_contains_ovh_client(record: str | None) -> bool:
    if not isinstance(record, str) or len(record.encode("utf-8")) > _MAX_STDIN_BYTES:
        return False
    try:
        rows = csv.reader(record.splitlines(), strict=True)
        return any(
            len(row) == 3 and row[0].replace("\\", "/") == "ovh/client.py"
            for row in rows
        )
    except csv.Error:
        return False


def _probe_hcloud_sdk() -> None:
    try:
        from hcloud import Client

        if not isinstance(Client(token="artifact-neutral-token"), Client):
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-sdk-hcloud") from None


def _probe_botocore_sdk() -> None:
    try:
        from botocore.loaders import create_loader

        model = create_loader().load_service_model("sts", "service-2")
        if not isinstance(model, dict) or not model.get("metadata"):
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-sdk-botocore") from None


def _probe_crypto() -> None:
    try:
        import bcrypt
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from nacl.public import PrivateKey, SealedBox

        plain = b"artifact-selftest"
        key = AESGCM.generate_key(bit_length=128)
        nonce = b"artifact-smk"
        if AESGCM(key).decrypt(nonce, AESGCM(key).encrypt(nonce, plain, None), None) != plain:
            raise ValueError
        private = PrivateKey.generate()
        if SealedBox(private).decrypt(SealedBox(private.public_key).encrypt(plain)) != plain:
            raise ValueError
        password_hash = bcrypt.hashpw(b"fixture", bcrypt.gensalt(rounds=4))
        if not bcrypt.checkpw(b"fixture", password_hash) or bcrypt.checkpw(b"wrong", password_hash):
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-crypto") from None


def _probe_ca_bundle() -> None:
    try:
        import certifi

        bundle = Path(certifi.where())
        context = ssl.create_default_context(cafile=str(bundle))
        if not bundle.is_file() or bundle.stat().st_size == 0 or not context.check_hostname:
            raise ValueError
        if context.verify_mode != ssl.CERT_REQUIRED or not context.get_ca_certs():
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-ca") from None


def _probe_keyring() -> None:
    try:
        import keyring

        backend = keyring.get_keyring()
        if backend.__class__.__module__ != "keyring.backends.null":
            raise ValueError
    except Exception:
        raise _SelftestFailure("diagnostic-keyring") from None


def _write_result(result: dict[str, object], stream: TextIO | None = None) -> None:
    target = sys.stdout if stream is None else stream
    target.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    target.flush()
