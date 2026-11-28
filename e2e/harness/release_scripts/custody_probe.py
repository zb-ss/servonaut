"""Exercise an installed release's Memory Sync and config sync code against the fake service.

Run with the Python of an install, not imported by the suite::

    <venv>/bin/python custody_probe.py <operation> <spec.json>

Each run performs ONE operation with the release's own classes and prints one
JSON document on stdout: ``{"operation", "version", "outcome", ...}``. The
outcome is ``ok`` or ``error``; an error carries the exception's type name and
a one-line message (never a secret: the only passphrase involved is the fixed
neutral one in the spec). A crash of this process (no JSON, a non-zero exit)
is what the journey reports as an unclean failure. Operations:

``login``            write ``auth.json`` with the release's ``AuthToken``;
``write_keys_json``  write the local passphrase-wrapped key cache as the
                     release would have, from the key in the spec;
``bootstrap``        ``MemorySyncService.bootstrap`` with a provider that
                     returns the passphrase; on success, upload one module
                     and report what the service answered;
``rotate``           ``MemorySyncService.rotate_keypair``;
``retrieval``        ``MemoryRetrievalService.get_module``;
``config_pull`` / ``config_push``  ``ConfigSyncService.pull`` / ``push``;
``summary``          consent, then ``AISummaryService.dispatch_summary`` with
                     the passphrase form;
``tui``              the release's real app under Textual's test driver
                     (``SERVONAUT_MEMORY_PASSPHRASE`` set by the journey): open
                     Memory Sync, press the set-up button, report the toasts;
``local_state``      which key files the home holds.

Standard library and the installed ``servonaut`` only. It sits in a directory
of its own because Python puts the script's directory first on ``sys.path``.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import inspect
import json
import os
import sys
import time
from importlib.metadata import version as installed_version
from pathlib import Path
from typing import Any, Awaitable, Callable

INSTANCE = {"id": "web-1", "name": "web-1", "provider": "custom"}


def _home() -> Path:
    return Path.home() / ".servonaut"


def _describe(exc: BaseException) -> dict[str, Any]:
    line = (str(exc).strip().splitlines() or [""])[0][:200]
    return {"outcome": "error", "error_type": type(exc).__name__, "error": line}


def _api_client() -> tuple[Any, Any]:
    from servonaut.services.api_client import APIClient
    from servonaut.services.auth_service import AuthService

    auth = AuthService()
    return auth, APIClient(auth)


def _passphrase_provider(passphrase: str) -> Callable[..., Awaitable[str]]:
    async def provide(*_args: Any, **_kwargs: Any) -> str:
        return passphrase

    return provide


def _sync_service(spec: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    """The release's own headless construction (what ``servonaut memory`` uses)."""
    from servonaut.cli import memory as cli_memory

    config, memory_service, _fleet = cli_memory._init_headless_services()
    from servonaut.config.manager import ConfigManager

    sync, retrieval = cli_memory._init_headless_sync_services(config, memory_service, ConfigManager())
    if sync is None:
        raise RuntimeError("the release built no sync service (not signed in?)")
    return sync, retrieval, memory_service, config


def _op_login(spec: dict[str, Any]) -> dict[str, Any]:
    from servonaut.services.auth_service import AuthToken

    known = {f.name for f in dataclasses.fields(AuthToken)}
    token = AuthToken(**{k: v for k, v in spec["token"].items() if k in known})
    path = _home() / "auth.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataclasses.asdict(token), indent=2), encoding="utf-8")
    path.chmod(0o600)
    return {"outcome": "ok"}


def _op_write_keys_json(spec: dict[str, Any]) -> dict[str, Any]:
    from servonaut.services.memory.crypto import wrap_private_key

    sync, _retrieval, _memory, _config = _sync_service(spec)
    key = spec["key"]
    wrapped = wrap_private_key(base64.b64decode(key["private_key"]), spec["passphrase"])
    sync._persist_key_cache(
        key["public_key"], wrapped.to_json(), key["fingerprint"], user_id=key["user_id"]
    )
    return {"outcome": "ok"}


def _module_result() -> Any:
    from servonaut.services.memory.interfaces import ModuleResult

    return ModuleResult(
        module="os",
        instance_id=INSTANCE["id"],
        observed={"kernel": "6.1"},
        declared={},
        sudo_used=False,
        truncated=False,
        partial=False,
        probed_at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        ttl_seconds=86400,
        raw_output="",
    )


async def _upload(sync: Any) -> dict[str, Any]:
    await sync.upsert_instance(INSTANCE)
    sync.enqueue_module(INSTANCE, "os", _module_result())
    result = await sync.drain_now()
    return {
        "accepted": len(result.accepted),
        "rejected": [getattr(r, "reason", None) or getattr(r, "code", None) or str(r) for r in result.rejected],
        "last_error": getattr(sync.status, "last_error", None),
        "halted_reason": getattr(sync.status, "halted_reason", None),
    }


async def _op_bootstrap(spec: dict[str, Any]) -> dict[str, Any]:
    sync, _retrieval, _memory, _config = _sync_service(spec)
    await sync.bootstrap(_passphrase_provider(spec["passphrase"]))
    report: dict[str, Any] = {"outcome": "ok", "is_configured": bool(sync.is_configured)}
    if spec.get("upload"):
        report["upload"] = await _upload(sync)
    return report


async def _op_rotate(spec: dict[str, Any]) -> dict[str, Any]:
    sync, _retrieval, _memory, _config = _sync_service(spec)
    await sync.rotate_keypair(spec["passphrase"], spec["new_passphrase"])
    return {"outcome": "ok"}


async def _op_retrieval(spec: dict[str, Any]) -> dict[str, Any]:
    from servonaut.services.memory import crypto as memory_crypto
    from servonaut.services.memory.rate_limiter import RateLimiter
    from servonaut.services.memory.retrieval_service import MemoryRetrievalService

    auth, api = _api_client()
    wanted = inspect.signature(MemoryRetrievalService.__init__).parameters
    extra = {"user_id_provider": auth.fetch_user_id} if "user_id_provider" in wanted else {}
    service = MemoryRetrievalService(
        api_client=api,
        crypto=memory_crypto,
        passphrase_provider=_passphrase_provider(spec["passphrase"]),
        rate_limiter=RateLimiter(),
        **extra,
    )
    envelope = await service.get_module(spec["instance_id"], spec["module"])
    return {"outcome": "ok", "got_envelope": envelope is not None}


def _config_service() -> Any:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.config_sync_service import ConfigSyncService

    _auth, api = _api_client()
    return ConfigSyncService(api, ConfigManager())


async def _op_config_pull(spec: dict[str, Any]) -> dict[str, Any]:
    data = await _config_service().pull(spec["passphrase"])
    return {"outcome": "ok", "keys": sorted(data) if isinstance(data, dict) else None}


async def _op_config_push(spec: dict[str, Any]) -> dict[str, Any]:
    result = await _config_service().push(spec["passphrase"], label="probe")
    return {"outcome": "ok", "version": result.get("version")}


async def _op_summary(spec: dict[str, Any]) -> dict[str, Any]:
    from servonaut.config.manager import ConfigManager
    from servonaut.services.memory.ai_summary_service import AISummaryService
    from servonaut.services.memory.rate_limiter import RateLimiter

    auth, api = _api_client()
    service = AISummaryService(api, RateLimiter(), auth, ConfigManager())
    instance_id = spec["instance_id"]
    service.confirm_provider_disclosure_shown(instance_id)
    report: dict[str, Any] = {"outcome": "ok"}
    try:
        consent = await service.request_consent_token(instance_id, "server_60s")
    except Exception as exc:  # noqa: BLE001 - reported, not hidden
        return {**_describe(exc), "stage": "consent"}
    report["consent_modules"] = list(consent.modules)
    try:
        dispatched = await service.dispatch_summary(
            instance_id, consent.token, consent.mode, spec["passphrase"]
        )
    except Exception as exc:  # noqa: BLE001
        return {**_describe(exc), "stage": "dispatch", "consent_modules": report["consent_modules"]}
    report["dispatch_status"] = dispatched.status
    return report


def _op_local_state(spec: dict[str, Any]) -> dict[str, Any]:
    memory_dir = _home() / "memory"
    keys = memory_dir / "keys.json"
    state: dict[str, Any] = {"outcome": "ok", "keys_json": keys.exists()}
    if keys.exists():
        try:
            state["keys_json_fingerprint"] = json.loads(keys.read_text(encoding="utf-8")).get("fingerprint")
        except (OSError, ValueError):
            state["keys_json_fingerprint"] = None
    state["marker"] = (memory_dir / "key_custody.json").exists()
    state["config_probe"] = (_home() / "sync_key_probe.json").exists()
    return state


async def _poll(pilot: Any, done: Callable[[], bool], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if done():
            return True
        await pilot.pause(0.25)
    return done()


def _toasts(app: Any) -> list[str]:
    # Private on purpose: this script is the only reader, and the release has
    # no public list of what it showed.
    return [f"{n.severity}: {n.message}"[:200] for n in list(getattr(app, "_notifications", []))]


def _static_text(app: Any) -> list[str]:
    """Short texts the active screen shows, for the report (status lines and card text)."""
    texts = []
    for widget in app.screen.query("Static"):
        value = getattr(widget, "content", None)
        if value is None:
            value = getattr(widget, "renderable", "")
        text = " ".join(str(value).split())
        if text and len(text) < 300:
            texts.append(text)
    return texts[:40]


async def _op_tui(spec: dict[str, Any]) -> dict[str, Any]:
    from servonaut.app import ServonautApp
    from servonaut.screens.memory_sync_setup import MemorySyncSetupScreen

    app = ServonautApp()
    report: dict[str, Any] = {"outcome": "ok"}
    async with app.run_test(size=(160, 50), notifications=True) as pilot:
        await pilot.pause(2.0)
        before = len(_toasts(app))
        app.switch_screen(MemorySyncSetupScreen())
        opened = await _poll(pilot, lambda: bool(app.screen.query("#msync_btn_setup")), 20.0)
        report["setup_button_shown"] = opened
        if opened:
            await pilot.click("#msync_btn_setup")
            await _poll(pilot, lambda: len(_toasts(app)) > before, 25.0)
            await pilot.pause(1.0)
        report["screen"] = type(app.screen).__name__
        report["statics"] = _static_text(app)
        report["toasts"] = _toasts(app)[before:]
        report["app_running"] = bool(app.is_running)
        report["passphrase_modal"] = any(
            type(s).__name__ == "PassphraseEnrolModal" for s in app.screen_stack
        )
    return report


OPERATIONS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "login": _op_login,
    "write_keys_json": _op_write_keys_json,
    "bootstrap": _op_bootstrap,
    "rotate": _op_rotate,
    "retrieval": _op_retrieval,
    "config_pull": _op_config_pull,
    "config_push": _op_config_push,
    "summary": _op_summary,
    "tui": _op_tui,
    "local_state": _op_local_state,
}


def main(operation: str, spec_path: str) -> int:
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    handler = OPERATIONS[operation]
    report: dict[str, Any]
    try:
        outcome = handler(spec)
        report = asyncio.run(outcome) if inspect.isawaitable(outcome) else outcome
    except Exception as exc:  # noqa: BLE001 - the release's own failure is the result
        report = _describe(exc)
    report.update({"operation": operation, "version": installed_version("servonaut")})
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main(sys.argv[1], sys.argv[2]))
