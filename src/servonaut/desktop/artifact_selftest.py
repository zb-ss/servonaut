"""Authenticated local self-test of a packaged desktop build.

The packaged GUI runs this instead of opening its window when it is started
with ``--_artifact-selftest``. Without a display it proves that the frozen
payload imports its desktop stack, finds its bundled resources, holds intact
the voice runtime inputs its manifest pins, and bootstraps the loopback host
through the real child executable. The host must serve the page, refuse an
unauthenticated session, hand the token over through the one-shot bridge, run
the real app for one authenticated session and then let the child exit cleanly.

Opening the native window needs a display, so it runs only when the request
asks for the ``desktop-window`` check.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import json
import os
import secrets
import stat
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

# The request, authentication, isolation and fixture helpers are shared with
# the standalone CLI self-test, so both builds follow one protocol.
from servonaut._artifact_selftest import (
    _RESULT_SCHEMA_VERSION,
    _authenticate,
    _create_fixtures,
    _read_request,
    _SelftestFailure,
    _verify_fixtures,
    _write_result,
    isolated_home,
)

if TYPE_CHECKING:
    from servonaut.desktop.launcher import DesktopSessionOwner
    from servonaut.desktop.voice.packaged_manifest import BundledFile
    from servonaut.runtime import RuntimeLayout

DESKTOP_CHECK: Final = "desktop"
DESKTOP_WINDOW_CHECK: Final = "desktop-window"
_CHECKS: Final = frozenset({DESKTOP_CHECK, DESKTOP_WINDOW_CHECK})
# Bounds of the individual steps. They sum to well under the smoke runner's
# own bound on the whole self-test, so a hung step reports its own code.
_HOST_STARTUP_SECONDS: Final = 20.0
_HOST_REQUEST_SECONDS: Final = 10.0
_SESSION_SECONDS: Final = 30.0
_CHILD_EXIT_SECONDS: Final = 10.0
_WINDOW_SECONDS: Final = 20.0
_MAX_PAGE_BYTES: Final = 1024 * 1024
_PING_PAYLOAD: Final = "artifact-selftest"


def run_desktop_artifact_selftest(runtime: object) -> int:
    """Run the one authenticated desktop check and write a bounded JSON result."""
    if sys.stdin is None or sys.stdout is None:
        # Without inherited standard streams there is no request to read and
        # nowhere to report; refuse instead of starting anything.
        return 1
    try:
        request = _read_request(sys.stdin.buffer, checks=_CHECKS)
        _authenticate(request)
        result = _run_isolated_check(runtime, request.check)
    except _SelftestFailure as error:
        _write_result(_failure(error.code))
        return 1
    except Exception:
        _write_result(_failure("selftest-failed"))
        return 1
    _write_result(result)
    return 0


def _failure(code: str) -> dict[str, object]:
    return {"schema_version": _RESULT_SCHEMA_VERSION, "ok": False, "error": code}


def _run_isolated_check(initial_runtime: object, check: str) -> dict[str, object]:
    try:
        with isolated_home() as home:
            runtime = _packaged_runtime(home, initial_runtime)
            _import_desktop_stack()
            resources = _verify_resources(runtime)
            voice = _verify_voice_payload(runtime)
            config_path, cache_path, expected = _create_fixtures(runtime.data_root)
            host = _bootstrap_host(runtime, open_window=check == DESKTOP_WINDOW_CHECK)
            preserved = _verify_fixtures(config_path, cache_path, expected)
            if not all(preserved.values()):
                raise _SelftestFailure("fixture-modified")
            return {
                "schema_version": _RESULT_SCHEMA_VERSION,
                "ok": True,
                "check": check,
                "runtime": {
                    "kind": "packaged-desktop",
                    "marker": True,
                    "channel": runtime.release_channel,
                    "packaging_revision": runtime.packaging_revision,
                },
                "resources": resources,
                "voice": voice,
                "host": host,
                "fixtures": preserved,
            }
    except _SelftestFailure:
        raise
    except Exception:
        raise _SelftestFailure("isolation-failed") from None


def _packaged_runtime(home: Path, initial_runtime: object) -> RuntimeLayout:
    """Re-detect the runtime inside the isolated home and require the GUI role."""
    from servonaut.runtime import (
        DesktopProcessRole,
        DistributionKind,
        RuntimeCapabilityError,
        detect_runtime,
        validate_desktop_process_role,
    )

    runtime = detect_runtime()
    if (
        runtime.kind is not DistributionKind.PACKAGED_DESKTOP
        or not runtime.is_frozen
        or runtime.build_revision is None
        or runtime.packaging_revision is None
        or runtime.data_root != home / ".servonaut"
        or runtime.product_version != getattr(initial_runtime, "product_version", None)
    ):
        raise _SelftestFailure("runtime-invalid")
    try:
        validate_desktop_process_role(
            runtime, DesktopProcessRole.GUI, current_executable=runtime.executable
        )
    except RuntimeCapabilityError:
        raise _SelftestFailure("runtime-roles") from None
    return runtime


def _import_desktop_stack() -> None:
    """Import what the GUI needs; the window toolkit loads only when shown."""
    try:
        import aiohttp  # noqa: F401
        import webview  # noqa: F401

        from servonaut.desktop import bridge, host, launcher  # noqa: F401
    except Exception:
        raise _SelftestFailure("import-failed") from None


def _verify_resources(runtime: RuntimeLayout) -> dict[str, bool]:
    from servonaut.desktop.assets import DesktopAssetError, load_and_verify_assets

    resource_root = runtime.resource_root
    try:
        routes, _manifest = load_and_verify_assets(repo_root=resource_root)
    except (DesktopAssetError, OSError, ValueError, KeyError):
        raise _SelftestFailure("resources-frontend") from None
    if "/" not in routes:
        raise _SelftestFailure("resources-frontend")
    notices = resource_root / "notices"
    try:
        has_notices = notices.is_dir() and any(
            entry.is_file() for entry in notices.iterdir()
        )
    except OSError:
        has_notices = False
    if not has_notices:
        raise _SelftestFailure("resources-notices")
    return {"frontend": True, "notices": True}


def _verify_voice_payload(runtime: RuntimeLayout) -> dict[str, object]:
    """Verify the bundled voice runtime inputs against the manifest that pins them.

    The manifest is read by the loader the app uses when it provisions voice,
    and every file it pins goes through the digest check provisioning runs, so
    what the manifest means is never decided by a second copy here. The runtime
    does not record which target it was built for; the manifest's target is
    reported so the smoke runner, which knows the target, can compare them.
    """
    from servonaut.desktop.voice.packaged_manifest import (
        PACKAGED_MANIFEST_FILENAME,
        PACKAGED_VOICE_DIRNAME,
        PackagedVoiceManifestError,
        load_packaged_manifest,
    )

    directory = runtime.resource_root / PACKAGED_VOICE_DIRNAME
    try:
        roots = _resource_directories(runtime.resource_root)
    except (OSError, RuntimeError):
        raise _SelftestFailure("voice-payload") from None
    manifest_path = _packaged_file(directory / PACKAGED_MANIFEST_FILENAME, roots)
    if not _lstat_is(directory, stat.S_ISDIR) or manifest_path is None:
        raise _SelftestFailure("voice-payload")
    try:
        manifest = load_packaged_manifest(manifest_path)
    except PackagedVoiceManifestError:
        raise _SelftestFailure("voice-manifest") from None
    pinned = {
        "uv": manifest.uv,
        "wheel": manifest.wheel,
        "requirements": manifest.requirements,
    }
    for role, bundled in pinned.items():
        _verify_bundled_file(directory, roots, role, bundled)
    return {
        "directory": True,
        "manifest": True,
        "target": manifest.target,
        **dict.fromkeys(pinned, True),
    }


def _verify_bundled_file(
    directory: Path, roots: tuple[Path, ...], role: str, bundled: BundledFile
) -> None:
    """Require a pinned file in the voice directory to match its digest.

    The manifest's filename pattern admits no path separator and no leading
    dot, so the name can only sit directly in the voice directory. Fails with
    ``voice-<role>-file`` or ``voice-<role>-digest``.
    """
    from servonaut.desktop.voice.runtime import (
        VoiceRuntimeIntegrityError,
        verify_sha256,
    )

    path = _packaged_file(directory / bundled.filename, roots)
    if path is None:
        raise _SelftestFailure(f"voice-{role}-file")
    try:
        verify_sha256(path, bundled.sha256)
    except VoiceRuntimeIntegrityError:
        raise _SelftestFailure(f"voice-{role}-digest") from None


def _packaged_file(path: Path, roots: tuple[Path, ...]) -> Path | None:
    """The regular file *path* names, resolved, if it stays within the resources.

    A macOS app bundle links data files from ``Contents/Frameworks`` into
    ``Contents/Resources``, so a link is followed, but only to a regular file
    inside the resource directories. A link that escapes them or dangles
    names nothing.
    """
    try:
        resolved = path.resolve(strict=True)
        is_regular = stat.S_ISREG(resolved.lstat().st_mode)
    except (OSError, RuntimeError):
        return None
    if not is_regular or not any(resolved.is_relative_to(root) for root in roots):
        return None
    return resolved


def _lstat_is(path: Path, is_kind: Callable[[int], bool]) -> bool:
    """Whether *path* itself, never the target of a link, is of the kind."""
    try:
        return is_kind(path.lstat().st_mode)
    except OSError:
        return False


def _resource_directories(resource_root: Path) -> tuple[Path, ...]:
    """Where the packaged resources live, resolved.

    A macOS app bundle keeps its code in ``Contents/Frameworks`` (the resource
    root) and its data in ``Contents/Resources``, linked into the root.
    """
    roots = [resource_root]
    if resource_root.name == "Frameworks" and resource_root.parent.name == "Contents":
        roots.append(resource_root.parent / "Resources")
    return tuple(root.resolve(strict=True) for root in roots)


def _bootstrap_host(runtime: RuntimeLayout, *, open_window: bool) -> dict[str, bool]:
    """Start the real child, exercise the host, and require a clean child exit."""
    from servonaut.desktop.launcher import (
        DesktopLauncherError,
        DesktopLaunchRequest,
        DesktopSessionOwner,
    )
    from servonaut.runtime import RuntimeCapabilityError

    # The window's location as the bridge sees it: nothing is loaded until the
    # page check passes, and then only the root document.
    current_url: list[str | None] = [None]
    owner = DesktopSessionOwner()
    try:
        try:
            ready = owner.start(
                DesktopLaunchRequest(
                    runtime=runtime, startup_timeout=_HOST_STARTUP_SECONDS
                ),
                get_current_url=lambda: current_url[0],
            )
        except (DesktopLauncherError, RuntimeCapabilityError):
            raise _SelftestFailure("host-start") from None
        port = urlsplit(ready.origin).port
        if port is None:
            raise _SelftestFailure("host-start")
        _require_page(port)
        _require_unauthenticated_session_refused(port, ready.origin)
        if open_window:
            _open_window(ready.origin)
        current_url[0] = f"{ready.origin}/"
        token = _claim_session_once(owner)
        session = _run_authenticated_session(ready.origin, token)
        child_exited = _wait_for_child_exit(owner)
        return {
            "page": True,
            "refused_unauthenticated": True,
            "window": open_window,
            **session,
            "child_exited": child_exited,
        }
    finally:
        owner.request_shutdown()
        owner.close()


def _claim_session_once(owner: DesktopSessionOwner) -> str:
    """Claim the token through the bridge, which must refuse a second claim."""
    from servonaut.desktop.bridge import DesktopBridgeError

    bridge = owner.bridge
    if bridge is None:
        raise _SelftestFailure("host-claim")
    try:
        token = bridge.claim_session()
    except DesktopBridgeError:
        raise _SelftestFailure("host-claim") from None
    try:
        bridge.claim_session()
    except DesktopBridgeError:
        return token
    raise _SelftestFailure("host-claim")


def _require_page(port: int) -> None:
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=_HOST_REQUEST_SECONDS
    )
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        body = response.read(_MAX_PAGE_BYTES + 1)
        if (
            response.status != 200
            or not body
            or len(body) > _MAX_PAGE_BYTES
            or not response.getheader("Content-Security-Policy")
        ):
            raise _SelftestFailure("host-page")
    except (OSError, http.client.HTTPException):
        raise _SelftestFailure("host-page") from None
    finally:
        connection.close()


def _require_unauthenticated_session_refused(port: int, origin: str) -> None:
    """A WebSocket upgrade without the session token must be forbidden."""
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=_HOST_REQUEST_SECONDS
    )
    try:
        connection.request(
            "GET",
            "/ws",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Origin": origin,
                "Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
                "Sec-WebSocket-Version": "13",
            },
        )
        response = connection.getresponse()
        response.read(_MAX_PAGE_BYTES)
        if response.status != 403:
            raise _SelftestFailure("host-auth")
    except (OSError, http.client.HTTPException):
        raise _SelftestFailure("host-auth") from None
    finally:
        connection.close()


def _run_authenticated_session(origin: str, token: str) -> dict[str, bool]:
    try:
        return asyncio.run(
            asyncio.wait_for(_authenticated_session(origin, token), _SESSION_SECONDS)
        )
    except _SelftestFailure:
        raise
    except Exception:
        raise _SelftestFailure("host-session") from None


async def _authenticated_session(origin: str, token: str) -> dict[str, bool]:
    """Run one session of the real app and require rendered output and a pong."""
    import aiohttp

    from servonaut.desktop.host import MAX_MESSAGE_BYTES, PROTOCOL_SUBPROTOCOL

    rendered = False
    answered = False
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(
            f"ws://{urlsplit(origin).netloc}/ws",
            protocols=(PROTOCOL_SUBPROTOCOL, f"auth.{token}"),
            origin=origin,
            max_msg_size=MAX_MESSAGE_BYTES,
        ) as websocket:
            await websocket.send_json(["ping", _PING_PAYLOAD])
            while not (rendered and answered):
                message = await websocket.receive()
                if message.type is aiohttp.WSMsgType.BINARY:
                    rendered = rendered or bool(message.data)
                elif message.type is aiohttp.WSMsgType.TEXT:
                    answered = answered or json.loads(message.data) == [
                        "pong",
                        _PING_PAYLOAD,
                    ]
                else:
                    raise _SelftestFailure("host-session")
    return {"session_rendered": rendered, "session_answered": answered}


def _wait_for_child_exit(owner: DesktopSessionOwner) -> bool:
    """The host serves one session; once it ends the child must exit with 0."""
    tree = owner.tree
    if tree is None:
        raise _SelftestFailure("host-exit")
    try:
        code = tree.wait(timeout=_CHILD_EXIT_SECONDS)
    except subprocess.TimeoutExpired:
        raise _SelftestFailure("host-exit") from None
    if code != 0:
        raise _SelftestFailure("host-exit")
    return True


def _open_window(origin: str) -> None:
    """Open the native window on the page, then close it once it has loaded."""
    try:
        import webview

        loaded = threading.Event()
        window = webview.create_window(
            "Servonaut self-test", url=origin, width=480, height=360
        )

        def on_loaded() -> None:
            loaded.set()
            window.destroy()

        def close_when_stalled() -> None:
            if not loaded.wait(_WINDOW_SECONDS):
                window.destroy()

        window.events.loaded += on_loaded
        webview.start(
            close_when_stalled, debug=False, http_server=False, private_mode=True
        )
    except Exception:
        raise _SelftestFailure("window-failed") from None
    if not loaded.is_set():
        raise _SelftestFailure("window-failed")
