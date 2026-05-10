#!/usr/bin/env python3
"""Spin up + tear down a 4-server Hetzner Cloud demo fleet.

The script that backs the marketing-video recording (and the
acceptance-criterion #8 smoke test from the kickoff brief at
``~/.dotfiles/org/org/servonaut/plans/cli/kickoff-hetzner-provider.org``).

Sequence (target wall clock <60 s, kickoff brief criterion #8):

1. Discover residual ``servonaut-demo-*`` servers — abort unless
   ``--reset`` is passed (operator must explicitly acknowledge).
2. Concurrently create four ``cx23`` servers in ``fsn1`` running
   ``ubuntu-22.04`` with ``wait_until_running=False`` so the create
   calls return as soon as the queue accepts them. Each server is
   tagged with a unique session label so concurrent runs don't step
   on each other's fleets.
3. List + log all four.
4. Concurrently delete the four servers.
5. Verify zero servers from this session remain.
6. Log every action to ``local/smoke-hetzner.log``.

Safety rails:

* Cost ceiling: cx23 is €0.0077/hr. Four × five minutes (cap) = €0.0026.
* Hard wall-clock cap of 300 s on the entire run — wraps the whole
  flow in ``asyncio.wait_for`` so even a stuck delete bails out.
* Ctrl-C is wired via ``loop.add_signal_handler`` so the running
  ``_run_smoke`` task is cancelled and ``_safety_cleanup`` runs in
  the SAME event loop — no "loop already running" RuntimeError.

Use ``--keep`` to skip the teardown (e.g. for video recording where
you want the fleet to live longer); the operator is responsible for
calling ``servonaut hetzner destroy`` afterwards.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Ensure ``src/`` is on the path so this script works without ``pip install -e .``
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / 'src'))

from servonaut.config.schema import HetznerConfig
from servonaut.services.hetzner_service import (
    HetznerError,
    HetznerNotConfiguredError,
    HetznerService,
)


_DEMO_PREFIX = 'servonaut-demo-'
_DEMO_LABEL_KEY = 'servonaut-demo-fleet'
_DEFAULT_COUNT = 4
_DEFAULT_TYPE = 'cx23'
_DEFAULT_LOCATION = 'fsn1'
_DEFAULT_IMAGE = 'ubuntu-22.04'
_HARD_TIMEOUT_SECONDS = 300


def _setup_logging(log_path: Path) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger('demo_fleet')
    logger.setLevel(logging.INFO)
    # Remove any pre-existing handlers (e.g. on re-run within the same process).
    for h in list(logger.handlers):
        logger.removeHandler(h)
    fmt = logging.Formatter('%(asctime)s %(levelname)-7s %(message)s')
    file_h = logging.FileHandler(log_path)
    file_h.setFormatter(fmt)
    stream_h = logging.StreamHandler()
    stream_h.setFormatter(fmt)
    logger.addHandler(file_h)
    logger.addHandler(stream_h)
    return logger


def _build_service(api_token: Optional[str]) -> HetznerService:
    """Build a HetznerService outside of the CLI app context."""
    cfg = HetznerConfig(
        enabled=True,
        api_token=api_token or '',
        default_server_type=_DEFAULT_TYPE,
        default_image=_DEFAULT_IMAGE,
        default_location=_DEFAULT_LOCATION,
        cache_path=str(_REPO_ROOT / 'local' / '.hetzner_cache_smoke.json'),
        audit_path=str(_REPO_ROOT / 'local' / 'smoke-hetzner-audit.jsonl'),
        cache_ttl_seconds=60,
    )
    return HetznerService(cfg)


async def _create_one(
    svc: HetznerService, name: str, session_id: str, logger: logging.Logger,
) -> dict:
    logger.info("Creating %s …", name)
    instance = await svc.create_server(
        name=name,
        server_type=_DEFAULT_TYPE,
        image=_DEFAULT_IMAGE,
        location=_DEFAULT_LOCATION,
        ssh_keys=None,
        labels={_DEMO_LABEL_KEY: session_id},
        wait_until_running=False,
        # Smoke fleet is intentionally key-less — they're deleted in
        # the same script. Override the safety guard explicitly.
        allow_no_ssh_keys=True,
    )
    logger.info(
        "Created %s id=%s ip=%s state=%s",
        name, instance.get('id'), instance.get('public_ip') or '-',
        instance.get('state'),
    )
    return instance


async def _delete_one(svc: HetznerService, identifier: str, logger: logging.Logger) -> None:
    logger.info("Deleting %s …", identifier)
    await svc.delete_server(identifier)
    logger.info("Deleted %s", identifier)


async def _safety_cleanup(
    svc: HetznerService, logger: logging.Logger,
    session_id: Optional[str] = None,
) -> int:
    """Best-effort sweep: delete servers belonging to this fleet.

    When ``session_id`` is given, only servers labelled with the
    matching session label are deleted (so concurrent runs don't step
    on each other). When ``session_id`` is None (e.g. ``--reset``),
    every server starting with the demo prefix is swept regardless of
    label — the operator explicitly opts in.

    Returns:
        Count of servers deleted.
    """
    try:
        instances = await svc.fetch_instances_cached(force_refresh=True)
    except Exception as exc:  # noqa: BLE001
        logger.error("Safety cleanup list failed: %s", exc)
        return 0
    if session_id:
        targets = [
            i for i in instances
            if (i.get('labels') or {}).get(_DEMO_LABEL_KEY) == session_id
        ]
    else:
        targets = [
            i for i in instances
            if (i.get('name') or '').startswith(_DEMO_PREFIX)
        ]
    if not targets:
        return 0
    logger.warning(
        "Safety cleanup: deleting %d residual demo server(s)%s",
        len(targets),
        f" (session={session_id})" if session_id else " (prefix sweep)",
    )
    deletions = [_delete_one(svc, i.get('id'), logger) for i in targets]
    results = await asyncio.gather(*deletions, return_exceptions=True)
    failures = [r for r in results if isinstance(r, Exception)]
    if failures:
        for f in failures:
            logger.error("Cleanup deletion failed: %s", f)
    return len(targets) - len(failures)


async def _run_smoke(
    svc: HetznerService, count: int, keep: bool, session_id: str,
    logger: logging.Logger,
) -> int:
    started_at = time.monotonic()

    # Step 1 — refuse to start if leftovers exist.
    instances = await svc.fetch_instances_cached(force_refresh=True)
    residuals = [
        i for i in instances
        if (i.get('name') or '').startswith(_DEMO_PREFIX)
    ]
    if residuals:
        names = ', '.join((i.get('name') or '?') for i in residuals)
        logger.error(
            "Found %d residual demo server(s): %s. "
            "Re-run with --reset to clean up first.",
            len(residuals), names,
        )
        return 2

    names = [f"{_DEMO_PREFIX}{i + 1}" for i in range(count)]
    creates = [_create_one(svc, name, session_id, logger) for name in names]

    try:
        await asyncio.wait_for(
            asyncio.gather(*creates),
            timeout=_HARD_TIMEOUT_SECONDS / 3,
        )
    except asyncio.TimeoutError:
        logger.error("Create wave timed out; cleaning up.")
        await _safety_cleanup(svc, logger, session_id=session_id)
        return 1

    # Step 3 — list (forces a refresh) — match by session label so we
    # don't accidentally see a parallel run's fleet.
    instances = await svc.fetch_instances_cached(force_refresh=True)
    ours = [
        i for i in instances
        if (i.get('labels') or {}).get(_DEMO_LABEL_KEY) == session_id
    ]
    logger.info(
        "Listing: %d server(s) tagged %s=%s:",
        len(ours), _DEMO_LABEL_KEY, session_id,
    )
    for inst in ours:
        logger.info(
            "  %s id=%s ip=%s state=%s region=%s",
            inst.get('name'), inst.get('id'),
            inst.get('public_ip') or '-', inst.get('state'),
            inst.get('region'),
        )

    if len(ours) != count:
        logger.error(
            "List mismatch: expected %d demo servers, found %d.",
            count, len(ours),
        )
        await _safety_cleanup(svc, logger, session_id=session_id)
        return 1

    if keep:
        logger.warning(
            "--keep set; %d server(s) will continue to bill "
            "(~€0.0077/hr each at cx23 list price).",
            len(ours),
        )
        elapsed = time.monotonic() - started_at
        logger.info("Smoke (keep mode) finished in %.1fs.", elapsed)
        return 0

    # Step 4 — concurrent destroy (use IDs because they're unambiguous).
    deletions = [_delete_one(svc, i.get('id'), logger) for i in ours]
    results = await asyncio.gather(*deletions, return_exceptions=True)
    failures = [r for r in results if isinstance(r, Exception)]
    if failures:
        logger.error("%d delete(s) failed: %s", len(failures), failures)
        await _safety_cleanup(svc, logger, session_id=session_id)
        return 1

    # Step 5 — verify zero session-tagged residuals.
    final = await svc.fetch_instances_cached(force_refresh=True)
    leftovers = [
        i for i in final
        if (i.get('labels') or {}).get(_DEMO_LABEL_KEY) == session_id
    ]
    if leftovers:
        logger.error(
            "Final list still contains demo servers: %s",
            [i.get('name') for i in leftovers],
        )
        await _safety_cleanup(svc, logger, session_id=session_id)
        return 1

    elapsed = time.monotonic() - started_at
    logger.info("Smoke completed cleanly in %.1fs.", elapsed)
    if elapsed > 60.0:
        logger.warning(
            "Wall-clock exceeded the kickoff-brief target of 60s "
            "(actual: %.1fs).", elapsed,
        )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Spin up + tear down a 4-server Hetzner demo fleet (smoke "
            "test for the Hetzner provider integration)."
        ),
    )
    parser.add_argument('--count', type=int, default=_DEFAULT_COUNT,
                        help=f'Servers to spin up (default: {_DEFAULT_COUNT}).')
    parser.add_argument('--reset', action='store_true',
                        help='Delete any pre-existing servonaut-demo-* servers '
                             'before running.')
    parser.add_argument('--keep', action='store_true',
                        help='Skip teardown (servers continue to bill — '
                             'use for marketing-video recording).')
    parser.add_argument('--token-file',
                        default=str(Path.home() / '.config' / 'hcloud' / 'token'),
                        help='Path to the Hetzner API token file '
                             '(default: ~/.config/hcloud/token).')
    parser.add_argument('--log',
                        default=str(_REPO_ROOT / 'local' / 'smoke-hetzner.log'),
                        help='Smoke-test log path.')
    args = parser.parse_args()

    logger = _setup_logging(Path(args.log))
    logger.info("=== Demo-fleet smoke %s ===", datetime.now().isoformat())

    token = ''
    try:
        token = Path(args.token_file).expanduser().read_text().strip()
    except OSError:
        token = os.environ.get('HCLOUD_TOKEN', '').strip()

    if not token:
        logger.error(
            "No API token available. Place it at %s, or set $HCLOUD_TOKEN.",
            args.token_file,
        )
        return 2

    try:
        svc = _build_service(token)
        # Force-resolve so a misconfigured token fails fast.
        svc.resolve_token()
    except HetznerNotConfiguredError as exc:
        logger.error("Hetzner not configured: %s", exc)
        return 2

    if args.reset:
        deleted = asyncio.run(_safety_cleanup(svc, logger, session_id=None))
        logger.info("--reset: removed %d pre-existing demo server(s).", deleted)

    session_id = uuid.uuid4().hex
    logger.info("Session label: %s=%s", _DEMO_LABEL_KEY, session_id)

    async def _bounded_smoke():
        """Wrap the smoke run in a hard wall-clock cap with cleanup."""
        try:
            return await asyncio.wait_for(
                _run_smoke(svc, args.count, args.keep, session_id, logger),
                timeout=_HARD_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.error(
                "Hard wall-clock cap of %ds exceeded — running cleanup.",
                _HARD_TIMEOUT_SECONDS,
            )
            await _safety_cleanup(svc, logger, session_id=session_id)
            return 1

    async def _async_main():
        loop = asyncio.get_running_loop()
        cancelled = asyncio.Event()
        smoke_task = asyncio.ensure_future(_bounded_smoke())

        def _on_signal(signame: str) -> None:
            if cancelled.is_set():
                return
            cancelled.set()
            logger.warning(
                "Received %s — cancelling smoke and running cleanup.",
                signame,
            )
            smoke_task.cancel()

        # Use loop.add_signal_handler so cleanup runs IN this event
        # loop. signal.signal + run_until_complete fails with
        # "loop already running".
        for signame in ('SIGINT', 'SIGTERM'):
            try:
                sig = getattr(signal, signame)
                loop.add_signal_handler(sig, _on_signal, signame)
            except (NotImplementedError, AttributeError):
                # Windows / non-Unix doesn't support add_signal_handler;
                # fall back to default KeyboardInterrupt propagation.
                pass

        try:
            return await smoke_task
        except asyncio.CancelledError:
            await _safety_cleanup(svc, logger, session_id=session_id)
            return 130
        except HetznerError as exc:
            logger.error("Hetzner error: %s", exc)
            await _safety_cleanup(svc, logger, session_id=session_id)
            return 1
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unhandled error: %s", exc)
            await _safety_cleanup(svc, logger, session_id=session_id)
            return 1

    try:
        rc = asyncio.run(_async_main())
    except KeyboardInterrupt:
        # Last-resort path: the ``add_signal_handler`` cleanup should
        # have run, but if we get here cleanup may not have happened.
        # Run it explicitly in a fresh loop.
        logger.warning("KeyboardInterrupt outside async context; cleaning up.")
        try:
            asyncio.run(_safety_cleanup(svc, logger, session_id=session_id))
        except Exception:  # noqa: BLE001
            pass
        rc = 130
    return rc


if __name__ == '__main__':
    sys.exit(main())
