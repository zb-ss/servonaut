"""High-level lifecycle orchestrator for the TUI's in-process relay listener.

The TUI calls :class:`RelayManager` at mount time, on login success, and on
app exit. The manager decides:

* whether the user's plan allows a relay connection (``mcp_connections > 0``);
* whether a detached ``servonaut connect --bg`` is already holding the lock
  (defer to it, don't double-start);
* how to surface state changes to the UI without leaking raw
  :class:`RelayListener` internals.

Keeping this logic in a service class (rather than inline in ``app.py``)
means we can unit-test it without Textual.
"""
from __future__ import annotations

import asyncio
import enum
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from servonaut.services.relay_lock import (
    DEFAULT_LOCK_PATH,
    LockOwner,
    RelayAlreadyActiveError,
    RelayLock,
    read_owner,
)
from servonaut.utils.relay_log import log_relay_event

logger = logging.getLogger(__name__)


class RelayState(enum.Enum):
    """Coarse state for UI binding.

    The TUI indicator maps each state to colour + label; callers should not
    inspect anything finer-grained. Transitions are idempotent.
    """
    DISABLED = "disabled"            # not logged in / httpx missing
    NO_ENTITLEMENT = "no_entitlement"  # plan doesn't include mcp_connections
    NOT_CONFIGURED = "not_configured"  # config.relay.base_url/mercure_url missing
    EXTERNAL = "external"            # a `bg` listener already holds the lock
    CONNECTING = "connecting"        # task scheduled, waiting for first heartbeat
    CONNECTED = "connected"          # first heartbeat accepted
    ERROR = "error"                  # listener task raised or exited unexpectedly
    STOPPED = "stopped"              # explicitly stopped (app exit, manual)


@dataclass(frozen=True)
class StartResult:
    """What happened when ``start()`` was called."""
    state: RelayState
    message: str
    external_owner: Optional[LockOwner] = None


StateCallback = Callable[[RelayState], None]


class RelayManager:
    """Owns the lifecycle of the in-process relay listener."""

    def __init__(
        self,
        config_manager,
        auth_service,
        *,
        on_state_change: Optional[StateCallback] = None,
        lock_path=None,
        listener_factory=None,
    ) -> None:
        self._config_manager = config_manager
        self._auth_service = auth_service
        self._on_state_change = on_state_change
        self._lock_path = lock_path or DEFAULT_LOCK_PATH
        # listener_factory overridable for tests — returns something with .run()
        # and .stop(), accepting on_connected / on_disconnected kwargs.
        self._listener_factory = listener_factory or self._default_listener_factory
        self._lock: Optional[RelayLock] = None
        self._listener = None
        self._task: Optional[asyncio.Task] = None
        self._state: RelayState = RelayState.DISABLED

    # --- public API ----------------------------------------------------------

    @property
    def state(self) -> RelayState:
        return self._state

    @property
    def is_running(self) -> bool:
        """True when we own the lock and the listener task is live."""
        return self._lock is not None and self._task is not None and not self._task.done()

    def check_applicability(self) -> StartResult:
        """Explain, without side-effects, whether start() would do anything useful.

        The TUI calls this to decide what to show in the status indicator
        before ever committing to acquire the lock.
        """
        auth = self._auth_service
        if auth is None or not getattr(auth, "is_authenticated", False):
            return StartResult(RelayState.DISABLED, "Not logged in.")

        if not _mcp_connections_allowed(auth):
            return StartResult(
                RelayState.NO_ENTITLEMENT,
                "Relay disabled by your plan. Upgrade at https://servonaut.dev/pricing.",
            )

        cfg = self._config_manager.get().relay
        if not cfg.base_url or not cfg.mercure_url:
            return StartResult(
                RelayState.NOT_CONFIGURED,
                "Relay URLs not configured in ~/.servonaut/config.json.",
            )

        owner = read_owner(self._lock_path)
        from servonaut.services.relay_lock import is_pid_alive
        if owner.mode == "bg" and is_pid_alive(owner.pid):
            return StartResult(
                RelayState.EXTERNAL,
                f"External listener (PID {owner.pid}) already connected.",
                external_owner=owner,
            )
        return StartResult(RelayState.CONNECTING, "")

    async def start(self) -> StartResult:
        """Try to start the in-process listener.

        Returns the outcome; on success the task is scheduled and the state
        transitions to ``CONNECTING``. The state flips to ``CONNECTED`` when
        the first heartbeat is accepted, via the ``on_connected`` hook.
        """
        if self.is_running:
            return StartResult(self._state, "Already running.")

        applicability = self.check_applicability()
        if applicability.state is not RelayState.CONNECTING:
            self._set_state(applicability.state)
            return applicability

        try:
            self._lock = RelayLock(mode="tui", path=self._lock_path).acquire()
        except RelayAlreadyActiveError as e:
            owner = e.owner
            # If a bg listener took the lock between our check and here,
            # defer rather than erroring.
            self._set_state(RelayState.EXTERNAL)
            return StartResult(
                RelayState.EXTERNAL,
                f"Another listener (mode={owner.mode} pid={owner.pid}) is active.",
                external_owner=owner,
            )

        try:
            self._listener = self._listener_factory(
                on_connected=self._handle_connected,
                on_disconnected=self._handle_disconnected,
            )
        except ImportError as e:
            self._release_lock()
            self._set_state(RelayState.ERROR)
            return StartResult(RelayState.ERROR, str(e))
        except Exception as e:
            self._release_lock()
            self._set_state(RelayState.ERROR)
            return StartResult(RelayState.ERROR, f"Failed to build listener: {e}")

        self._set_state(RelayState.CONNECTING)
        log_relay_event("starting", mode="tui",
                        client_id=getattr(self._listener, "client_id", None))
        self._task = asyncio.create_task(self._run_listener(), name="relay_manager_listener")
        return StartResult(RelayState.CONNECTING, "Connecting…")

    async def stop(self, *, grace_seconds: float = 2.0) -> None:
        """Cancel the listener task, await it briefly, release the lock."""
        task = self._task
        listener = self._listener
        if listener is not None:
            try:
                listener.stop()
            except Exception:
                pass
        if task is not None and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=grace_seconds)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass
        self._task = None
        self._listener = None
        self._release_lock()
        self._set_state(RelayState.STOPPED)
        log_relay_event("stopped", mode="tui", reason="explicit")

    async def restart(self) -> StartResult:
        """Stop the current listener and start a fresh one."""
        await self.stop()
        return await self.start()

    # --- internals -----------------------------------------------------------

    async def _run_listener(self) -> None:
        """Drive the listener's run loop; capture failures into state."""
        assert self._listener is not None
        try:
            await self._listener.run()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception("Relay listener crashed: %s", e)
            self._set_state(RelayState.ERROR)
            log_relay_event("error", mode="tui", reason=str(e)[:200])

    async def _handle_connected(self) -> None:
        self._set_state(RelayState.CONNECTED)
        log_relay_event(
            "connected", mode="tui",
            client_id=getattr(self._listener, "client_id", None),
        )

    async def _handle_disconnected(self) -> None:
        """Listener teardown notice — log only; task-level handler sets the final state."""
        log_relay_event("disconnected", mode="tui")

    def _set_state(self, new_state: RelayState) -> None:
        if new_state is self._state:
            return
        self._state = new_state
        if self._on_state_change is not None:
            try:
                self._on_state_change(new_state)
            except Exception:
                logger.exception("RelayManager state-change callback raised")

    def _release_lock(self) -> None:
        if self._lock is not None:
            try:
                self._lock.release()
            except Exception:
                pass
            self._lock = None

    def _default_listener_factory(self, *, on_connected, on_disconnected):
        """Construct a RelayListener wired to the app's services."""
        from servonaut.services.relay_listener import RelayListener
        from servonaut.services.relay_executors import RelayExecutors

        cfg = self._config_manager.get().relay
        token = self._auth_service.access_token if self._auth_service else None
        if not token:
            raise RuntimeError("No OAuth token available.")
        user_id = _extract_user_id(self._auth_service)
        if not user_id:
            raise RuntimeError("Could not determine user id from auth service.")

        executors = _build_executors(self._config_manager)
        return RelayListener(
            executors=executors,
            base_url=cfg.base_url,
            mercure_url=cfg.mercure_url,
            auth_token=token,
            user_id=user_id,
            heartbeat_interval=cfg.heartbeat_interval,
            on_connected=on_connected,
            on_disconnected=on_disconnected,
        )


# --- helpers ----------------------------------------------------------------

def _mcp_connections_allowed(auth_service) -> bool:
    """Read ``mcp_connections`` from the cached entitlements dict.

    Backend returns this as a top-level integer key. A value > 0 means the
    user may run a relay listener; 0 = no relay. Falls back to False if the
    key is missing or entitlements haven't been fetched.
    """
    token = getattr(auth_service, "_token", None)
    if token is None:
        return False
    ents = getattr(token, "entitlements", None) or {}
    if not isinstance(ents, dict):
        return False
    try:
        quota = int(ents.get("mcp_connections", 0))
    except (TypeError, ValueError):
        return False
    return quota > 0


def _extract_user_id(auth_service) -> Optional[str]:
    """Pull the integer/stringy user id out of the token (canonical) or cached entitlements.

    The Mercure subscriber JWT minted by the server authorizes the topic
    `/cli/{user_id}/commands` (numeric). Falling back to email here would
    build a topic the JWT cannot subscribe to and produce permanent 401s,
    so we treat email as a last-resort hint only.

    Resolution order:
      1. ``token.user_id`` — set by ``auth_service._apply_entitlements`` once
         the server has returned ``user_id`` in the entitlements payload.
         This is the canonical source.
      2. ``token.entitlements["user_id"]`` / ``["id"]`` — direct read of the
         cached payload, in case ``token.user_id`` has not been populated yet
         (older auth.json from before the field was tracked).
      3. ``token.email`` — best effort if neither field is present. Will not
         match the JWT topic, so the listener will surface the mismatch
         loudly rather than silently subscribing under the wrong identifier.
    """
    token = getattr(auth_service, "_token", None)
    if token is None:
        return None
    uid = getattr(token, "user_id", None)
    if uid is not None:
        return str(uid)
    ents = getattr(token, "entitlements", None) or {}
    if isinstance(ents, dict):
        ents_uid = ents.get("user_id") or ents.get("id")
        if ents_uid is not None:
            return str(ents_uid)
    email = getattr(token, "email", "")
    return email or None


def _build_executors(config_manager):
    """Assemble the same executor graph that ``main.py _relay_run_foreground`` uses."""
    from servonaut.services.cache_service import CacheService
    from servonaut.services.aws_service import AWSService
    from servonaut.services.ssh_service import SSHService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.scp_service import SCPService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.relay_executors import RelayExecutors
    cfg = config_manager.get()
    cache_service = CacheService(ttl_seconds=cfg.cache_ttl_seconds)
    aws_service = AWSService(cache_service)
    custom_server_service = CustomServerService(config_manager)
    ssh_service = SSHService(config_manager)
    connection_service = ConnectionService(config_manager)
    scp_service = SCPService()
    return RelayExecutors(
        config_manager, aws_service, custom_server_service,
        ssh_service, connection_service, scp_service,
    )
