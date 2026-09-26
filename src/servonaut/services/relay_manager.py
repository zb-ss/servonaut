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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from servonaut.services.relay_control import (
    DEFAULT_CONTROL_TIMEOUT_SECONDS,
    _complete_owned_cleanup,
    cleanup_deadline_seconds,
    configured_control_timeout_seconds,
)
from servonaut.services.relay_lock import (
    DEFAULT_LOCK_PATH,
    LockOwner,
    RelayAlreadyActiveError,
    RelayLock,
    RelayLockUnavailableError,
    active_owner,
)
from servonaut.utils.endpoints import (
    RELAY_BASE_URL_KEY,
    RELAY_MERCURE_URL_KEY,
    EndpointOverrideError,
    validate_relay_urls,
)
from servonaut.utils.relay_log import log_relay_event

logger = logging.getLogger(__name__)


def derive_relay_urls(api_base: str) -> tuple[str, str]:
    """Derive (relay_base_url, mercure_url) from the auth API base URL.

    Production splits the API and Mercure hub across two hosts (``api.``
    subdomain vs apex), while staging puts both on a single host. The rule:
    Mercure lives on the API host with any leading ``api.`` label stripped,
    at ``/.well-known/mercure``. Relay base_url stays equal to the API base.

    Examples:
        ``https://api.servonaut.dev``      → mercure on ``servonaut.dev``
        ``https://staging.example.com``  → mercure on ``staging.example.com``
    """
    parts = urlsplit(api_base)
    if not parts.scheme or not parts.netloc:
        raise ValueError("The API base URL has no scheme or host.")
    mercure_host = parts.netloc
    mercure_host = mercure_host.removeprefix("api.")
    mercure_url = urlunsplit(
        (parts.scheme, mercure_host, "/.well-known/mercure", "", "")
    )
    relay_base = urlunsplit((parts.scheme, parts.netloc, "", "", "")).rstrip("/")
    return relay_base, mercure_url


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
    SESSION_EXPIRED = "session_expired"  # backend rejected the OAuth bearer; sign in again


@dataclass(frozen=True)
class StartResult:
    """What happened when ``start()`` was called."""
    state: RelayState
    message: str
    external_owner: LockOwner | None = None


StateCallback = Callable[[RelayState], None]


@dataclass
class _StopScope:
    """The lifecycle objects one ``stop()`` call owns, captured when it starts.

    Settling compares identities against this scope, so a stop that finishes
    late can never release a newer lock or clear a newer listener task.
    """

    lock: RelayLock | None
    task: asyncio.Task | None
    listener: Any
    settled: bool = False


class RelayManager:
    """Owns the lifecycle of the in-process relay listener."""

    def __init__(
        self,
        config_manager,
        auth_service,
        *,
        on_state_change: StateCallback | None = None,
        lock_path=None,
        listener_factory=None,
        control_server_factory=None,
        control_record_path=None,
        control_timeout_seconds=None,
        cleanup_timeout_seconds=None,
        app: Any = None,
    ) -> None:
        self._config_manager = config_manager
        self._auth_service = auth_service
        self._on_state_change = on_state_change
        self._lock_path = lock_path or DEFAULT_LOCK_PATH
        # listener_factory overridable for tests — returns something with .run()
        # and .stop(), accepting on_connected / on_disconnected kwargs.
        self._listener_factory = listener_factory or self._default_listener_factory
        # Kept injectable because the control server opens a real loopback
        # socket.  Runtime defaults remain in LocalControlServer itself.
        self._control_server_factory = control_server_factory
        self._control_record_path = control_record_path
        self._control_timeout_seconds = control_timeout_seconds
        # ``None`` defers to the environment-configured cleanup deadline.
        self._cleanup_timeout_seconds = cleanup_timeout_seconds
        self._lock: RelayLock | None = None
        self._listener = None
        self._task: asyncio.Task | None = None
        self._control_server = None
        self._state: RelayState = RelayState.DISABLED
        # Why the last start() ended in ERROR, for the relay status screen.
        self._last_error: str | None = None
        # Optional reference to the running Textual app; used to resolve
        # ``providers_configured`` for the wire-format v1.0 handshake.
        self._app = app

    # --- public API ----------------------------------------------------------

    @property
    def state(self) -> RelayState:
        return self._state

    @property
    def last_error(self) -> str | None:
        """The reason the listener is in ERROR, when there is one to show.

        Messages name config keys and variables, never URLs.
        """
        return self._last_error if self._state is RelayState.ERROR else None

    @property
    def is_running(self) -> bool:
        """True when we own the lock and the listener task is live."""
        return self._lock is not None and self._task is not None and not self._task.done()

    @property
    def control_record_path(self):
        """Return the active control record path, if the server has started."""
        if self._control_server is None:
            return None
        return self._control_server.record_path

    def ensure_configured(self) -> bool:
        """Auto-fill missing relay URLs from the current API base, persist if changed.

        A fresh login leaves ``relay.{base_url, mercure_url}`` blank because
        the device-flow handshake only writes auth tokens — relay URLs are a
        separate config block. Without this helper, every new user sees a
        spurious "MCP relay URLs not configured" toast right after login.

        Idempotent: returns True (configured) when both URLs are already set
        or when derivation succeeds; returns False if the API base is
        unparseable or the config write fails. Any field already populated by
        the user is left untouched — we only fill empties.
        """
        config = self._config_manager.get()
        relay_cfg = config.relay
        if relay_cfg.base_url and relay_cfg.mercure_url:
            return True

        try:
            from servonaut.services.auth_service import _api_base
            api_base = _api_base()
            derived_base, derived_mercure = derive_relay_urls(api_base)
        except Exception as exc:  # noqa: BLE001 - optional auth-service boundary
            logger.warning("Could not derive relay URLs: %s", exc)
            return False

        # Only the derived values are logged: they come from the checked API
        # base. A value the user set may not have been checked yet and could
        # carry credentials, so it is never logged.
        filled = []
        if not relay_cfg.base_url:
            relay_cfg.base_url = derived_base
            filled.append(f"{RELAY_BASE_URL_KEY}={derived_base}")
        if not relay_cfg.mercure_url:
            relay_cfg.mercure_url = derived_mercure
            filled.append(f"{RELAY_MERCURE_URL_KEY}={derived_mercure}")

        try:
            self._config_manager.save(config)
        except Exception as exc:  # noqa: BLE001 - persistence implementation boundary
            logger.error("Failed to persist auto-derived relay URLs: %s", exc)
            return False

        logger.info("Auto-populated relay URLs from the API base: %s", " ".join(filled))
        return True

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
        try:
            validate_relay_urls(cfg.base_url, cfg.mercure_url)
        except EndpointOverrideError as exc:
            # Names the config key only; the listener would send tokens there.
            return StartResult(RelayState.ERROR, str(exc))

        owner = active_owner(self._lock_path)
        from servonaut.services.relay_lock import is_pid_alive
        if owner is not None and owner.mode == "bg" and is_pid_alive(owner.pid):
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
        the first heartbeat is accepted, via the ``on_connected`` hook. An
        ERROR outcome's message is kept as :attr:`last_error`.
        """
        result = await self._start()
        if result.state is RelayState.ERROR:
            self._last_error = result.message
        return result

    async def _start(self) -> StartResult:
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
        except RelayLockUnavailableError as e:
            logger.warning("Relay lock %s is unavailable: %s", self._lock_path, e)
            self._set_state(RelayState.ERROR)
            return StartResult(
                RelayState.ERROR, f"Could not open the relay lock ({e.strerror})."
            )

        try:
            self._listener = self._listener_factory(
                on_connected=self._handle_connected,
                on_disconnected=self._handle_disconnected,
                on_session_expired=self._handle_session_expired,
            )
        except ImportError as e:
            self._release_lock()
            self._set_state(RelayState.ERROR)
            return StartResult(RelayState.ERROR, str(e))
        except Exception as e:  # noqa: BLE001 - injected listener factory boundary
            self._release_lock()
            self._set_state(RelayState.ERROR)
            return StartResult(RelayState.ERROR, f"Failed to build listener: {e}")

        control_server = None
        startup_listener = self._listener
        startup_lock = self._lock
        try:
            control_server = self._build_control_server()
            self._control_server = control_server
            await control_server.start(self._release_for_handover)
        except asyncio.CancelledError:
            await self._settle_failed_startup(
                control_server, startup_listener, startup_lock, RelayState.STOPPED
            )
            raise
        except Exception:
            logger.exception("Could not start local relay control server")
            await self._settle_failed_startup(
                control_server, startup_listener, startup_lock, RelayState.ERROR
            )
            return StartResult(RelayState.ERROR, "Could not start local relay control.")

        # ``stop()`` may have run while the control server was binding. It
        # clears this reference before awaiting its close, so never schedule a
        # listener after shutdown has already won the lifecycle race.
        if self._control_server is not control_server or self._lock is None:
            await self._close_control_server(control_server)
            self._set_state(RelayState.STOPPED)
            return StartResult(RelayState.STOPPED, "Relay startup was stopped.")

        self._set_state(RelayState.CONNECTING)
        log_relay_event("starting", mode="tui",
                        client_id=getattr(self._listener, "client_id", None))
        self._task = asyncio.create_task(self._run_listener(), name="relay_manager_listener")
        return StartResult(RelayState.CONNECTING, "Connecting…")

    async def stop(
        self,
        *,
        grace_seconds: float = 2.0,
        close_control: bool = True,
    ) -> None:
        """Cancel the listener task, await it briefly, release the lock.

        Textual may cancel shutdown workers. Owned state is still torn down
        deterministically, then that cancellation is propagated to the caller.

        The asynchronous part is bounded: it gets ``grace_seconds`` plus the
        cleanup deadline, and if cut short the same again to unwind, so the
        worst case is 2 x (grace + cleanup deadline). Whatever happens there,
        the lock, task and listener captured when this call started are
        settled synchronously before it returns. A lifecycle started in the
        meantime is never touched.
        """
        control_server = self._control_server if close_control else None
        if close_control:
            self._control_server = None
        scope = _StopScope(lock=self._lock, task=self._task, listener=self._listener)
        try:
            await _complete_owned_cleanup(
                self._stop_owned_resources(
                    scope,
                    grace_seconds=grace_seconds,
                    control_server=control_server,
                ),
                timeout_seconds=grace_seconds + self._cleanup_deadline_seconds(),
            )
        except asyncio.TimeoutError:
            pass  # Already logged; the ``finally`` below settles this stop.
        finally:
            self._settle_stopped(scope)

    async def _stop_owned_resources(
        self,
        scope: _StopScope,
        *,
        grace_seconds: float,
        control_server,
    ) -> None:
        """Perform idempotent shutdown work, allowing cancellation to escape.

        The synchronous part sits in ``finally`` so that a cleanup deadline
        cancelling this coroutine still releases the lock and settles the
        state.
        """
        try:
            if control_server is not None:
                await self._close_control_server(control_server)
            await self._stop_listener_task(scope, grace_seconds)
        finally:
            self._settle_stopped(scope)

    async def _stop_listener_task(self, scope: _StopScope, grace_seconds: float) -> None:
        """Signal the listener, cancel its task and wait out the grace period.

        ``asyncio.wait`` neither re-cancels the task on timeout nor waits for
        it when this coroutine is itself cancelled, so a listener that
        ignores cancellation can delay the stop by ``grace_seconds`` at most.
        """
        task = scope.task
        self._signal_listener_stop(scope.listener)
        if task is None or task.done():
            return
        task.cancel()
        done, _ = await asyncio.wait((task,), timeout=grace_seconds)
        if not done:
            logger.warning("Relay listener did not stop within its grace period")
        elif not task.cancelled() and task.exception() is not None:
            logger.error(
                "Relay listener failed while stopping", exc_info=task.exception()
            )

    def _signal_listener_stop(self, listener) -> None:
        if listener is None:
            return
        try:
            listener.stop()
        except Exception:
            logger.exception("Could not stop relay listener")

    def _settle_stopped(self, scope: _StopScope) -> None:
        """Synchronously finish one stop; only the first call for a scope acts.

        Only objects captured in ``scope`` are released or cleared, so a stop
        that settles late cannot touch a lifecycle started after it.
        """
        if scope.settled:
            return
        scope.settled = True
        task = scope.task
        if task is not None and not task.done():
            # The bounded stop was cut short or the listener ignores cancellation.
            self._signal_listener_stop(scope.listener)
            task.cancel()
        superseded = (self._lock is not None and self._lock is not scope.lock) or (
            self._task is not None and self._task is not task
        )
        if superseded:
            return
        self._task = None
        if self._listener is scope.listener:
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
            logger.exception("Relay listener crashed")
            self._last_error = "The relay listener stopped unexpectedly; see the log."
            self._set_state(RelayState.ERROR)
            log_relay_event("error", mode="tui", reason=str(e)[:200])
            self._release_lock()
            control_server = self._control_server
            self._control_server = None
            if control_server is not None:
                await self._close_control_server(control_server)

    async def _release_for_handover(self) -> None:
        """Release the live TUI listener before the control success response.

        Raises when the lock is still held afterwards, so the requester is
        told the release failed instead of being acknowledged.
        """
        lock = self._lock
        await self.stop(close_control=False)
        if self._lock is not None or (lock is not None and lock.is_held):
            raise RuntimeError("The relay lock is still held")

    async def _rollback_control_startup(
        self,
        control_server,
        startup_listener,
        startup_lock,
        terminal_state: RelayState,
    ) -> None:
        """Close a partially-started endpoint and settle all matching state."""
        try:
            if control_server is not None:
                try:
                    await control_server.close()
                except Exception:
                    logger.exception("Could not roll back local relay control server")
        finally:
            owns_control = (
                control_server is not None
                and self._control_server is control_server
            )
            owns_listener = self._listener is startup_listener
            owns_lock = self._lock is startup_lock
            if owns_control:
                self._control_server = None
            if owns_listener:
                self._listener = None
            if owns_lock:
                self._release_lock()
            if owns_control or owns_listener or owns_lock:
                self._set_state(terminal_state)

    async def _settle_failed_startup(
        self,
        control_server,
        startup_listener,
        startup_lock,
        terminal_state: RelayState,
    ) -> None:
        """Roll back a failed start within the cleanup deadline.

        A deadline overrun is logged by the cleanup helper and must not
        replace the start outcome (its error result or its cancellation);
        the rollback settles the manager state in its own ``finally``.
        """
        try:
            await _complete_owned_cleanup(
                self._rollback_control_startup(
                    control_server,
                    startup_listener,
                    startup_lock,
                    terminal_state,
                ),
                timeout_seconds=self._cleanup_deadline_seconds(),
            )
        except asyncio.TimeoutError:
            pass

    async def _close_control_server(self, control_server) -> None:
        """Close the control server, logging instead of raising on failure."""
        try:
            await control_server.close()
        except Exception:
            logger.exception("Could not close local relay control server")

    def _cleanup_deadline_seconds(self) -> float:
        """The cleanup deadline, never shorter than this manager's control timeout."""
        if self._control_timeout_seconds is None:
            control_timeout = DEFAULT_CONTROL_TIMEOUT_SECONDS
        else:
            control_timeout = configured_control_timeout_seconds(self._control_timeout_seconds)
        return cleanup_deadline_seconds(self._cleanup_timeout_seconds, control_timeout)

    def _build_control_server(self):
        """Construct the local authenticated control server for this lifecycle."""
        kwargs = {}
        if self._control_record_path is not None:
            kwargs["record_path"] = self._control_record_path
        if self._control_timeout_seconds is not None:
            kwargs["timeout_seconds"] = self._control_timeout_seconds
        if self._cleanup_timeout_seconds is not None:
            kwargs["cleanup_timeout_seconds"] = self._cleanup_timeout_seconds
        if self._control_server_factory is not None:
            return self._control_server_factory(**kwargs)
        from servonaut.services.relay_control import LocalControlServer

        return LocalControlServer(**kwargs)

    async def _handle_connected(self) -> None:
        self._set_state(RelayState.CONNECTED)
        log_relay_event(
            "connected", mode="tui",
            client_id=getattr(self._listener, "client_id", None),
        )

    async def _handle_disconnected(self) -> None:
        """Listener teardown notice — log only; task-level handler sets the final state."""
        log_relay_event("disconnected", mode="tui")

    async def _handle_degraded(self) -> None:
        """Heartbeats keep being rejected although the session is valid.

        The listener keeps retrying, but the server is not delivering
        commands, so the indicator must stop claiming "connected". The
        status model has no separate degraded state; CONNECTING ("not yet
        accepted by the server") is the accurate one. The listener has
        already written the relay.log event, and its next accepted
        heartbeat fires ``on_connected``, which restores CONNECTED.
        """
        if self._state is RelayState.CONNECTED:
            self._set_state(RelayState.CONNECTING)

    async def notify_session_expired(self) -> None:
        """Public hook for any caller that sees a 401 from an API call.

        Routes through the same handler the heartbeat uses so the
        indicator flips immediately instead of waiting for the next
        heartbeat tick (~30s). Idempotent — once SESSION_EXPIRED is
        the current state subsequent calls no-op.

        A 401/403 alone does not prove the session is gone: a refresh
        that failed transiently (network error, 429, 5xx) or a 403 from
        something in front of the API leaves the session authenticated,
        and then this is a no-op.
        """
        auth = self._auth_service
        if auth is not None and auth.is_authenticated:
            logger.info("API call rejected but the session is still valid; relay kept")
            return
        await self._handle_session_expired()

    async def _handle_session_expired(self) -> None:
        """Backend rejected our OAuth bearer (401). Stop the listener,
        flip the indicator to a state that says "sign in again", and
        log the event so users debugging the silent-disconnect-after-
        token-expiry case can find the trail.

        Without this, the heartbeat would just log warnings forever
        while the indicator stayed green — the bug the user reported.
        """
        if self._state is RelayState.SESSION_EXPIRED:
            return
        log_relay_event("session_expired", mode="tui")
        # Stop the listener task FIRST so we don't keep hammering
        # /heartbeat with a known-bad bearer. ``stop()`` itself
        # transitions to STOPPED; the explicit re-set below ensures
        # the final settled state reflects "session expired" rather
        # than the generic disconnected-on-purpose state.
        try:
            await self.stop()
        except Exception:
            logger.exception("Failed to stop relay after session expired")
        finally:
            # ``stop()`` deliberately re-raises caller cancellation only
            # after its owned resources are settled.  The heartbeat callback
            # is one such caller, so establish the terminal auth state before
            # allowing that cancellation to propagate through RelayListener's
            # gather.
            self._set_state(RelayState.SESSION_EXPIRED)

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
                logger.exception("Could not release relay lock")
            self._lock = None

    def _default_listener_factory(
        self, *, on_connected, on_disconnected, on_session_expired=None,
    ):
        """Construct a RelayListener wired to the app's services."""
        from servonaut.services.relay_listener import (
            RelayListener,
            _resolve_providers_configured,
        )

        cfg = self._config_manager.get().relay
        auth = self._auth_service
        # Sanity check now so the user gets a clear error before the
        # listener spins up. The provider closure below re-reads on every
        # call so OAuth refresh-token rotations are picked up live.
        if not auth or not auth.access_token:
            raise RuntimeError("No OAuth token available.")
        user_id = _extract_user_id(auth)
        if not user_id:
            raise RuntimeError("Could not determine user id from auth service.")

        # Pass a callable, not the captured string, so the listener picks
        # up the rotated bearer on every heartbeat / mercure-token /
        # command-result POST. The previous snapshot-at-construction
        # approach caused 401s ~30 min into a session once the access
        # token rotated, which in turn let the server's 90s
        # cli_connected key expire and surfaced as "CLI not connected"
        # for tool dispatches.
        executors = _build_executors(self._config_manager)
        providers = _resolve_providers_configured(self._app)
        probe_bridge = self._build_probe_bridge(executors)
        return RelayListener(
            executors=executors,
            base_url=cfg.base_url,
            mercure_url=cfg.mercure_url,
            auth_token=lambda: auth.access_token,
            user_id=user_id,
            heartbeat_interval=cfg.heartbeat_interval,
            on_connected=on_connected,
            on_disconnected=on_disconnected,
            on_session_expired=on_session_expired,
            # Wired here rather than through the listener-factory hooks, so
            # a custom factory keeps the three-hook signature.
            on_degraded=self._handle_degraded,
            heartbeat_rejection_alert_after=cfg.heartbeat_rejection_alert_after,
            # The listener owns its own httpx.AsyncClient (needs to —
            # the SSE subscription holds it open). Hand it the refresh
            # path so a locally-stale access_token on heartbeat doesn't
            # surface as a phantom "session expired" before refresh has
            # had a chance to rotate the bearer.
            refresh_callback=auth.refresh_token,
            # Only a session that is really gone expires the relay; a
            # transient refresh failure leaves it authenticated.
            session_alive=lambda: auth.is_authenticated,
            providers_configured=providers,
            probe_bridge=probe_bridge,
        )

    def _build_probe_bridge(self, executors):
        """Build the proactive-probe bridge for the TUI's listener.

        Unlike chat tool calls (skipped in TUI mode — the chat panel
        executes its own), monitoring probes MUST be answered by the
        TUI's in-process listener too: the user pressed Scan Now in the
        TUI and reasonably expects it to work without a separate
        headless `servonaut connect`. The bridge uses the fixed probe
        policy (readonly + in-DB introspection, never a prompt) and
        tags audit rows source="proactive". Returns None when the
        collaborators aren't wired yet (free / unauthenticated boot) —
        the listener then answers probes with a structured error.
        """
        try:
            from servonaut.mcp.audit import AuditTrail
            from servonaut.services.ai_tool_bridge import AIToolBridge
            from servonaut.services.relay_listener import build_probe_confirm

            app = self._app
            api_client = getattr(app, "api_client", None)
            auth = self._auth_service
            if api_client is None or auth is None:
                return None
            cfg_all = self._config_manager.get()
            return AIToolBridge(
                api_client=api_client,
                relay_executors=executors,
                mcp_audit=AuditTrail(cfg_all.mcp.audit_path),
                confirm_callback=build_probe_confirm(),
                auth_service=auth,
                servonaut_tools=getattr(app, "servonaut_tools", None),
                ip_ban_service=getattr(app, "ip_ban_service", None),
                audit_source="proactive",
            )
        except Exception as exc:  # noqa: BLE001 — probes degrade to errors
            logger.debug("Probe bridge init skipped: %s", exc)
            return None


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


def _extract_user_id(auth_service) -> str | None:
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
    from servonaut.services.aws_service import AWSService
    from servonaut.services.cache_service import CacheService
    from servonaut.services.connection_service import ConnectionService
    from servonaut.services.custom_server_service import CustomServerService
    from servonaut.services.relay_executors import RelayExecutors
    from servonaut.services.scp_service import SCPService
    from servonaut.services.ssh_service import SSHService
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
