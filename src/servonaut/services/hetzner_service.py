"""Hetzner Cloud instance fetching + lifecycle service.

Mirrors :class:`servonaut.services.ovh_service.OVHService` in shape:

* Lazy client init via :meth:`_get_client` so the SDK ``hcloud`` import
  is deferred until the user actually exercises Hetzner.
* Async ``fetch_instances`` + ``fetch_instances_cached`` so the TUI can
  schedule it on a Textual worker without blocking the UI thread.
* Sync ``get_cached_instances`` for instant render on app startup
  (matches OVH at ``ovh_service.py:148``).
* On-disk JSON cache at ``~/.servonaut/hetzner_cache.json`` written
  with ``0o600`` permissions (mirrors :func:`OVHService._save_cache`).

Where Hetzner /diverges/ from OVH: it ships full lifecycle (create +
delete server, create SSH key) which OVH on Servonaut does not. The
mutating methods all log to a JSONL audit file at
``config.hetzner.audit_path`` so operators have a tamper-evident trail
of who-spun-up-what without depending on the generic MCP audit.

Token resolution chain (highest priority first), per
:class:`HetznerConfig` doc-string:

1. ``config.hetzner.api_token`` (with ``$ENV_VAR`` / ``file:`` resolution).
2. ``$HCLOUD_TOKEN`` environment variable.
3. ``~/.config/hcloud/token`` file fallback.

If none of those resolve to a non-empty string, the lazy client init
raises :exc:`HetznerNotConfiguredError` — callers (CLI, MCP tools)
catch this and surface a clean "configure Hetzner first" message
instead of leaking a hcloud-internal exception.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from servonaut.config.secrets import resolve_secret

if TYPE_CHECKING:
    from servonaut.config.schema import HetznerConfig

logger = logging.getLogger(__name__)

# The canonical place ``hcloud`` CLI writes its bearer token to. The
# Servonaut TUI's "Connect Hetzner" wizard hints at this path so users
# who already use hcloud's CLI get zero-config token discovery.
_HCLOUD_DEFAULT_TOKEN_FILE = Path.home() / '.config' / 'hcloud' / 'token'

# Hetzner names: ASCII alphanumeric + dot/dash/underscore. Must START with
# an alphanumeric (Hetzner rejects leading dot/dash/underscore).
_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$')


class HetznerError(Exception):
    """Base class for Hetzner-provider errors raised by this service."""


class HetznerNotConfiguredError(HetznerError):
    """Raised when no API token is configured anywhere in the resolution chain."""


class HetznerSDKMissingError(HetznerError):
    """Raised when the optional ``hcloud`` Python SDK is not installed."""


# Map Hetzner Cloud server statuses to the common Servonaut state vocab
# (running / stopped / pending / error / unknown). Reference:
# https://docs.hetzner.cloud/#servers — ``status`` enum.
_STATUS_MAP: Dict[str, str] = {
    'initializing': 'pending',
    'starting': 'pending',
    'running': 'running',
    'stopping': 'stopped',
    'off': 'stopped',
    'deleting': 'pending',
    'rebuilding': 'pending',
    'migrating': 'pending',
    'unknown': 'unknown',
}


def _validate_resource_name(name: str, kind: str = 'resource') -> str:
    """Reject obviously malformed resource names before any API call.

    Hetzner Cloud already enforces server-side validation, but we filter
    upfront to (a) give a faster error path, and (b) avoid leaking the
    raw input back into log lines / audit rows when an attacker tries
    to smuggle control characters through.

    Args:
        name: Caller-supplied resource name (server, SSH key).
        kind: Human-readable label used in the error message.

    Returns:
        The validated name unchanged.

    Raises:
        ValueError: If the name violates the allowed character set.
    """
    if not isinstance(name, str) or not name:
        raise ValueError(f"{kind} name must be a non-empty string")
    if not _NAME_RE.match(name):
        raise ValueError(
            f"Invalid {kind} name: {name!r}. Allowed: ASCII alphanumerics, "
            f"dot, dash, underscore (1-253 chars)."
        )
    return name


class HetznerService:
    """Service for Hetzner Cloud instances + lifecycle (create / destroy)."""

    def __init__(self, config: 'HetznerConfig') -> None:
        """Initialise the Hetzner service.

        Args:
            config: HetznerConfig dataclass instance.
        """
        self._config = config
        self._client = None  # lazy
        self._cache_path = Path(os.path.expanduser(config.cache_path)).resolve()
        self._cache_ttl_seconds = max(int(config.cache_ttl_seconds), 0)

    # ------------------------------------------------------------------
    # Token resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _read_token_file(path: Path) -> str:
        """Read a token from ``path`` and strip surrounding whitespace.

        Returns an empty string on any read error so the resolver moves
        on to the next chain step instead of crashing.
        """
        try:
            return path.read_text().strip()
        except OSError:
            return ''

    def resolve_token(self) -> str:
        """Resolve the active API token from config / env / file.

        Order of precedence (highest first) — see ``HetznerConfig``
        docstring for rationale.

        Returns:
            The first non-empty token found.

        Raises:
            HetznerNotConfiguredError: If no chain step yields a token.
        """
        from_config = resolve_secret(self._config.api_token)
        if from_config:
            return from_config

        from_env = os.environ.get('HCLOUD_TOKEN', '')
        if from_env:
            return from_env

        from_file = self._read_token_file(_HCLOUD_DEFAULT_TOKEN_FILE)
        if from_file:
            return from_file

        raise HetznerNotConfiguredError(
            "No Hetzner Cloud API token configured. Set "
            "config.hetzner.api_token in ~/.servonaut/config.json, "
            "export HCLOUD_TOKEN, or write the token to "
            "~/.config/hcloud/token."
        )

    # ------------------------------------------------------------------
    # Client init
    # ------------------------------------------------------------------

    def _get_client(self):
        """Lazy-initialise the hcloud client with the resolved token.

        Returns:
            ``hcloud.Client`` instance.

        Raises:
            HetznerSDKMissingError: If ``hcloud`` is not installed.
            HetznerNotConfiguredError: If token resolution fails.
        """
        if self._client is not None:
            return self._client

        try:
            from hcloud import Client
        except ModuleNotFoundError as exc:
            raise HetznerSDKMissingError(
                "hcloud is not installed. "
                "Install with: pip install 'servonaut[hetzner]'"
            ) from exc
        except ImportError as exc:
            # The package is installed but a transitive import broke —
            # don't lie to the user about which thing is missing.
            raise HetznerSDKMissingError(
                f"hcloud import failed (likely a broken dependency): {exc}"
            ) from exc

        token = self.resolve_token()
        self._client = Client(
            token=token,
            application_name="servonaut",
            # We can't import the runtime version safely at module load
            # (would fail on editable installs without metadata), so we
            # set application_version conservatively here.
            application_version="0",
        )
        return self._client

    # Public access for callers (tests, MCP tools) that want the raw
    # client. Lazy init still applies.
    @property
    def client(self):
        return self._get_client()

    # ------------------------------------------------------------------
    # Instance fetching
    # ------------------------------------------------------------------

    async def fetch_instances(self) -> List[dict]:
        """Fetch all Hetzner Cloud servers as Servonaut instance dicts.

        Returns:
            List of instance dicts compatible with ``app.instances``.

        Raises:
            HetznerError: On any API failure. (Earlier revisions of this
                method swallowed transient errors and returned ``[]`` —
                that caused empty-list pollution of the on-disk cache,
                freezing the fleet view to "0 servers" for the full TTL.
                We now propagate so :meth:`fetch_instances_cached` can
                decide whether to keep the previous cache or surface the
                error to the UI.)
        """
        try:
            servers = await asyncio.to_thread(self._fetch_servers_blocking)
        except HetznerError:
            raise
        except Exception as exc:
            raise HetznerError(
                f"Failed to fetch Hetzner servers: {exc}"
            ) from exc

        return [self._server_to_dict(s) for s in servers]

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Fetch instances, consulting the on-disk cache first.

        On API failure, the previous cache (if any, regardless of TTL)
        is returned to preserve the operator's last good fleet view —
        true stale-while-revalidate semantics. Only on a successful
        fetch do we overwrite the cache. Callers that need to surface
        fetch errors should call :meth:`fetch_instances` directly.

        Args:
            force_refresh: If True, bypass the cache.
        """
        if not force_refresh:
            cached = self._load_cache()
            if cached is not None:
                logger.debug("Using cached Hetzner instances")
                return cached

        try:
            instances = await self.fetch_instances()
        except HetznerError as exc:
            # Don't poison the cache — keep the previous good entries.
            stale = self._load_cache(ignore_ttl=True)
            if stale is not None:
                logger.warning(
                    "Hetzner fetch failed (%s); falling back to stale cache "
                    "of %d server(s).", exc, len(stale),
                )
                return stale
            raise

        self._save_cache(instances)
        return instances

    def get_cached_instances(self) -> List[dict]:
        """Return whatever is in the cache, regardless of TTL (sync).

        Returns:
            List of instance dicts, or empty list if no cache exists.
        """
        cached = self._load_cache(ignore_ttl=True)
        return cached if cached is not None else []

    def is_cache_fresh(self) -> bool:
        """Whether the on-disk cache is within TTL."""
        if not self._cache_path.exists():
            return False
        try:
            data = json.loads(self._cache_path.read_text())
            ts = data.get('timestamp')
            if not ts:
                return False
            age = datetime.now() - datetime.fromisoformat(ts)
            return age < timedelta(seconds=self._cache_ttl_seconds)
        except (OSError, ValueError):
            return False

    # ------------------------------------------------------------------
    # Lifecycle: create / delete servers
    # ------------------------------------------------------------------

    async def create_server(
        self,
        name: str,
        server_type: Optional[str] = None,
        image: Optional[str] = None,
        location: Optional[str] = None,
        ssh_keys: Optional[List[str]] = None,
        labels: Optional[Dict[str, str]] = None,
        wait_until_running: bool = True,
        wait_timeout_seconds: int = 90,
        allow_no_ssh_keys: bool = False,
    ) -> dict:
        """Create a Hetzner Cloud server.

        Args:
            name: Server name. Validated against
                ``[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}`` (Hetzner rejects
                names that start with a dot/hyphen/underscore) before
                any network call.
            server_type: Server-type name (e.g. ``cx23``). Falls back
                to ``config.hetzner.default_server_type``.
            image: Image name (e.g. ``ubuntu-22.04``) or numeric image
                ID (for snapshots/backups). Falls back to
                ``config.hetzner.default_image``.
            location: Datacentre location (``fsn1``/``nbg1``/``hel1``/
                ``ash``/``hil``). Falls back to
                ``config.hetzner.default_location``.
            ssh_keys: SSH key names or numeric IDs (passed as strings)
                to inject. Falls back to
                ``config.hetzner.default_hetzner_ssh_key`` when empty.
            labels: Optional Hetzner labels for the server.
            wait_until_running: If True, poll until the server reports
                ``running`` status before returning. Recommended so the
                first ``servonaut connect`` after create just works.
            wait_timeout_seconds: Bound for the wait above.
            allow_no_ssh_keys: Override the default refusal to create a
                server without any SSH keys. When ``False`` (default)
                AND ``config.require_ssh_keys_on_create`` is True AND
                no keys are resolvable, a ``HetznerError`` is raised
                BEFORE the network call. Hetzner would otherwise spawn
                a server with a random root password emitted in the
                response that the CLI discards — leaving a billed
                unreachable box.

        Returns:
            The new server as a Servonaut instance dict (matches the
            shape used by ``fetch_instances``).

        Raises:
            ValueError: On malformed name.
            HetznerError: Wraps any hcloud API failure, the
                no-SSH-keys footgun guard, and the post-create wait
                timeout. EVERY raise path writes a failure audit row
                first.
        """
        # ---- validation phase (audited) ----
        try:
            _validate_resource_name(name, kind='server')
        except ValueError as exc:
            self._audit(
                'create_server', name, success=False,
                reason=f"validation: {exc}",
            )
            raise

        server_type_name = server_type or self._config.default_server_type
        image_name = image or self._config.default_image
        location_name = location or self._config.default_location

        if not server_type_name or not image_name:
            self._audit(
                'create_server', name, success=False,
                reason="missing server_type or image (no default configured)",
            )
            raise ValueError(
                "server_type and image are required (no default configured)"
            )

        try:
            from hcloud.server_types.domain import ServerType
            from hcloud.images.domain import Image
            from hcloud.locations.domain import Location
        except ImportError as exc:
            self._audit(
                'create_server', name, success=False,
                reason="sdk_missing",
            )
            raise HetznerSDKMissingError(
                "hcloud is not installed. "
                "Install with: pip install 'servonaut[hetzner]'"
            ) from exc

        # ---- SSH key resolution (audited on failure) ----
        try:
            ssh_key_objs = await asyncio.to_thread(
                self._resolve_ssh_keys, ssh_keys
            )
        except HetznerError as exc:
            self._audit(
                'create_server', name, success=False,
                reason=f"ssh_key_resolution_failed: {exc}",
            )
            raise

        if (not ssh_key_objs and not allow_no_ssh_keys
                and self._config.require_ssh_keys_on_create):
            self._audit(
                'create_server', name, success=False,
                reason="refused: no ssh keys configured (footgun guard)",
            )
            raise HetznerError(
                "Refusing to create a Hetzner server without SSH keys. "
                "Hetzner would assign a random root password we cannot "
                "recover, leaving the server billed but unreachable. "
                "Pass --ssh-key NAME or set "
                "config.hetzner.default_hetzner_ssh_key. "
                "If you intentionally want a key-less server, "
                "set config.hetzner.require_ssh_keys_on_create=false "
                "or pass allow_no_ssh_keys=True."
            )

        # Image lookup: digit-only → numeric ID (for snapshots/backups);
        # otherwise → name lookup (for stock images like ubuntu-22.04).
        image_arg = (
            Image(id=int(image_name))
            if image_name.isdigit()
            else Image(name=image_name)
        )

        def _do_create():
            client = self._get_client()
            response = client.servers.create(
                name=name,
                server_type=ServerType(name=server_type_name),
                image=image_arg,
                location=Location(name=location_name) if location_name else None,
                ssh_keys=ssh_key_objs or None,
                labels=labels,
                start_after_create=True,
            )
            return response

        try:
            response = await asyncio.to_thread(_do_create)
        except Exception as exc:
            # Truncate the upstream message to bound how much
            # SDK-supplied text lands in the audit row (the message can
            # include public-key fragments / fingerprints from "key
            # already exists"-style errors).
            self._audit(
                'create_server', name, success=False,
                reason=f"api_error: {str(exc)[:200]}",
            )
            raise HetznerError(f"Failed to create server {name!r}: {exc}") from exc

        server = response.server
        if wait_until_running:
            try:
                server = await self._wait_until_running(
                    server.id, timeout_seconds=wait_timeout_seconds
                )
            except HetznerError as exc:
                # Server was created but never became reachable; don't
                # leave the user without a remediation path.
                self._audit(
                    'create_server', name, success=False,
                    reason=f"created but not reachable: {exc}",
                    server_id=server.id,
                )
                raise

        # Bust the local cache so the next list reflects the new server.
        self._invalidate_cache()
        self._audit(
            'create_server', name, success=True,
            server_id=server.id, server_type=server_type_name,
            image=image_name, location=location_name,
        )
        return self._server_to_dict(server)

    async def delete_server(self, identifier: str) -> bool:
        """Delete a Hetzner Cloud server by ID or name.

        Args:
            identifier: Numeric server ID (as a string) or server name.
                Validated against the same character class as
                :func:`_validate_resource_name` to prevent log/audit
                injection from upstream agent payloads. Numeric IDs
                bypass the name regex.

        Returns:
            True on success.

        Raises:
            ValueError: On malformed identifier.
            HetznerError: Wraps any hcloud API failure (incl. not-found).
                Every raise path writes a failure audit row first.
        """
        # Cheap input validation — write an audit row even on rejection
        # so the forensic trail captures the attempt.
        if not isinstance(identifier, str) or not identifier:
            self._audit(
                'delete_server', str(identifier), success=False,
                reason='validation: empty or non-string identifier',
            )
            raise ValueError("identifier must be a non-empty string")
        if not (identifier.isdigit() or _NAME_RE.match(identifier)):
            self._audit(
                'delete_server', identifier, success=False,
                reason='validation: invalid identifier shape',
            )
            raise ValueError(
                f"Invalid identifier shape: {identifier!r}. "
                "Expected a numeric ID or a Hetzner name "
                "([a-zA-Z0-9][a-zA-Z0-9._-]{0,252})."
            )

        def _do_delete():
            client = self._get_client()
            server = self._lookup_server_blocking(client, identifier)
            if server is None:
                raise HetznerError(f"Server not found: {identifier}")
            return client.servers.delete(server)

        try:
            await asyncio.to_thread(_do_delete)
        except HetznerError as exc:
            self._audit(
                'delete_server', identifier, success=False,
                reason=str(exc)[:200],
            )
            raise
        except Exception as exc:
            self._audit(
                'delete_server', identifier, success=False,
                reason=f"api_error: {str(exc)[:200]}",
            )
            raise HetznerError(
                f"Failed to delete server {identifier!r}: {exc}"
            ) from exc

        self._invalidate_cache()
        self._audit('delete_server', identifier, success=True)
        return True

    # ------------------------------------------------------------------
    # SSH keys
    # ------------------------------------------------------------------

    async def list_ssh_keys(self) -> List[dict]:
        """List SSH keys registered with Hetzner Cloud.

        Returns:
            List of dicts: ``{id, name, fingerprint, public_key, labels}``.
        """
        def _do():
            client = self._get_client()
            return client.ssh_keys.get_all()

        keys = await asyncio.to_thread(_do)
        return [
            {
                'id': str(k.id),
                'name': k.name,
                'fingerprint': k.fingerprint or '',
                'public_key': k.public_key or '',
                'labels': dict(k.labels or {}),
            }
            for k in keys
        ]

    async def create_ssh_key(self, name: str, public_key: str) -> dict:
        """Register a new SSH public key with Hetzner Cloud.

        Args:
            name: Display name for the key.
            public_key: Full public-key text (e.g. ``ssh-ed25519 AAA...``).
        """
        try:
            _validate_resource_name(name, kind='SSH key')
        except ValueError as exc:
            self._audit(
                'create_ssh_key', name, success=False,
                reason=f"validation: {exc}",
            )
            raise

        public_key = (public_key or '').strip()
        if not public_key.startswith(('ssh-', 'ecdsa-', 'sk-')):
            self._audit(
                'create_ssh_key', name, success=False,
                reason='validation: public_key prefix mismatch',
            )
            raise ValueError(
                "public_key must start with an SSH key type prefix "
                "(e.g. 'ssh-ed25519 AAA...')"
            )

        def _do():
            client = self._get_client()
            return client.ssh_keys.create(name=name, public_key=public_key)

        try:
            key = await asyncio.to_thread(_do)
        except Exception as exc:
            # Truncate to bound how much SDK-supplied error text (which
            # can include public-key fingerprints / fragments on
            # already-exists errors) lands in the audit row.
            self._audit(
                'create_ssh_key', name, success=False,
                reason=f"api_error: {exc.__class__.__name__}: {str(exc)[:160]}",
            )
            raise HetznerError(
                f"Failed to register SSH key {name!r}: {exc}"
            ) from exc

        self._audit('create_ssh_key', name, success=True, key_id=key.id)
        return {
            'id': str(key.id),
            'name': key.name,
            'fingerprint': key.fingerprint or '',
        }

    # ------------------------------------------------------------------
    # Server types
    # ------------------------------------------------------------------

    async def list_server_types(self) -> List[dict]:
        """List Hetzner Cloud server types and their hourly prices.

        Returns:
            List of dicts: ``{id, name, description, cores, memory_gb,
            disk_gb, architecture, hourly_price_eur, monthly_price_eur,
            currency}``. Prices use the first per-location entry — a
            normalisation; per-location prices are nearly identical
            within a region group anyway.
        """
        def _do():
            client = self._get_client()
            return client.server_types.get_all()

        types = await asyncio.to_thread(_do)
        out: List[dict] = []
        for t in types:
            hourly_price = ''
            monthly_price = ''
            prices = t.prices or []
            if prices:
                first = prices[0] or {}
                price_hourly = first.get('price_hourly') or {}
                price_monthly = first.get('price_monthly') or {}
                hourly_price = self._format_price(price_hourly.get('gross'), 4)
                monthly_price = self._format_price(price_monthly.get('gross'), 2)
            out.append({
                'id': str(t.id),
                'name': t.name,
                'description': t.description or '',
                'cores': t.cores or 0,
                'memory_gb': t.memory or 0,
                'disk_gb': t.disk or 0,
                'architecture': t.architecture or '',
                'hourly_price_gross': hourly_price,
                'monthly_price_gross': monthly_price,
                # Hetzner Cloud bills in EUR globally (the API does not
                # surface per-location currency because there is none —
                # all locations, including ash/hil in the US, bill in
                # EUR). We tag the dict with EUR so downstream callers
                # don't have to guess.
                'currency': 'EUR',
            })
        return out

    @staticmethod
    def _format_price(value: Any, decimals: int) -> str:
        """Format a Hetzner gross-price string to a readable decimal.

        Hetzner returns prices as overspecified strings like
        ``"0.0115200000000000"``. Cast through float to drop trailing
        zeros, then quantise to ``decimals`` places. Returns ``""`` when
        the input is missing or unparseable so the caller can show ``-``.
        """
        if value is None or value == '':
            return ''
        try:
            return f"{float(value):.{decimals}f}"
        except (TypeError, ValueError):
            return ''

    # ------------------------------------------------------------------
    # Locations & images (read-only; used by the Create-server wizard)
    # ------------------------------------------------------------------

    async def list_locations(self) -> List[dict]:
        """List Hetzner Cloud datacentre locations.

        Returns:
            List of dicts: ``{id, name, description, country, city,
            network_zone}``.
        """
        def _do():
            client = self._get_client()
            return client.locations.get_all()

        locations = await asyncio.to_thread(_do)
        return [
            {
                'id': str(loc.id),
                'name': loc.name or '',
                'description': loc.description or '',
                'country': loc.country or '',
                'city': loc.city or '',
                'network_zone': loc.network_zone or '',
            }
            for loc in locations
        ]

    async def list_images(
        self, architecture: Optional[str] = None,
    ) -> List[dict]:
        """List Hetzner Cloud stock OS images.

        Args:
            architecture: Optional ``"x86"`` or ``"arm"`` filter — passed
                straight through to the SDK so the API does the work.
                ARM server types only boot ARM images, so the wizard
                filters by the selected server type's architecture to
                avoid surfacing a guaranteed-failure image pick.

        Returns:
            List of dicts: ``{id, name, description, os_flavor,
            os_version, architecture}``. Only ``type=system`` images
            are returned — snapshots and backups are intentionally
            excluded from the wizard surface.
        """
        def _do():
            client = self._get_client()
            kwargs: Dict[str, Any] = {'type': ['system']}
            if architecture:
                kwargs['architecture'] = [architecture]
            return client.images.get_all(**kwargs)

        try:
            images = await asyncio.to_thread(_do)
        except TypeError:
            # Older hcloud-python releases (<1.30) lack the
            # ``architecture`` kwarg on get_all. Retry without the
            # filter and fall back to client-side filtering.
            def _do_legacy():
                client = self._get_client()
                return client.images.get_all(type=['system'])
            images = await asyncio.to_thread(_do_legacy)
            if architecture:
                images = [
                    i for i in images
                    if (getattr(i, 'architecture', '') or '') == architecture
                ]

        out: List[dict] = []
        for img in images:
            out.append({
                'id': str(img.id),
                'name': img.name or '',
                'description': img.description or '',
                'os_flavor': getattr(img, 'os_flavor', '') or '',
                'os_version': getattr(img, 'os_version', '') or '',
                'architecture': getattr(img, 'architecture', '') or '',
            })
        return out

    # ------------------------------------------------------------------
    # Connection test (used by Settings UI / smoke test)
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Validate the API token by calling a cheap read-only endpoint.

        Returns:
            ``{success: bool, message: str, server_count: Optional[int]}``.
        """
        def _do():
            client = self._get_client()
            return client.servers.get_all()

        try:
            servers = await asyncio.to_thread(_do)
        except (HetznerNotConfiguredError, HetznerSDKMissingError) as exc:
            return {'success': False, 'message': str(exc), 'server_count': None}
        except Exception as exc:
            return {
                'success': False,
                'message': f"Authentication failed: {exc}",
                'server_count': None,
            }
        return {
            'success': True,
            'message': f"Connected. {len(servers)} server(s) in project.",
            'server_count': len(servers),
        }

    # ------------------------------------------------------------------
    # Internal — blocking helpers
    # ------------------------------------------------------------------

    def _fetch_servers_blocking(self) -> List[Any]:
        client = self._get_client()
        return client.servers.get_all()

    def _lookup_server_blocking(self, client, identifier: str):
        # Numeric → ID lookup; string → name lookup. Hetzner server
        # IDs are always integer — try int parse first to keep the
        # dispatch unambiguous and avoid a name match that happens to
        # be all digits.
        if identifier.isdigit():
            try:
                return client.servers.get_by_id(int(identifier))
            except Exception:
                return None
        try:
            return client.servers.get_by_name(identifier)
        except Exception:
            return None

    def _resolve_ssh_keys(self, requested: Optional[List[str]]) -> List[Any]:
        """Resolve a list of name-or-ID strings to bound SSH key objects.

        Empty / unset list → fall back to
        ``config.hetzner.default_hetzner_ssh_key``.
        Each resolution failure raises ``HetznerError`` with the offending
        identifier so the user can fix the typo before paying for a
        server that comes up without their key.
        """
        client = self._get_client()
        names = list(requested or [])
        if not names and self._config.default_hetzner_ssh_key:
            names = [self._config.default_hetzner_ssh_key]
        if not names:
            # Hetzner /will/ create a server without keys — root_password
            # is emitted in the response — but the create_server caller
            # has its own footgun guard above. Just return [] here.
            return []
        resolved: List[Any] = []
        for ident in names:
            ident = (ident or '').strip()
            if not ident:
                continue
            obj = None
            if ident.isdigit():
                try:
                    obj = client.ssh_keys.get_by_id(int(ident))
                except Exception:
                    obj = None
            if obj is None:
                try:
                    obj = client.ssh_keys.get_by_name(ident)
                except Exception:
                    obj = None
            if obj is None:
                raise HetznerError(
                    f"SSH key not found: {ident!r}. List with "
                    f"'servonaut hetzner ssh-keys list' or register one with "
                    f"'servonaut hetzner ssh-keys add'."
                )
            resolved.append(obj)
        return resolved

    async def _wait_until_running(self, server_id: int, timeout_seconds: int) -> Any:
        """Poll the server until status is 'running' or the timeout elapses."""
        deadline = time.monotonic() + max(timeout_seconds, 1)
        last_status = ''
        while time.monotonic() < deadline:
            def _refresh():
                client = self._get_client()
                return client.servers.get_by_id(server_id)
            try:
                server = await asyncio.to_thread(_refresh)
            except Exception as exc:
                raise HetznerError(
                    f"Could not refresh server {server_id} status: {exc}"
                ) from exc
            last_status = server.status or 'unknown'
            if last_status == 'running':
                return server
            await asyncio.sleep(2.0)
        raise HetznerError(
            f"Timed out waiting for server {server_id} to reach 'running' "
            f"(last status: {last_status})"
        )

    # ------------------------------------------------------------------
    # Internal — instance-dict shaping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_status(status: str) -> str:
        return _STATUS_MAP.get(status or 'unknown', status or 'unknown')

    def _server_to_dict(self, server: Any) -> dict:
        """Convert a hcloud BoundServer to the Servonaut instance shape.

        Sticks to scalar fields the rest of the app already consumes
        (``id``, ``name``, ``type``, ``state``, ``public_ip``, ...) so
        any screen that already renders AWS/OVH instances can render a
        Hetzner instance without code changes.
        """
        ipv4 = ''
        try:
            if server.public_net and server.public_net.ipv4:
                ipv4 = server.public_net.ipv4.ip or ''
        except AttributeError:
            ipv4 = ''

        location_name = ''
        try:
            if server.datacenter and server.datacenter.location:
                location_name = server.datacenter.location.name or ''
        except AttributeError:
            pass

        type_name = ''
        try:
            if server.server_type:
                type_name = server.server_type.name or ''
        except AttributeError:
            pass

        created_at = ''
        try:
            if server.created:
                created_at = server.created.isoformat()
        except AttributeError:
            pass

        labels = {}
        try:
            labels = dict(server.labels or {})
        except (AttributeError, TypeError):
            pass

        return {
            'id': str(server.id),
            'name': server.name or '',
            'type': type_name,
            'state': self._map_status(getattr(server, 'status', '') or ''),
            'public_ip': ipv4,
            'private_ip': '',
            'region': location_name,
            'key_name': '',
            'provider': 'hetzner',
            'is_hetzner': True,
            'username': self._config.default_username or 'root',
            # Local SSH-key path used by ``ssh -i`` when connecting to
            # the server. Stored as a literal string (NOT
            # resolve_secret-processed) so we never accidentally
            # dereference a ``file:`` prefix and put private-key
            # contents into the instance dict — which would then be
            # logged by SSH-connect handlers.
            'ssh_key': self._config.default_local_ssh_key or '',
            'owned_by_servonaut': True,
            'disposable': True,
            'created_at': created_at,
            'labels': labels,
        }

    # ------------------------------------------------------------------
    # Cache (file backed, 0o600)
    # ------------------------------------------------------------------

    def _load_cache(self, ignore_ttl: bool = False) -> Optional[List[dict]]:
        if not self._cache_path.exists():
            return None
        try:
            data = json.loads(self._cache_path.read_text())
        except (OSError, ValueError) as exc:
            logger.debug("Hetzner cache unreadable: %s", exc)
            return None

        ts = data.get('timestamp')
        instances = data.get('instances')
        if ts is None or instances is None:
            return None
        if not ignore_ttl:
            try:
                age = datetime.now() - datetime.fromisoformat(ts)
            except ValueError:
                return None
            if age >= timedelta(seconds=self._cache_ttl_seconds):
                return None
        return instances

    def _save_cache(self, instances: List[dict]) -> None:
        """Atomically write the cache: write to ``<path>.tmp`` then rename.

        Atomicity matters because :meth:`_load_cache` may run
        concurrently from another worker / sub-process. A non-atomic
        truncate-then-write would briefly expose an empty / partial
        JSON file. ``os.replace`` is atomic on POSIX and Windows for
        same-filesystem renames.

        File mode is forced to ``0o600`` via ``os.open`` to bypass
        umask (which could be 0o022 by default), and ``O_NOFOLLOW`` to
        defeat symlink-redirect attacks against the cache path.
        """
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'timestamp': datetime.now().isoformat(),
                'instances': instances,
            }
            tmp_path = self._cache_path.with_suffix(
                self._cache_path.suffix + '.tmp',
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(tmp_path), flags, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(str(tmp_path), str(self._cache_path))
        except OSError as exc:
            logger.warning("Failed to save Hetzner cache: %s", exc)

    def _invalidate_cache(self) -> None:
        try:
            self._cache_path.unlink(missing_ok=True)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Audit (JSONL, 0o600)
    # ------------------------------------------------------------------

    def _audit(
        self, action: str, target: str,
        *, success: bool, **fields: Any,
    ) -> None:
        """Append a JSONL audit row for a mutating operation.

        Fail-soft: audit write errors are logged but never raised, so a
        full disk doesn't block a delete that the user asked for.
        """
        path = Path(os.path.expanduser(self._config.audit_path))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            row = {
                'timestamp': datetime.now().isoformat(),
                'action': action,
                'target': target,
                'success': bool(success),
                **fields,
            }
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW
            fd = os.open(str(path), flags, 0o600)
            with os.fdopen(fd, 'a') as f:
                f.write(json.dumps(row, default=str) + '\n')
        except OSError as exc:
            logger.warning("Failed to write Hetzner audit row: %s", exc)
