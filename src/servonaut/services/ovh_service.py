"""OVHcloud instance fetching service with caching support."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

from servonaut.config.secrets import resolve_secret
from servonaut.utils.atomic_file import write_json_atomic

if TYPE_CHECKING:
    from servonaut.config.schema import OVHConfig

logger = logging.getLogger(__name__)

_OVH_CACHE_PATH = Path.home() / '.servonaut' / 'ovh_cache.json'
_OVH_CACHE_TTL_SECONDS = 300  # 5 minutes


class OVHFetchError(Exception):
    """Raised when no enabled OVH resource type could be listed.

    Separates "OVH answered with zero instances" (a valid, cacheable result)
    from "every call failed" (revoked key, network), so a failed refresh is
    never persisted as an empty fleet.
    """

# OVH does not reliably raise the specific ``InvalidCredential`` subclass —
# a revoked or expired key surfaces as a plain ``APIError`` whose message
# text is the only stable signal. Match on substrings, not exception class.
_OVH_AUTH_ERROR_MARKERS = (
    "credential is not valid",
    "invalid credential",
    "invalid signature",
    "invalid key",
    "not authenticated",
    "must login",
)
_OVH_PERMISSION_ERROR_MARKERS = (
    "not been granted",
    "forbidden",
)


def _classify_ovh_error(exc: Exception) -> str:
    """Map a fetch exception to a concise, user-facing message.

    Args:
        exc: Exception raised by an OVH list call.

    Returns:
        A short, actionable message safe to show in a TUI notification.
    """
    if isinstance(exc, ImportError):
        return "OVH: python-ovh is not installed — pip install 'servonaut[ovh]'"
    text = str(exc).lower()
    if any(marker in text for marker in _OVH_AUTH_ERROR_MARKERS):
        return (
            "OVH authentication failed — API credentials are invalid or "
            "expired. Update them in Settings → OVH."
        )
    if any(marker in text for marker in _OVH_PERMISSION_ERROR_MARKERS):
        return (
            "OVH access denied — the API token is missing required "
            "permissions. Regenerate it in Settings → OVH."
        )
    # Generic: OVH appends an "OVH-Query-ID:" line — keep only the first.
    first_line = str(exc).strip().splitlines()[0].strip()
    return f"OVH refresh failed: {first_line}"


def _source_of(instance: dict) -> str:
    """The listing an OVH row comes from, named as in a failed-source entry.

    Public Cloud rows carry their project in the composite id
    ``<project_id>/<instance_id>``, so each project is its own source.
    """
    provider_type = str(instance.get('provider_type') or '')
    if provider_type == 'cloud':
        project_id = str(instance.get('id') or '').partition('/')[0]
        return f"cloud:{project_id}"
    return provider_type


def _describe_source(source: str) -> str:
    """User-facing name of a listing source."""
    if source == 'dedicated':
        return "dedicated servers"
    if source == 'vps':
        return "VPS"
    if source.startswith('cloud:'):
        return f"Public Cloud project {source[len('cloud:'):]}"
    return source


def _first_line(exc: Exception) -> str:
    """First line of an error (OVH appends an ``OVH-Query-ID:`` line)."""
    lines = str(exc).strip().splitlines()
    return lines[0].strip() if lines else type(exc).__name__


class _NoAmbientConfig:
    """A python-ovh configuration source that knows nothing.

    python-ovh builds one of these per client and asks it for every
    credential the caller left out, reading ``OVH_*`` variables and the
    ``ovh.conf`` files. An extra account must only ever use its own settings.
    """

    def get(self, section: str, name: str) -> None:
        return None

    def read(self, config_file: str) -> None:
        return None


# python-ovh looks its configuration source up at client construction; the
# swap below must not overlap another client being built.
_OVH_CONFIG_LOCK = threading.Lock()


@contextmanager
def _ambient_ovh_config(ovh_module, allowed: bool):
    """Build a python-ovh client with (``allowed``) or without ambient config."""
    if allowed:
        with _OVH_CONFIG_LOCK:
            yield
        return
    config_module = ovh_module.client.config
    with _OVH_CONFIG_LOCK:
        original = config_module.ConfigurationManager
        config_module.ConfigurationManager = _NoAmbientConfig
        try:
            yield
        finally:
            config_module.ConfigurationManager = original


class OVHService:
    """Service for fetching OVHcloud instances (dedicated, VPS, Public Cloud)."""

    def __init__(
        self,
        config: 'OVHConfig',
        cache_path: Optional[Path] = None,
        allow_ambient_config: bool = True,
    ) -> None:
        """Initialize OVH service.

        Args:
            config: OVHConfig dataclass instance.
            cache_path: Cache file for this account. None uses the primary
                account's ``~/.servonaut/ovh_cache.json``.
            allow_ambient_config: Whether python-ovh may fill credentials this
                config leaves out from ``OVH_*`` variables and ``ovh.conf``.
                Only the primary account may: they belong to it, and an extra
                account picking them up would mix two accounts' credentials
                (python-ovh then refuses the account outright).
        """
        self._config = config
        self._allow_ambient_config = allow_ambient_config
        self._cache_path_override = (
            Path(cache_path).expanduser() if cache_path is not None else None
        )
        self._client = None  # lazy-initialized
        # Seconds per API request; None keeps python-ovh's default (180).
        self._request_timeout: Optional[float] = None
        # Why the last refresh could not be trusted, or None after a complete
        # successful fetch. Read by the instance list and MCP list_instances.
        self.last_fetch_error: Optional[str] = None
        # The error behind a failed refresh (None after a complete or partial
        # one), so a caller can tell a timeout from an error response.
        self.last_fetch_exception: Optional[BaseException] = None
        # True when some sources refreshed and others failed: the fresh rows
        # are then mixed with cached rows for the failed sources only.
        self.last_fetch_partial: bool = False
        self._failed_sources: List[str] = []
        self._source_errors: Dict[str, str] = {}
        # No request starts after this (time.monotonic); None: no limit.
        self._listing_deadline: Optional[float] = None
        # Sources of the last listing cut short because its time was up.
        self._late_sources: List[str] = []

    @property
    def _cache_path(self) -> Path:
        """This account's cache file (read at call time so tests can patch it)."""
        return self._cache_path_override or _OVH_CACHE_PATH

    def _get_client(self):
        """Lazy-initialize the OVH API client.

        Returns:
            ovh.Client instance.

        Raises:
            ImportError: If python-ovh is not installed.
        """
        if self._client is not None:
            return self._client

        try:
            import ovh
        except ImportError:
            raise ImportError(
                "python-ovh is not installed. "
                "Install with: pip install 'servonaut[ovh]'"
            )

        config = self._config
        application_key = resolve_secret(config.application_key)
        application_secret = resolve_secret(config.application_secret)
        consumer_key = resolve_secret(config.consumer_key)
        client_id = resolve_secret(config.client_id)
        client_secret = resolve_secret(config.client_secret)
        timeout_kwargs = (
            {"timeout": self._request_timeout} if self._request_timeout is not None else {}
        )

        with _ambient_ovh_config(ovh, self._allow_ambient_config):
            if client_id and client_secret:
                # OAuth2 service account auth
                self._client = ovh.Client(
                    endpoint=config.endpoint,
                    client_id=client_id,
                    client_secret=client_secret,
                    **timeout_kwargs,
                )
            else:
                # Classic 3-key auth
                self._client = ovh.Client(
                    endpoint=config.endpoint,
                    application_key=application_key,
                    application_secret=application_secret,
                    consumer_key=consumer_key,
                    **timeout_kwargs,
                )

        return self._client

    def limit_listing_time(self, request_seconds: float, start_by_seconds: float) -> None:
        """Bound the next listing for a caller that will not wait long.

        Every API request gets *request_seconds* (python-ovh's ``timeout``),
        and no request starts once *start_by_seconds* have passed: what was
        listed by then comes back as a partial listing (never saved as the
        cache). The CLI builds its services for one command, so the limits
        reach no other surface.
        """
        self._request_timeout = request_seconds
        self._listing_deadline = time.monotonic() + start_by_seconds
        self._client = None

    def _out_of_time(self) -> bool:
        return self._listing_deadline is not None and time.monotonic() >= self._listing_deadline

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def fetch_instances(self) -> List[dict]:
        """Fetch all OVH instances across configured resource types.

        Returns:
            List of instance dictionaries compatible with app.instances format.
        """
        logger.debug("Fetching instances from OVHcloud")
        instances: List[dict] = []
        self._failed_sources = []
        self._source_errors = {}
        self._late_sources = []
        attempted = 0
        last_error: Optional[Exception] = None

        if self._config.include_dedicated and self._started_in_time("dedicated"):
            attempted += 1
            try:
                dedicated = await asyncio.to_thread(self._fetch_dedicated)
                instances.extend(dedicated)
                logger.debug("Fetched %d OVH dedicated servers", len(dedicated))
            except Exception as e:
                logger.error("Error fetching OVH dedicated servers: %s", e)
                self._record_failed_source("dedicated", e)
                last_error = e

        if self._config.include_vps and self._started_in_time("vps"):
            attempted += 1
            try:
                vps = await asyncio.to_thread(self._fetch_vps)
                instances.extend(vps)
                logger.debug("Fetched %d OVH VPS instances", len(vps))
            except Exception as e:
                logger.error("Error fetching OVH VPS instances: %s", e)
                self._record_failed_source("vps", e)
                last_error = e

        if self._config.include_cloud:
            for project_id in self._config.cloud_project_ids:
                if not self._started_in_time(f"cloud:{project_id}"):
                    continue
                attempted += 1
                try:
                    cloud = await asyncio.to_thread(self._fetch_cloud, project_id)
                    instances.extend(cloud)
                    logger.debug(
                        "Fetched %d OVH Cloud instances for project %s",
                        len(cloud), project_id
                    )
                except Exception as e:
                    logger.error(
                        "Error fetching OVH Cloud instances for project %s: %s",
                        project_id, e
                    )
                    self._record_failed_source(f"cloud:{project_id}", e)
                    last_error = e

        if self._late_sources and not instances:
            raise OVHFetchError("nothing was listed in the time allowed") from TimeoutError(
                "listing time is up",
            )
        if attempted and len(self._failed_sources) == attempted:
            raise OVHFetchError(
                f"all {attempted} OVH source(s) failed: {last_error}"
            ) from last_error

        logger.info("Fetched %d total OVH instances", len(instances))
        return instances

    def _started_in_time(self, source: str) -> bool:
        """False, and *source* counts as cut short, once the listing's time is up."""
        if self._out_of_time():
            self._late_sources.append(source)
            return False
        return True

    def _record_failed_source(self, source: str, exc: Exception) -> None:
        self._failed_sources.append(source)
        self._source_errors[source] = _first_line(exc)

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Fetch instances with OVH-specific file cache.

        Args:
            force_refresh: If True, bypass cache and fetch from API.

        Returns:
            List of instance dictionaries.
        """
        if not force_refresh:
            cached = self._load_cache()
            if cached is not None:
                logger.debug("Using cached OVH instances")
                return cached

        try:
            instances = await self.fetch_instances()
        except OVHFetchError as exc:
            # Don't poison the cache — keep the previous good entries.
            self.last_fetch_error = str(exc)
            self.last_fetch_exception = exc
            self.last_fetch_partial = False
            stale = self._load_cache(ignore_ttl=True)
            if stale is not None:
                logger.warning(
                    "OVH fetch failed (%s); keeping %d cached instances",
                    exc, len(stale),
                )
                return stale
            logger.warning("OVH fetch failed (%s); no cached instances to fall back on", exc)
            return []

        if self._late_sources:
            # Cut short by its time limit: returned, never saved (the cache
            # would lose every server not listed in time).
            self.last_fetch_error = "; ".join(
                f"OVH {_describe_source(source)} not fully listed in the time allowed"
                for source in self._late_sources
            )
            self.last_fetch_partial = True
            self.last_fetch_exception = None
            return instances

        if self._failed_sources:
            # Save what did refresh and keep the cached rows of the sources
            # that failed. Refusing to save a partial inventory would let one
            # stale project id or one missing permission freeze the whole
            # OVH cache; saving it as fetched would drop those rows.
            instances = self._keep_cached_rows_of_failed_sources(instances)
            self.last_fetch_exception = None
            self._save_cache(instances)
            return instances

        self.last_fetch_error = None
        self.last_fetch_exception = None
        self.last_fetch_partial = False
        self._save_cache(instances)
        return instances

    def _keep_cached_rows_of_failed_sources(self, fresh: List[dict]) -> List[dict]:
        """Add the cached rows of every failed source to the fresh rows.

        Also words :attr:`last_fetch_error` for the user: which sources
        failed, why, and how many of their rows come from the cache.
        """
        failed = set(self._failed_sources)
        cached = self._load_cache(ignore_ttl=True) or []
        kept = [
            row for row in cached
            if isinstance(row, dict) and _source_of(row) in failed
        ]
        messages = []
        for source in self._failed_sources:
            count = sum(1 for row in kept if _source_of(row) == source)
            shown = (
                f"showing {count} cached {'row' if count == 1 else 'rows'}"
                if count else "none cached to show"
            )
            messages.append(
                f"Could not list OVH {_describe_source(source)} "
                f"({self._source_errors.get(source, 'unknown error')}); {shown}."
            )
        self.last_fetch_error = " ".join(messages)
        self.last_fetch_partial = True
        logger.warning("OVH fetch incomplete: %s", self.last_fetch_error)
        return fresh + kept

    def get_cached_instances(self) -> List[dict]:
        """Return cached OVH instances synchronously (any age).

        Returns:
            Cached instance list or empty list if no cache exists.
        """
        cached = self._load_cache(ignore_ttl=True)
        return cached if cached is not None else []

    def has_cached_instances(self) -> bool:
        """Whether this account was listed on this machine: a usable cache
        exists, whatever its age (an empty one included)."""
        return self._load_cache(ignore_ttl=True) is not None

    def listing_record(self):
        """Where a CLI lookup remembers a failed listing (see ``ListingRecord``)."""
        from servonaut.services.accounts.listing_record import ListingRecord

        return ListingRecord.beside(self._cache_path, _OVH_CACHE_TTL_SECONDS)

    def is_cache_fresh(self) -> bool:
        """Check if OVH cache is within TTL.

        Returns:
            True if cache exists and has not expired.
        """
        if not self._cache_path.exists():
            return False
        try:
            with open(self._cache_path, 'r') as f:
                data = json.load(f)
            ts = data.get('timestamp')
            if not ts:
                return False
            age = datetime.now() - datetime.fromisoformat(ts)
            return age < timedelta(seconds=_OVH_CACHE_TTL_SECONDS)
        except Exception:
            return False

    @property
    def client(self):
        """Return the initialized OVH API client.

        Returns:
            ovh.Client instance (lazy-initialized).
        """
        return self._get_client()

    @staticmethod
    def default_username(provider_type: str) -> str:
        """Return the default SSH username for an OVH provider type.

        Args:
            provider_type: One of "dedicated", "vps", "cloud".

        Returns:
            Default SSH username string.
        """
        return {
            'cloud': 'ubuntu',
            'dedicated': 'debian',
            'vps': 'ubuntu',
        }.get(provider_type, 'ubuntu')

    # ------------------------------------------------------------------
    # Power management
    # ------------------------------------------------------------------

    async def reboot_instance(self, instance_id: str, provider_type: str) -> bool:
        """Reboot an OVH instance.

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "dedicated", "vps", "cloud".

        Returns:
            True if reboot was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "dedicated":
            await asyncio.to_thread(
                client.post, f"/dedicated/server/{instance_id}/reboot"
            )
        elif provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/reboot"
            )
        elif provider_type == "cloud":
            # Cloud reboots need project_id — instance_id is "<project_id>/<id>"
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/reboot",
                type="soft",
            )
        else:
            raise ValueError(f"Unknown OVH provider_type: {provider_type}")
        return True

    async def start_instance(self, instance_id: str, provider_type: str) -> bool:
        """Start an OVH instance (VPS and Cloud only).

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "vps", "cloud".

        Returns:
            True if start was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/start"
            )
        elif provider_type == "cloud":
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/start",
            )
        else:
            raise ValueError(
                f"Start is not supported for OVH provider_type: {provider_type}"
            )
        return True

    async def stop_instance(self, instance_id: str, provider_type: str) -> bool:
        """Stop an OVH instance (VPS and Cloud only).

        Args:
            instance_id: OVH instance identifier.
            provider_type: One of "vps", "cloud".

        Returns:
            True if stop was requested successfully.
        """
        if not re.match(r'^[a-zA-Z0-9._:/-]+$', instance_id):
            raise ValueError(f"Invalid instance_id format: {instance_id!r}")
        client = self._get_client()
        if provider_type == "vps":
            await asyncio.to_thread(
                client.post, f"/vps/{instance_id}/stop"
            )
        elif provider_type == "cloud":
            project_id, _, inst_id = instance_id.partition('/')
            await asyncio.to_thread(
                client.post,
                f"/cloud/project/{project_id}/instance/{inst_id}/stop",
            )
        else:
            raise ValueError(
                f"Stop is not supported for OVH provider_type: {provider_type}"
            )
        return True

    # ------------------------------------------------------------------
    # Credential validation
    # ------------------------------------------------------------------

    async def test_connection(self) -> dict:
        """Test OVH API credentials by calling GET /me.

        Returns:
            Dict with keys: success (bool), account (str), message (str).
        """
        try:
            client = self._get_client()
            me = await asyncio.to_thread(client.get, "/me")
            nickname = me.get('nichandle') or me.get('email') or 'unknown'
            return {
                'success': True,
                'account': nickname,
                'message': f"Connected as {nickname}",
            }
        except Exception as e:
            logger.debug("OVH test_connection failed: %s", e)
            return {
                'success': False,
                'account': '',
                'message': "Authentication failed. Check your API credentials.",
            }

    async def check_credentials(self) -> Optional[str]:
        """Verify the OVH API credentials with a lightweight GET /me.

        Screens call this to disambiguate an empty result list: "no
        resources" and "credentials revoked" look identical otherwise,
        because every fetch helper swallows API errors and returns [].

        Returns:
            None when the credentials authenticate successfully; otherwise
            a concise, user-facing error message from ``_classify_ovh_error``.
        """
        try:
            client = self._get_client()
            await asyncio.to_thread(client.get, "/me")
            return None
        except Exception as exc:
            logger.debug("OVH credential check failed: %s", exc)
            return _classify_ovh_error(exc)

    async def request_consumer_key(self) -> dict:
        """Request a new consumer key via the OVH credential flow.

        Returns:
            Dict with keys: consumer_key, validation_url, state.
        """
        try:
            import ovh
        except ImportError:
            raise ImportError("python-ovh is not installed. Install with: pip install 'servonaut[ovh]'")

        config = self._config
        application_secret = resolve_secret(config.application_secret)

        application_key = resolve_secret(config.application_key)

        with _ambient_ovh_config(ovh, self._allow_ambient_config):
            client = ovh.Client(
                endpoint=config.endpoint,
                application_key=application_key,
                application_secret=application_secret,
            )

        access_rules = [
            # Listing endpoints (/* doesn't match the root list endpoint)
            {'method': 'GET', 'path': '/dedicated/server'},
            {'method': 'GET', 'path': '/vps'},
            {'method': 'GET', 'path': '/cloud/project'},
            # Individual resource access
            {'method': 'GET', 'path': '/dedicated/server/*'},
            {'method': 'GET', 'path': '/vps/*'},
            {'method': 'GET', 'path': '/cloud/project/*'},
            # Power management
            {'method': 'POST', 'path': '/vps/*/reboot'},
            {'method': 'POST', 'path': '/vps/*/start'},
            {'method': 'POST', 'path': '/vps/*/stop'},
            {'method': 'POST', 'path': '/dedicated/server/*/reboot'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/reboot'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/start'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/stop'},
            # Billing and account
            {'method': 'GET', 'path': '/me'},
            {'method': 'GET', 'path': '/me/consumption/*'},
            {'method': 'GET', 'path': '/me/bill'},
            {'method': 'GET', 'path': '/me/bill/*'},
            # VPS lifecycle — reinstall, resize, snapshots, firewall
            {'method': 'POST', 'path': '/vps/*/reinstall'},
            {'method': 'GET', 'path': '/vps/*/availableUpgrade'},
            {'method': 'POST', 'path': '/vps/*/upgrade'},
            {'method': 'GET', 'path': '/vps/*/snapshot'},
            {'method': 'POST', 'path': '/vps/*/createSnapshot'},
            {'method': 'DELETE', 'path': '/vps/*/snapshot'},
            {'method': 'POST', 'path': '/vps/*/snapshot/revert'},
            {'method': 'POST', 'path': '/vps/*/automatedBackup/restore'},
            {'method': 'PUT', 'path': '/vps/*/ips/*'},
            {'method': 'GET', 'path': '/vps/*/firewall'},
            {'method': 'PUT', 'path': '/vps/*/firewall'},
            # Dedicated server — firewall, secondary DNS
            {'method': 'GET', 'path': '/dedicated/server/*/ips'},
            {'method': 'GET', 'path': '/dedicated/server/*/firewall/*'},
            {'method': 'POST', 'path': '/dedicated/server/*/firewall/*'},
            {'method': 'PUT', 'path': '/dedicated/server/*/firewall/*'},
            {'method': 'DELETE', 'path': '/dedicated/server/*/firewall/*'},
            # Cloud — instances, snapshots, storage, SSH keys, flavors, images
            {'method': 'GET', 'path': '/cloud/project/*/instance/*'},
            {'method': 'POST', 'path': '/cloud/project/*/instance'},
            {'method': 'DELETE', 'path': '/cloud/project/*/instance/*'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/resize'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/reinstall'},
            {'method': 'GET', 'path': '/cloud/project/*/snapshot'},
            {'method': 'POST', 'path': '/cloud/project/*/instance/*/snapshot'},
            {'method': 'DELETE', 'path': '/cloud/project/*/snapshot/*'},
            {'method': 'GET', 'path': '/cloud/project/*/volume'},
            {'method': 'POST', 'path': '/cloud/project/*/volume'},
            {'method': 'GET', 'path': '/cloud/project/*/volume/*'},
            {'method': 'PUT', 'path': '/cloud/project/*/volume/*'},
            {'method': 'DELETE', 'path': '/cloud/project/*/volume/*'},
            {'method': 'POST', 'path': '/cloud/project/*/volume/*/attach'},
            {'method': 'POST', 'path': '/cloud/project/*/volume/*/detach'},
            {'method': 'POST', 'path': '/cloud/project/*/volume/*/snapshot'},
            {'method': 'GET', 'path': '/cloud/project/*/sshkey'},
            {'method': 'POST', 'path': '/cloud/project/*/sshkey'},
            {'method': 'DELETE', 'path': '/cloud/project/*/sshkey/*'},
            {'method': 'GET', 'path': '/cloud/project/*/flavor'},
            {'method': 'GET', 'path': '/cloud/project/*/image'},
            {'method': 'GET', 'path': '/cloud/project/*/region'},
            # IP management
            {'method': 'GET', 'path': '/ip'},
            {'method': 'GET', 'path': '/ip/*'},
            {'method': 'POST', 'path': '/ip/*/move'},
            {'method': 'POST', 'path': '/ip/*/park'},
            {'method': 'POST', 'path': '/ip/*/reverse'},
            {'method': 'DELETE', 'path': '/ip/*/reverse/*'},
            {'method': 'GET', 'path': '/ip/*/firewall'},
            {'method': 'POST', 'path': '/ip/*/firewall'},
            {'method': 'POST', 'path': '/ip/*/firewall/*/rule'},
            {'method': 'PUT', 'path': '/ip/*/firewall/*'},
            {'method': 'DELETE', 'path': '/ip/*/firewall/*'},
            # Account SSH keys
            {'method': 'GET', 'path': '/me/sshKey'},
            {'method': 'GET', 'path': '/me/sshKey/*'},
            {'method': 'POST', 'path': '/me/sshKey'},
            {'method': 'DELETE', 'path': '/me/sshKey/*'},
            # DNS zones
            {'method': 'GET', 'path': '/domain/zone'},
            {'method': 'GET', 'path': '/domain/zone/*'},
            {'method': 'POST', 'path': '/domain/zone/*/record'},
            {'method': 'GET', 'path': '/domain/zone/*/record/*'},
            {'method': 'PUT', 'path': '/domain/zone/*/record/*'},
            {'method': 'DELETE', 'path': '/domain/zone/*/record/*'},
            {'method': 'POST', 'path': '/domain/zone/*/refresh'},
        ]

        result = await asyncio.to_thread(
            client.request_consumerkey,
            access_rules,
        )
        return result

    # ------------------------------------------------------------------
    # Blocking fetch helpers (run inside asyncio.to_thread)
    # ------------------------------------------------------------------

    def _fetch_dedicated(self) -> List[dict]:
        """Fetch all dedicated servers sequentially.

        Returns:
            List of instance dictionaries.

        Raises:
            Exception: When OVH refuses the listing call (bad credentials,
                API error). :meth:`fetch_instances` records the source as
                failed, so the refusal is never cached as "no servers".
        """
        client = self._get_client()
        server_names = client.get("/dedicated/server")

        if not server_names:
            return []

        instances = []
        for name in server_names:
            if self._out_of_time():
                self._late_sources.append("dedicated")
                break
            try:
                instance = self._fetch_dedicated_server(name)
                if instance:
                    instances.append(instance)
            except Exception as e:
                logger.error("Error fetching OVH dedicated server %s: %s", name, e)

        return instances

    def _fetch_dedicated_server(self, name: str) -> Optional[dict]:
        """Fetch details for a single dedicated server.

        Args:
            name: Dedicated server hostname/identifier.

        Returns:
            Instance dictionary or None on error.
        """
        client = self._get_client()
        try:
            details = client.get(f"/dedicated/server/{name}")
        except Exception as e:
            logger.error("Error fetching dedicated server details for %s: %s", name, e)
            return None

        # Fetch hardware specs — non-fatal if missing
        try:
            specs = client.get(f"/dedicated/server/{name}/specifications/hardware")
        except Exception:
            specs = {}

        # Fetch IPs — non-fatal if missing
        try:
            ips = client.get(f"/dedicated/server/{name}/ips")
        except Exception:
            ips = []

        return {
            'id': name,
            'name': details.get('reverse') or name,
            'type': specs.get('description') or 'Dedicated',
            'state': self._map_dedicated_state(details.get('state', '')),
            'public_ip': self._find_public_ip(ips) or '',
            'private_ip': self._find_private_ip(ips) or '',
            'region': details.get('datacenter') or '',
            'key_name': '',
            'provider': 'OVH',
            'provider_type': 'dedicated',
            'is_ovh': True,
            'os': details.get('os') or '',
            'cpu': specs.get('numberOfCores') or '',
            'ram_gb': self._bytes_to_gb(specs.get('memorySize', 0)),
            'raw': details,
        }

    def _fetch_vps(self) -> List[dict]:
        """Fetch all VPS instances.

        Returns:
            List of instance dictionaries.

        Raises:
            Exception: When OVH refuses the listing call; see
                :meth:`_fetch_dedicated`.
        """
        client = self._get_client()
        vps_names = client.get("/vps")

        if not vps_names:
            return []

        instances = []
        for name in vps_names:
            if self._out_of_time():
                self._late_sources.append("vps")
                break
            try:
                details = client.get(f"/vps/{name}")
                model = details.get('model') or {}
                # IPs are at a separate endpoint, not in the detail response
                public_ip = ''
                try:
                    ips = client.get(f"/vps/{name}/ips")
                    if ips:
                        # Filter for IPv4 — first non-IPv6 address
                        for ip in ips:
                            if isinstance(ip, str) and ':' not in ip:
                                public_ip = ip
                                break
                        # Fallback to first IP if no IPv4 found
                        if not public_ip and ips:
                            public_ip = ips[0] if isinstance(ips[0], str) else ''
                except Exception:
                    pass
                instances.append({
                    'id': name,
                    'name': details.get('displayName') or name,
                    'type': model.get('name') or 'VPS',
                    'state': self._map_vps_state(details.get('state', '')),
                    'public_ip': public_ip,
                    'private_ip': '',
                    'region': details.get('zone') or '',
                    'key_name': '',
                    'provider': 'OVH',
                    'provider_type': 'vps',
                    'is_ovh': True,
                    'ram_gb': self._mb_to_gb(model.get('memory')),
                    'raw': details,
                })
            except Exception as e:
                logger.error("Error fetching OVH VPS details for %s: %s", name, e)

        return instances

    def _fetch_cloud(self, project_id: str) -> List[dict]:
        """Fetch all Public Cloud instances for a project.

        Args:
            project_id: OVH Public Cloud project identifier.

        Returns:
            List of instance dictionaries.

        Raises:
            Exception: When OVH refuses the listing call; see
                :meth:`_fetch_dedicated`.
        """
        client = self._get_client()
        cloud_instances = client.get(f"/cloud/project/{project_id}/instance")

        if not cloud_instances:
            return []

        instances = []
        for inst in cloud_instances:
            inst_id = inst.get('id', '')
            # Encode project_id into the composite ID for power management routing
            composite_id = f"{project_id}/{inst_id}"
            ip_addresses = inst.get('ipAddresses') or []
            instances.append({
                'id': composite_id,
                'name': inst.get('name') or inst_id,
                'type': inst.get('flavor', {}).get('name') or inst.get('flavorId') or '',
                'state': self._map_cloud_state(inst.get('status', '')),
                'public_ip': self._extract_public_ip(ip_addresses),
                'private_ip': self._extract_private_ip(ip_addresses),
                'region': inst.get('region') or '',
                'key_name': '',
                'provider': 'OVH',
                'provider_type': 'cloud',
                'is_ovh': True,
                'raw': inst,
            })

        return instances

    # ------------------------------------------------------------------
    # State mapping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _map_dedicated_state(state: str) -> str:
        """Normalize OVH dedicated server state to common format."""
        return {
            'ok': 'running',
            'hacked': 'error',
            'hackedBlocked': 'error',
        }.get(state, state)

    @staticmethod
    def _map_vps_state(state: str) -> str:
        """Normalize OVH VPS state to common format."""
        return {
            'running': 'running',
            'stopped': 'stopped',
            'installing': 'pending',
            'rescueMode': 'running',
        }.get(state, state)

    @staticmethod
    def _map_cloud_state(status: str) -> str:
        """Normalize OVH Public Cloud instance status to common format."""
        return {
            'ACTIVE': 'running',
            'SHUTOFF': 'stopped',
            'BUILD': 'pending',
            'ERROR': 'error',
            'SHELVED': 'stopped',
            'RESCUED': 'running',
            'SUSPENDED': 'stopped',
        }.get(status, status.lower() if status else '')

    # ------------------------------------------------------------------
    # IP extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_public_ip(ips: List[str]) -> str:
        """Extract the first public (non-RFC1918) IP from a list.

        Args:
            ips: List of IP strings from OVH dedicated server API.

        Returns:
            First public IP or empty string.
        """
        import ipaddress
        for ip in ips:
            ip_str = ip.split('/')[0] if '/' in ip else ip
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 4 and not addr.is_private and not addr.is_loopback:
                    return ip_str
            except ValueError:
                continue
        # Fall back to the first entry if no public IP found
        if ips:
            return ips[0].split('/')[0] if '/' in ips[0] else ips[0]
        return ''

    @staticmethod
    def _find_private_ip(ips: List[str]) -> str:
        """Extract the first private (RFC1918) IP from a list.

        Args:
            ips: List of IP strings from OVH dedicated server API.

        Returns:
            First private IP or empty string.
        """
        import ipaddress
        for ip in ips:
            ip_str = ip.split('/')[0] if '/' in ip else ip
            try:
                addr = ipaddress.ip_address(ip_str)
                if addr.version == 4 and addr.is_private:
                    return ip_str
            except ValueError:
                continue
        return ''

    @staticmethod
    def _extract_public_ip(ip_addresses: List[dict]) -> str:
        """Extract public IPv4 from OVH Cloud ipAddresses list.

        Args:
            ip_addresses: List of ip-address dicts from Cloud instance API.

        Returns:
            First public IPv4 string or empty string.
        """
        for entry in ip_addresses:
            if entry.get('type') == 'public' and entry.get('version') == 4:
                return entry.get('ip', '')
        # Fallback: any public IP
        for entry in ip_addresses:
            if entry.get('type') == 'public':
                return entry.get('ip', '')
        return ''

    @staticmethod
    def _extract_private_ip(ip_addresses: List[dict]) -> str:
        """Extract private IPv4 from OVH Cloud ipAddresses list.

        Args:
            ip_addresses: List of ip-address dicts from Cloud instance API.

        Returns:
            First private IPv4 string or empty string.
        """
        for entry in ip_addresses:
            if entry.get('type') == 'private' and entry.get('version') == 4:
                return entry.get('ip', '')
        for entry in ip_addresses:
            if entry.get('type') == 'private':
                return entry.get('ip', '')
        return ''

    @staticmethod
    def _bytes_to_gb(value) -> float:
        """Convert bytes to GB.

        Args:
            value: Memory size in bytes (OVH dedicated server memorySize field).

        Returns:
            Size in GB, rounded to 1 decimal place.
        """
        if not value:
            return 0.0
        try:
            v = int(value)
        except (TypeError, ValueError):
            return 0.0
        # OVH dedicated server API returns memorySize in bytes
        return round(v / (1024 ** 3), 1)

    @staticmethod
    def _mb_to_gb(value) -> float:
        """Convert megabytes to GB.

        Args:
            value: Memory size in MB (OVH VPS model.memory field).

        Returns:
            Size in GB, rounded to 1 decimal place.
        """
        if not value:
            return 0.0
        try:
            v = int(value)
        except (TypeError, ValueError):
            return 0.0
        # OVH VPS API returns model.memory in MB
        return round(v / 1024, 1)

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _load_cache(self, ignore_ttl: bool = False) -> Optional[List[dict]]:
        """Load OVH instances from local file cache.

        Args:
            ignore_ttl: If True, return data even if expired.

        Returns:
            List of instance dicts or None if cache invalid/expired.
        """
        if not self._cache_path.exists():
            return None

        try:
            with open(self._cache_path, 'r') as f:
                data = json.load(f)

            ts = data.get('timestamp')
            instances = data.get('instances')

            if ts is None or instances is None:
                return None

            if not ignore_ttl:
                age = datetime.now() - datetime.fromisoformat(ts)
                if age >= timedelta(seconds=_OVH_CACHE_TTL_SECONDS):
                    logger.debug("OVH cache expired (age: %s)", age)
                    return None

            logger.debug("Loaded %d OVH instances from cache", len(instances))
            return instances

        except Exception as e:
            logger.error("Error reading OVH cache: %s", e)
            return None

    def _save_cache(self, instances: List[dict]) -> None:
        """Save OVH instances to local file cache with restricted permissions.

        Args:
            instances: List of instance dicts to cache.
        """
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'instances': instances,
            }
            # Atomic, and readable by the owner only (see write_json_atomic).
            write_json_atomic(self._cache_path, data, sweep_older_than=_OVH_CACHE_TTL_SECONDS)
            logger.debug("Saved %d OVH instances to cache", len(instances))
        except (OSError, TypeError, ValueError) as e:
            logger.error("Error saving OVH cache: %s", e)
