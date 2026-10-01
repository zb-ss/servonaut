"""S3-compatible object storage service for AWS, Hetzner, and OVH providers."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import boto3
import logging

from servonaut.services.interfaces import BucketListing, ObjectStorageServiceInterface

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level compiled regexes for input validation
# ---------------------------------------------------------------------------

# S3 bucket naming rules (virtual-hosted-style compatible):
#   - 3–63 chars, lowercase letters, digits, dots, hyphens
#   - Must start and end with a letter or digit
#   - No consecutive dots, no leading/trailing dots or hyphens
_BUCKET_RE = re.compile(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$')

_VALID_PROVIDERS = frozenset({"aws", "hetzner", "ovh"})

# Region format: lowercase alphanumeric and hyphens, 1–32 chars.
# Used both here and in app.py (imported from this module).
S3_REGION_RE = re.compile(r'^[a-z0-9\-]{1,32}$')


def _is_ip_address(value: str) -> bool:
    """Return True if *value* looks like an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _validate_endpoint_url(url: str) -> None:
    """Raise ValueError if *url* is not a safe HTTPS S3 endpoint URL.

    Guards against SSRF: rejects http://, data://, and any URL whose netloc
    contains embedded credentials (``@``), a path component, or query/fragment.
    Only ``https://hostname`` (with optional port) is accepted.

    Args:
        url: Endpoint URL to validate.

    Raises:
        ValueError: If the URL is rejected.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:  # pragma: no cover — urlparse rarely raises
        raise ValueError(f"Unparseable endpoint URL {url!r}: {exc}") from exc

    if parsed.scheme != "https":
        raise ValueError(
            f"Endpoint URL must use https://; got scheme {parsed.scheme!r} in {url!r}."
        )
    netloc = parsed.netloc
    if not netloc:
        raise ValueError(f"Endpoint URL has no host component: {url!r}.")
    if "@" in netloc:
        raise ValueError(
            f"Endpoint URL must not embed credentials (@ found): {url!r}."
        )
    if parsed.path and parsed.path != "/":
        raise ValueError(
            f"Endpoint URL must not include a path component; got {parsed.path!r} in {url!r}."
        )
    if parsed.query:
        raise ValueError(
            f"Endpoint URL must not include a query string: {url!r}."
        )
    if parsed.fragment:
        raise ValueError(
            f"Endpoint URL must not include a fragment: {url!r}."
        )

    # SSRF protection: reject link-local, loopback, and private/RFC1918
    # ranges when the host is a bare IP address.  Non-IP hostnames pass
    # (DNS-based filtering is outside our scope here).
    host = parsed.hostname or ""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_loopback or ip.is_private:
            raise ValueError(
                f"Endpoint URL host {host!r} resolves to a reserved IP range "
                f"(link-local, loopback, or private/RFC1918) — not allowed."
            )
    except ValueError as ip_err:
        # Re-raise only if it was our own rejection; ignore "not a valid IP"
        # errors from ip_address() (those mean the host is a hostname).
        if "reserved IP range" in str(ip_err):
            raise

    # Alternate IPv4 encodings (decimal e.g. 2130706433, hex 0x7f000001,
    # octal 0177.0.0.1, short-form 127.1) are NOT parsed by ip_address()
    # but the OS resolver still decodes them — socket.inet_aton accepts
    # every numeric form. A genuine hostname raises OSError and falls
    # through. This closes the SSRF alternate-encoding bypass.
    try:
        packed = socket.inet_aton(host)
    except OSError:
        packed = None
    if packed is not None:
        ip = ipaddress.IPv4Address(packed)
        if ip.is_link_local or ip.is_loopback or ip.is_private:
            raise ValueError(
                f"Endpoint URL host {host!r} decodes to a reserved IPv4 "
                f"range via an alternate encoding — not allowed."
            )


def _bucket_entry(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """The listing dict for one ``ListBuckets`` entry."""
    created = bucket.get("CreationDate")
    return {
        "name": bucket["Name"],
        "creation_date": created.isoformat() if created else "",
    }


def _try_list_buckets(client: Any) -> Tuple[List[Dict[str, Any]], Optional[Exception]]:
    """``(buckets, None)`` from one client's ListBuckets, or ``([], error)``."""
    try:
        return client.list_buckets().get("Buckets", []), None
    except Exception as exc:  # noqa: BLE001 — reported per region by the caller
        return [], exc


def _error_code(exc: Exception) -> str:
    """The S3 error code of *exc* (e.g. ``AccessDenied``), else its type name."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if isinstance(code, str) and code:
            return code
    return type(exc).__name__


class ObjectStorageService(ObjectStorageServiceInterface):
    """S3-compatible object storage client for AWS, Hetzner, and OVH.

    A single parameterised class covers all three providers.  The ``provider``
    argument controls which validation rules apply (e.g. ``endpoint_url`` is
    required for Hetzner/OVH but optional for AWS).  boto3 is imported at the
    module level (hard dependency) but the actual S3 client is created lazily
    via :meth:`_get_client` so construction is cheap and deferred until the
    first real API call.

    Credentials passed to the constructor are ALREADY RESOLVED (``$ENV_VAR``
    expanded by the caller).  The raw config values are never seen here.

    Args:
        provider: One of ``"aws"``, ``"hetzner"``, ``"ovh"``.
        access_key: S3 access key ID (resolved, may be empty for AWS
            instance-profile auth).
        secret_key: S3 secret access key (resolved, may be empty for AWS
            instance-profile auth).
        region: AWS region or provider region string.  Empty → boto3 default.
        endpoint_url: Custom S3 endpoint URL.  Empty → use AWS S3.
        endpoint_template: For a provider whose endpoint is derived from the
            region, that endpoint with a ``{region}`` placeholder.  Required
            with *search_regions*.
        search_regions: For a provider whose ListBuckets answers for one
            region only (OVH), every region to look for buckets in.  Each
            bucket found is then reached at its own region's endpoint.
    """

    def __init__(
        self,
        *,
        provider: str,
        access_key: str = "",
        secret_key: str = "",
        region: str = "",
        endpoint_url: str = "",
        account: Optional[Any] = None,
        endpoint_template: str = "",
        search_regions: Sequence[str] = (),
    ) -> None:
        """Build an S3-compatible storage service.

        Args:
            account: For AWS, the account (``AWSAccountContext``) whose
                credentials sign requests when no access key is configured.
                None keeps the process-wide default credential chain.
        """
        if provider not in _VALID_PROVIDERS:
            raise ValueError(
                f"Invalid provider {provider!r}. Must be one of: "
                + ", ".join(sorted(_VALID_PROVIDERS))
            )
        # Validate endpoint_url before storing it: only HTTPS URLs with a
        # clean netloc are accepted.  An http:// or data:// URL could be used
        # to exfiltrate credentials to an attacker-controlled server (SSRF).
        if endpoint_url:
            _validate_endpoint_url(endpoint_url)
        # Validate region format to prevent injection into derived URLs.
        self._validate_region(region)
        if search_regions and not endpoint_template:
            raise ValueError("search_regions needs an endpoint_template.")
        searched = tuple(dict.fromkeys(r for r in (region, *search_regions) if r))
        if endpoint_template:
            if "{region}" not in endpoint_template:
                raise ValueError(
                    f"Endpoint template {endpoint_template!r} has no {{region}} placeholder."
                )
            for candidate in searched or ("region",):
                self._validate_region(candidate)
                _validate_endpoint_url(endpoint_template.format(region=candidate))
        self._provider = provider
        self._access_key = access_key
        self._secret_key = secret_key
        self._region = region
        self._endpoint_url = endpoint_url
        self._account = account
        self._endpoint_template = endpoint_template
        # Configured region first, so its error is the one reported when no
        # region answers at all.
        self._search_regions: Tuple[str, ...] = searched if search_regions else ()
        self._client: Optional[Any] = None
        # region → client, for the regional endpoints of endpoint_template.
        self._regional_clients: Dict[str, Any] = {}
        self._regional_clients_lock = threading.Lock()
        # bucket name → home region, populated by discovery and bucket searches.
        self._bucket_regions: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Lazy client
    # ------------------------------------------------------------------

    def _get_client(self) -> Any:
        """Return (or create) the boto3 S3 client.

        Credentials are passed explicitly when both access_key and secret_key
        are non-empty; otherwise boto3 falls back to the standard credential
        chain (env vars, ~/.aws/credentials, instance profile, etc.).
        """
        if self._client is not None:
            return self._client

        self._client = self._new_client(self._client_kwargs(self._region))
        return self._client

    def _client_kwargs(self, region: str) -> Dict[str, Any]:
        """boto3 client arguments for a client bound to *region*."""
        kwargs: Dict[str, Any] = {}
        if region:
            kwargs["region_name"] = region
        endpoint = self._endpoint_for_region(region)
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        if self._access_key and self._secret_key:
            kwargs["aws_access_key_id"] = self._access_key
            kwargs["aws_secret_access_key"] = self._secret_key
        return kwargs

    def _endpoint_for_region(self, region: str) -> str:
        """The endpoint serving *region*: derived from the template, else fixed."""
        if self._endpoint_template and region:
            return self._endpoint_template.format(region=region)
        return self._endpoint_url

    def _new_client(self, kwargs: Dict[str, Any]) -> Any:
        """An S3 client; explicit keys win, then the account's credentials."""
        account = self._account
        if (
            account is not None
            and not account.uses_ambient_credentials
            and "aws_access_key_id" not in kwargs
        ):
            return account.client("s3", **kwargs)
        return boto3.client("s3", **kwargs)

    def _region_for_bucket(
        self, bucket: str, override: str = "", *, discover: bool = False,
    ) -> str:
        """Resolve which region a request for *bucket* should target.

        Resolution order: explicit *override* → endpoint-pinned region →
        cached discovery → live discovery (only when *discover*) → the
        configured region.

        A provider with *search_regions* always discovers: its regional
        endpoints never redirect to each other, so a bucket not seen yet is
        looked for in every region before the request goes out.

        Discovery is off by default on purpose.  botocore's
        ``S3RegionRedirectorv2`` already retries a misdirected request against
        the correct region and caches the result, so paying for a HeadBucket
        up front would just move that cost rather than remove it.  It is worth
        paying only where no redirect can happen — see
        :meth:`generate_presigned_url`.

        Args:
            bucket: Bucket the request targets.
            override: Caller-supplied region (already validated).
            discover: Issue a HeadBucket when the region is not yet known.

        Returns:
            Region string, possibly empty (→ credential-chain default).
        """
        if override:
            return override
        if self._search_regions:
            if bucket not in self._bucket_regions:
                self._search_all_regions()
            return self._bucket_regions.get(bucket, self._region)
        # For Hetzner (and an OVH endpoint set by hand) the endpoint URL
        # encodes the region; there is no cross-region redirect to discover
        # and no other endpoint to reach.
        if self._endpoint_url:
            return self._region
        cached = self._bucket_regions.get(bucket)
        if cached:
            return cached
        if not discover:
            return self._region
        discovered = self._discover_bucket_region(bucket)
        if discovered:
            self._bucket_regions[bucket] = discovered
            return discovered
        return self._region

    def _discover_bucket_region(self, bucket: str) -> str:
        """Return the region *bucket* lives in, or "" if it cannot be found.

        S3 reports the bucket's home region in the ``x-amz-bucket-region``
        response header, and does so on the 301/403 error responses too — so
        a HeadBucket answers the question even without ``s3:GetBucketLocation``
        or read access to the bucket.

        Never raises: a failed lookup degrades to the configured region.

        Args:
            bucket: Bucket to look up.

        Returns:
            Region string, or "" when undetermined.
        """
        def _header_region(payload: Any) -> str:
            if not isinstance(payload, dict):
                return ""
            headers = payload.get("ResponseMetadata", {}).get("HTTPHeaders", {})
            value = headers.get("x-amz-bucket-region", "") if headers else ""
            return value if isinstance(value, str) else ""

        try:
            region = _header_region(self._get_client().head_bucket(Bucket=bucket))
        except Exception as exc:  # noqa: BLE001 — best-effort lookup
            region = _header_region(getattr(exc, "response", None))
            if not region:
                logger.debug("Bucket region lookup failed for %r: %s", bucket, exc)
                return ""

        # The value arrives off the wire and is fed straight into a boto3
        # client config, so it gets the same format check as configured input.
        if region and not S3_REGION_RE.match(region):
            logger.warning(
                "Ignoring malformed x-amz-bucket-region %r for bucket %r",
                region, bucket,
            )
            return ""
        return region

    def _client_for_bucket(
        self, bucket: str, override: str = "", *, discover: bool = False,
    ) -> Any:
        """Return an S3 client pointed at the region *bucket* lives in."""
        return self._client_for_region(
            self._region_for_bucket(bucket, override, discover=discover)
        )

    def _client_for_region(self, region: str) -> Any:
        """Return an S3 client bound to *region*.

        ``CreateBucket`` must be sent to the endpoint of the region the bucket
        should live in, so a one-off region override needs its own client
        rather than the cached default one.  Falls back to the cached client
        when *region* is empty or already matches the configured region.

        The ad-hoc client is deliberately NOT cached — an override is a
        per-call concern and must not change the region of later calls.

        Args:
            region: Target region.  Empty → cached default client.

        Returns:
            A boto3 S3 client.
        """
        if not region or region == self._region:
            return self._get_client()
        if not self._endpoint_template:
            return self._new_client(self._client_kwargs(region))
        # Regional endpoints are a fixed, small set, so their clients are kept.
        with self._regional_clients_lock:
            client = self._regional_clients.get(region)
            if client is None:
                client = self._new_client(self._client_kwargs(region))
                self._regional_clients[region] = client
            return client

    @property
    def region(self) -> str:
        """Configured region for this provider (empty when unset)."""
        return self._region

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_region(region: str) -> None:
        """Raise ValueError if *region* is set and malformed.

        Region strings are interpolated into derived endpoint URLs and boto3
        client config, so anything outside the expected shape is rejected.

        Args:
            region: Region string ("" is allowed and means "unset").

        Raises:
            ValueError: If the region is non-empty and malformed.
        """
        if region and not S3_REGION_RE.match(region):
            raise ValueError(
                f"Invalid region {region!r}. Must match ^[a-z0-9-]{{1,32}}$."
            )

    def _reject_pinned_region(self, region: str) -> None:
        """Reject a region override that the configured endpoint cannot honour.

        For Hetzner, or an OVH endpoint set by hand, the endpoint URL encodes
        the region, so accepting an override would send the request to the
        endpoint's region while reporting the requested one back to the
        caller.  Failing loudly is the honest outcome.  An endpoint derived
        from a template reaches every region at its own endpoint, so any
        override is honoured.

        Args:
            region: Requested region ("" is always allowed).

        Raises:
            ValueError: If an override disagrees with the pinned endpoint.
        """
        if (
            region
            and self._endpoint_url
            and not self._endpoint_template
            and region != self._region
        ):
            raise ValueError(
                f"Cannot target region {region!r}: provider {self._provider!r} "
                f"is pinned to endpoint {self._endpoint_url} "
                f"(region {self._region or 'unset'!r}). Configure a separate "
                "endpoint URL for that region instead."
            )

    def _check_region_arg(self, region: str) -> None:
        """Validate a caller-supplied region override for this provider."""
        self._validate_region(region)
        self._reject_pinned_region(region)

    @staticmethod
    def _validate_bucket(bucket: str) -> None:
        """Raise ValueError if *bucket* is not a valid S3 bucket name.

        Enforces virtual-hosted-style naming rules:
        - 3–63 chars, lowercase letters/digits/dots/hyphens
        - Start and end with letter or digit
        - No ``..`` sequences (reserved / ambiguous)
        - Must not look like an IP address

        Args:
            bucket: Bucket name to validate.

        Raises:
            ValueError: If the name is invalid.
        """
        if not bucket or not _BUCKET_RE.match(bucket):
            raise ValueError(
                f"Invalid bucket name {bucket!r}. Must be 3–63 lowercase "
                "alphanumeric characters, dots, or hyphens; must start and "
                "end with a letter or digit."
            )
        if ".." in bucket:
            raise ValueError(
                f"Invalid bucket name {bucket!r}: consecutive dots are not allowed."
            )
        if _is_ip_address(bucket):
            raise ValueError(
                f"Invalid bucket name {bucket!r}: bucket names must not be "
                "formatted as IP addresses."
            )

    @staticmethod
    def _validate_object_key(key: str) -> None:
        """Raise ValueError if *key* is not a valid S3 object key.

        Rules:
        - Non-empty
        - At most 1024 bytes (UTF-8)
        - No null bytes
        - Must not start with ``/`` (would create confusing path semantics)

        Args:
            key: Object key to validate.

        Raises:
            ValueError: If the key is invalid.
        """
        if not key:
            raise ValueError("Object key must be non-empty.")
        if "\x00" in key:
            raise ValueError("Object key must not contain null bytes.")
        if len(key.encode("utf-8")) > 1024:
            raise ValueError(
                f"Object key must be at most 1024 bytes; got {len(key.encode('utf-8'))}."
            )
        if key.startswith("/"):
            raise ValueError(
                f"Object key must not start with '/'; got {key!r}."
            )

    @staticmethod
    def _validate_local_path(path: str, *, must_exist: bool) -> Path:
        """Validate and resolve *path*, enforcing path-traversal guards.

        Allowed roots (an attempt to write/read outside these will be
        rejected even if the path resolves to a valid filesystem location):

        - Current working directory (``Path.cwd()``)
        - User home directory (``Path.home()``)
        - ``~/Downloads``

        For uploads (*must_exist=True*) the resolved path must exist and be
        a regular file.  For downloads (*must_exist=False*) the parent
        directory must exist.

        Args:
            path: Local filesystem path (may be relative or use ``~``).
            must_exist: When True the file must already exist (upload path).
                When False the parent directory must exist (download path).

        Returns:
            Resolved absolute :class:`~pathlib.Path`.

        Raises:
            ValueError: If the path fails any validation check.
        """
        if not path:
            raise ValueError("Local path must be non-empty.")

        resolved = Path(path).expanduser().resolve()

        # Path-traversal guard: resolved path must be under an allowed root.
        allowed_roots = (
            Path.cwd(),
            Path.home(),
            (Path.home() / "Downloads").resolve(),
        )
        if not any(
            resolved == root or str(resolved).startswith(str(root) + "/")
            for root in allowed_roots
        ):
            raise ValueError(
                f"Path {path!r} resolves to {resolved} which is outside the "
                "allowed roots (home directory, Downloads, or current working "
                "directory). Refusing for security."
            )

        if must_exist:
            if not resolved.exists():
                raise ValueError(f"Local file does not exist: {resolved}")
            if not resolved.is_file():
                raise ValueError(
                    f"Local path must point to a regular file, not a directory: {resolved}"
                )
        else:
            if not resolved.parent.exists():
                raise ValueError(
                    f"Parent directory does not exist: {resolved.parent}"
                )

        return resolved

    @staticmethod
    def _validate_expires_in(expires_in: int) -> None:
        """Raise ValueError if *expires_in* is outside the valid range 1–604800.

        Args:
            expires_in: Expiry in seconds.

        Raises:
            ValueError: If out of range.
        """
        if not isinstance(expires_in, int) or not (1 <= expires_in <= 604_800):
            raise ValueError(
                f"expires_in must be an integer between 1 and 604800 seconds; "
                f"got {expires_in!r}."
            )

    # ------------------------------------------------------------------
    # ObjectStorageServiceInterface implementation
    # ------------------------------------------------------------------

    async def list_buckets(self) -> List[Dict[str, Any]]:
        """List all buckets accessible with the configured credentials.

        Returns:
            List of dicts with keys: ``name`` (str),
            ``creation_date`` (str ISO-8601 or empty), and ``region`` (str)
            when every region was searched.
        """
        return (await self.search_buckets()).buckets

    async def search_buckets(self) -> BucketListing:
        """List buckets and report where they were looked for.

        With *search_regions*, every region is asked at once and a region
        that does not answer is reported rather than failing the listing;
        only when none answers is the configured region's error raised.
        """
        if self._search_regions:
            return await asyncio.to_thread(self._search_all_regions)

        def _sync() -> List[Dict[str, Any]]:
            response = self._get_client().list_buckets()
            return [_bucket_entry(b) for b in response.get("Buckets", [])]

        return BucketListing(
            buckets=await asyncio.to_thread(_sync),
            endpoint=self._endpoint_url,
            region=self._region,
        )

    def _search_all_regions(self) -> BucketListing:
        """Ask every search region for its buckets and remember where each is.

        Raises:
            Exception: The first region's error, when no region answered.
        """
        # Clients are made here, one after another: building boto3 clients
        # from several threads at once is not safe.  The calls then run
        # side by side.
        clients = {region: self._client_for_region(region) for region in self._search_regions}
        with ThreadPoolExecutor(max_workers=len(clients)) as pool:
            answers = dict(zip(clients, pool.map(_try_list_buckets, clients.values())))

        buckets: List[Dict[str, Any]] = []
        failures: Dict[str, str] = {}
        errors: List[Exception] = []
        found: Dict[str, str] = {}
        for region, (raw, error) in answers.items():
            if error is not None:
                failures[region] = _error_code(error)
                errors.append(error)
                logger.info("Bucket search: region %s could not be searched: %s", region, error)
                continue
            for bucket in raw:
                entry = _bucket_entry(bucket)
                entry["region"] = region
                buckets.append(entry)
                found.setdefault(entry["name"], region)
        if len(failures) == len(answers):
            raise errors[0]
        self._bucket_regions.update(found)
        return BucketListing(
            buckets=buckets,
            region=self._region,
            searched_regions=self._search_regions,
            failed_regions=failures,
        )

    async def create_bucket(self, bucket: str, region: str = "") -> None:
        """Create a new S3 bucket.

        Args:
            bucket: Bucket name to create.
            region: Region to create the bucket in.  Empty → the region this
                service was configured with (or the credential chain's default
                when that is also unset).  Where the region is pinned by a
                configured endpoint URL (Hetzner, an OVH endpoint set by
                hand), an override that disagrees with it is rejected rather
                than silently creating the bucket somewhere else.

        Raises:
            ValueError: If *bucket* or *region* fails validation, or a region
                override is given for an endpoint-pinned provider.
        """
        self._validate_bucket(bucket)
        self._check_region_arg(region)

        def _sync() -> None:
            client = self._client_for_region(region)
            # Resolve the region the request will actually reach: an explicit
            # override wins, then the configured region, then whatever boto3
            # worked out from the credential chain (env, ~/.aws/config).  The
            # last case matters — without it a client that boto3 pointed at
            # eu-west-1 would send a CreateBucket with no LocationConstraint
            # and get IllegalLocationConstraintException back.
            effective = region or self._region
            if not effective:
                resolved = getattr(getattr(client, "meta", None), "region_name", None)
                if isinstance(resolved, str):
                    effective = resolved
            # AWS requires CreateBucketConfiguration for every region except
            # us-east-1, where it must be omitted.  Endpoint-based providers
            # derive the region from the endpoint, so we send the plain call.
            if effective and effective != "us-east-1" and not self._endpoint_url:
                client.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={"LocationConstraint": effective},
                )
            else:
                client.create_bucket(Bucket=bucket)
            # We know exactly where it landed — seed the cache so later ops on
            # this bucket skip both discovery and a redirect round-trip.
            if effective:
                self._bucket_regions[bucket] = effective

        await asyncio.to_thread(_sync)

    async def delete_bucket(self, bucket: str, region: str = "") -> None:
        """Delete a bucket.  The bucket must be empty.

        Args:
            bucket: Name of the bucket to delete.
            region: Region the bucket lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Raises:
            ValueError: If *bucket* or *region* fails validation.
        """
        self._validate_bucket(bucket)
        self._check_region_arg(region)

        def _sync() -> None:
            client = self._client_for_bucket(bucket, region)
            client.delete_bucket(Bucket=bucket)
            self._bucket_regions.pop(bucket, None)

        await asyncio.to_thread(_sync)

    async def list_objects(
        self,
        bucket: str,
        prefix: str = "",
        delimiter: str = "/",
        region: str = "",
    ) -> Dict[str, Any]:
        """List objects and virtual-folder prefixes in *bucket*.

        Issues a single ``ListObjectsV2`` call (max 1000 keys).  If the
        result is truncated the returned dict includes
        ``"is_truncated": True`` so the UI can surface a warning.

        Args:
            bucket: Target bucket name.
            prefix: Key prefix filter (e.g. ``"images/"``).
            delimiter: Hierarchy delimiter (default ``"/"``).
            region: Region the bucket lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Returns:
            Dict with keys:

            - ``"folders"`` — ``List[str]``: common-prefix strings.
            - ``"objects"`` — ``List[Dict]``: each with keys ``"key"``,
              ``"size"`` (int bytes), ``"last_modified"`` (str ISO-8601).
            - ``"is_truncated"`` — ``bool``.

        Raises:
            ValueError: If *bucket* or *region* fails validation.
        """
        self._validate_bucket(bucket)
        self._check_region_arg(region)

        def _sync() -> Dict[str, Any]:
            client = self._client_for_bucket(bucket, region)
            kwargs: Dict[str, Any] = {"Bucket": bucket}
            if prefix:
                kwargs["Prefix"] = prefix
            if delimiter:
                kwargs["Delimiter"] = delimiter
            response = client.list_objects_v2(**kwargs)

            folders = [
                cp["Prefix"]
                for cp in response.get("CommonPrefixes") or []
            ]
            objects = [
                {
                    "key": obj["Key"],
                    "size": obj.get("Size", 0),
                    "last_modified": (
                        obj["LastModified"].isoformat()
                        if obj.get("LastModified")
                        else ""
                    ),
                }
                for obj in response.get("Contents") or []
            ]
            return {
                "folders": folders,
                "objects": objects,
                "is_truncated": response.get("IsTruncated", False),
            }

        return await asyncio.to_thread(_sync)

    async def upload_object(
        self,
        bucket: str,
        key: str,
        local_path: str,
        region: str = "",
    ) -> None:
        """Upload a local file to *bucket* at *key*.

        Args:
            bucket: Target bucket name.
            key: Destination object key.
            local_path: Absolute path to the local file.
            region: Region the bucket lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_bucket(bucket)
        self._validate_object_key(key)
        self._check_region_arg(region)
        resolved = self._validate_local_path(local_path, must_exist=True)

        def _sync() -> None:
            client = self._client_for_bucket(bucket, region)
            client.upload_file(str(resolved), bucket, key)

        await asyncio.to_thread(_sync)

    async def download_object(
        self,
        bucket: str,
        key: str,
        local_path: str,
        region: str = "",
    ) -> None:
        """Download an object from *bucket*/*key* to *local_path*.

        Args:
            bucket: Source bucket name.
            key: Object key to download.
            local_path: Absolute path where the file will be written.
            region: Region the bucket lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_bucket(bucket)
        self._validate_object_key(key)
        self._check_region_arg(region)
        resolved = self._validate_local_path(local_path, must_exist=False)

        def _sync() -> None:
            # Re-run path validation immediately before the write so the
            # allowed-roots check is as close to the boto3 call as possible
            # (defence against TOCTOU: a symlink swap between the outer check
            # and the actual download).
            self._validate_local_path(local_path, must_exist=False)
            client = self._client_for_bucket(bucket, region)
            client.download_file(bucket, key, str(resolved))

        await asyncio.to_thread(_sync)

    async def delete_object(self, bucket: str, key: str, region: str = "") -> None:
        """Delete a single object from *bucket*.

        Args:
            bucket: Bucket containing the object.
            key: Object key to delete.
            region: Region the bucket lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Raises:
            ValueError: If *bucket*, *key*, or *region* fails validation.
        """
        self._validate_bucket(bucket)
        self._validate_object_key(key)
        self._check_region_arg(region)

        def _sync() -> None:
            client = self._client_for_bucket(bucket, region)
            client.delete_object(Bucket=bucket, Key=key)

        await asyncio.to_thread(_sync)

    async def copy_object(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        region: str = "",
    ) -> None:
        """Server-side copy of an object.

        A cross-region copy is driven from the DESTINATION region — S3 resolves
        ``CopySource`` globally and pulls the source itself — so *region*
        describes where *dst_bucket* lives, not the source.

        Args:
            src_bucket: Source bucket name.
            src_key: Source object key.
            dst_bucket: Destination bucket name.
            dst_key: Destination object key.
            region: Region *dst_bucket* lives in.  Empty → resolved from the
                configured region, with botocore redirecting if it is wrong.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_bucket(src_bucket)
        self._validate_object_key(src_key)
        self._validate_bucket(dst_bucket)
        self._validate_object_key(dst_key)
        self._check_region_arg(region)

        def _sync() -> None:
            client = self._client_for_bucket(dst_bucket, region)
            client.copy_object(
                CopySource={"Bucket": src_bucket, "Key": src_key},
                Bucket=dst_bucket,
                Key=dst_key,
            )

        await asyncio.to_thread(_sync)

    async def move_object(
        self,
        src_bucket: str,
        src_key: str,
        dst_bucket: str,
        dst_key: str,
        region: str = "",
        src_region: str = "",
    ) -> None:
        """Move an object: server-side copy then delete source.

        The two legs can target different regions: the copy is driven from the
        destination region, the delete from the source one.  Hence the two
        parameters — passing only *region* still works, the delete leg just
        falls back to a redirect when the source lives elsewhere.

        Args:
            src_bucket: Source bucket name.
            src_key: Source object key.
            dst_bucket: Destination bucket name.
            dst_key: Destination object key.
            region: Region *dst_bucket* lives in (drives the copy).
            src_region: Region *src_bucket* lives in (drives the delete).

        Raises:
            ValueError: If any argument fails validation.
        """
        # Validators run inside copy_object and delete_object; calling them
        # again here avoids wasted API calls on bad input.
        self._validate_bucket(src_bucket)
        self._validate_object_key(src_key)
        self._validate_bucket(dst_bucket)
        self._validate_object_key(dst_key)
        self._check_region_arg(region)
        self._check_region_arg(src_region)

        await self.copy_object(src_bucket, src_key, dst_bucket, dst_key, region)
        await self.delete_object(src_bucket, src_key, src_region)

    async def generate_presigned_url(
        self,
        bucket: str,
        key: str,
        expires_in: int = 3600,
        region: str = "",
    ) -> str:
        """Generate a pre-signed URL for temporary public access to an object.

        This is the one operation that resolves the bucket's region up front
        (a single cached HeadBucket) rather than letting botocore redirect.
        Signing happens locally with no request to redirect, and SigV4 binds
        the region into the credential scope — so a URL signed for the wrong
        region is not slow, it is silently unusable, failing with
        ``SignatureDoesNotMatch`` only once somebody opens it.

        Args:
            bucket: Bucket containing the object.
            key: Object key.
            expires_in: Expiry in seconds (1–604800, default 3600).
            region: Region the bucket lives in.  Empty → discovered and cached.

        Returns:
            Pre-signed URL string.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_bucket(bucket)
        self._validate_object_key(key)
        self._validate_expires_in(expires_in)
        self._check_region_arg(region)

        def _sync() -> str:
            client = self._client_for_bucket(bucket, region, discover=True)
            return client.generate_presigned_url(
                "get_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=expires_in,
            )

        return await asyncio.to_thread(_sync)
