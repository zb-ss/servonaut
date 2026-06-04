"""Shared boto3 client factory with optional STS AssumeRole + region/account pinning.

This is the single construction point for *control-plane* boto3 clients used by
the generic ``aws_call`` passthrough, the CloudWatch Logs Insights tool, and
(incrementally) the curated describe/list services. It exists so the
"control-plane / host-plane split" from the tooling feedback has a real home:
control-plane reads (security groups, WAF, ELB, logs, metrics) go through a
dedicated least-privilege IAM role assumed via STS, instead of leaning on a
per-box instance profile or the operator's personal credentials.

Behaviour contract:

- **No role configured → no behaviour change.** When ``control_plane_role_arn``
  (and the per-account map) are empty, ``client()`` builds the boto3 client
  straight off the ambient credential chain (env vars / shared config / host
  instance profile) — byte-for-byte what the services did before this factory
  existed. The STS path is strictly opt-in.
- **Role configured → STS AssumeRole.** Temporary credentials are cached per
  ``(role_arn, region)`` until ~5 minutes before expiry, so a burst of
  control-plane reads during an incident does not hammer ``sts:AssumeRole``.
- **Per-account override.** ``control_plane_role_arns`` maps ``account_id ->
  role_arn``; the ``account`` argument selects it, falling back to the default
  role ARN when the account is absent.

The factory never raises on construction and does no IO until ``client()`` is
called. An AssumeRole failure surfaces as the underlying botocore exception to
the caller (the tool layer turns it into an ``api_error`` audit row).
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import boto3

from servonaut.config.schema import AWSConfig
from servonaut.config.secrets import resolve_secret

logger = logging.getLogger(__name__)

# Refresh assumed-role credentials this many seconds before they actually
# expire, so an in-flight call never races the expiry boundary.
_CREDENTIAL_SKEW_SECONDS = 300


@dataclass
class _CachedCredentials:
    """STS temporary credentials with their absolute expiry (epoch seconds)."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiry_epoch: float

    def is_fresh(self, now: float) -> bool:
        return self.expiry_epoch - _CREDENTIAL_SKEW_SECONDS > now


class AWSClientFactory:
    """Builds boto3 clients, optionally via STS AssumeRole, with creds caching."""

    def __init__(self, aws_config: Optional[AWSConfig] = None) -> None:
        self._config = aws_config or AWSConfig()
        self._cred_cache: Dict[str, _CachedCredentials] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def default_region(self) -> str:
        """Region used when a caller passes none (empty defers to boto3)."""
        return self._config.default_region or ""

    def role_for(self, account: str = "", mutate: bool = False) -> str:
        """Resolve the role ARN to assume for *account*.

        Read calls use the control-plane (read-only) role. Write calls
        (``mutate=True``) use the SEPARATE mutate role and never fall back to
        the read role — the read role is the read-only backstop, so assuming it
        for a write would only ever hit AccessDenied. An empty result means
        "use the ambient credential chain".
        """
        if mutate:
            if account:
                mapped = (self._config.control_plane_mutate_role_arns or {}).get(account)
                if mapped:
                    return mapped
            return self._config.control_plane_mutate_role_arn or ""
        if account:
            mapped = (self._config.control_plane_role_arns or {}).get(account)
            if mapped:
                return mapped
        return self._config.control_plane_role_arn or ""

    def uses_assumed_role(self, account: str = "", mutate: bool = False) -> bool:
        """True when calls for *account* go through STS."""
        return bool(self.role_for(account, mutate))

    def client(
        self,
        service: str,
        region: str = "",
        account: str = "",
        mutate: bool = False,
    ) -> Any:
        """Return a boto3 client for *service*.

        When a role is configured for this call (read role for reads, mutate
        role for ``mutate=True``), the client is built from freshly-assumed STS
        credentials; otherwise it falls back to the ambient credential chain.
        ``region`` empty uses the configured ``default_region`` (and, if that
        too is empty, boto3's own default region resolution).
        """
        region_name = region or self.default_region or None
        role_arn = self.role_for(account, mutate)
        if not role_arn:
            kwargs: Dict[str, Any] = {}
            if region_name:
                kwargs["region_name"] = region_name
            return boto3.client(service, **kwargs)

        creds = self._assume(role_arn)
        kwargs = {
            "aws_access_key_id": creds.access_key_id,
            "aws_secret_access_key": creds.secret_access_key,
            "aws_session_token": creds.session_token,
        }
        if region_name:
            kwargs["region_name"] = region_name
        return boto3.client(service, **kwargs)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _assume(self, role_arn: str) -> _CachedCredentials:
        """Return cached STS creds for *role_arn*, assuming the role if stale."""
        now = time.time()
        with self._lock:
            cached = self._cred_cache.get(role_arn)
            if cached and cached.is_fresh(now):
                return cached

        # AssumeRole outside the lock — the STS round-trip can take a moment and
        # we don't want to serialise every other role's lookups behind it.
        sts = boto3.client("sts")
        assume_kwargs: Dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": self._config.assume_role_session_name
            or "servonaut-control-plane",
        }
        external_id = resolve_secret(self._config.control_plane_external_id or "")
        if external_id:
            assume_kwargs["ExternalId"] = external_id

        resp = sts.assume_role(**assume_kwargs)
        c = resp["Credentials"]
        fresh = _CachedCredentials(
            access_key_id=c["AccessKeyId"],
            secret_access_key=c["SecretAccessKey"],
            session_token=c["SessionToken"],
            expiry_epoch=c["Expiration"].timestamp(),
        )
        with self._lock:
            self._cred_cache[role_arn] = fresh
        logger.debug("Assumed control-plane role %s (expires %s)",
                     role_arn, c["Expiration"].isoformat())
        return fresh


def build_aws_client_factory(config) -> AWSClientFactory:
    """Construct an :class:`AWSClientFactory` from an :class:`AppConfig`.

    Mirrors :func:`servonaut.services.object_storage_factory.build_object_storage_services`
    — the single shared construction helper called by every wiring site
    (``app.py``, ``mcp/server.py``, the CLI) so the STS/region resolution logic
    lives in exactly one place.
    """
    aws_config = getattr(config, "aws", None)
    return AWSClientFactory(aws_config)
