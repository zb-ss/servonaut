"""Factory for constructing per-provider ObjectStorageService instances.

Shared between ``ServonautApp._init_services`` and the headless MCP server,
so both surfaces see the same provider availability under identical config.
"""
from __future__ import annotations

import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def build_object_storage_services(
    config,
) -> Tuple[Optional[object], Optional[object], Optional[object]]:
    """Build AWS, Hetzner, and OVH ObjectStorageService instances from config.

    Args:
        config: AppConfig instance.

    Returns:
        Tuple of (aws_service, hetzner_service, ovh_service). Each is an
        ObjectStorageService instance or None when the provider is not
        configured or has invalid configuration.
    """
    from servonaut.services.object_storage_service import ObjectStorageService, S3_REGION_RE
    from servonaut.config.secrets import resolve_secret

    aws_object_storage_service = None
    hetzner_object_storage_service = None
    ovh_object_storage_service = None

    # AWS S3 — always attempted; boto3 credential chain covers key-less auth.
    # Validate region first; an invalid region string (e.g. attacker-supplied
    # config value) would be interpolated into the derived endpoint URL.
    _aws_region = config.aws.object_storage.region or config.aws.default_region
    if _aws_region and not S3_REGION_RE.match(_aws_region):
        logger.warning(
            "AWS Object Storage: invalid region %r — service not initialised",
            _aws_region,
        )
    else:
        try:
            aws_object_storage_service = ObjectStorageService(
                provider="aws",
                access_key=resolve_secret(config.aws.object_storage.access_key),
                secret_key=resolve_secret(config.aws.object_storage.secret_key),
                region=_aws_region,
                endpoint_url=config.aws.object_storage.endpoint_url,
            )
        except ValueError as exc:
            logger.warning(
                "AWS Object Storage: invalid config (%s) — service not initialised", exc
            )

    # Hetzner Object Storage — independent of hetzner_service (cloud vs
    # object storage are separate products).  Only construct when creds
    # are provided and either region or endpoint_url is set; otherwise the
    # derived endpoint URL would be malformed (e.g. "https://.your-objectstorage.com").
    if config.hetzner.object_storage.access_key:
        region_h = config.hetzner.object_storage.region
        endpoint_h = config.hetzner.object_storage.endpoint_url
        if not endpoint_h and not region_h:
            logger.warning(
                "Hetzner Object Storage: region or endpoint_url required"
                " — service not initialised"
            )
        elif region_h and not S3_REGION_RE.match(region_h):
            logger.warning(
                "Hetzner Object Storage: invalid region %r — service not initialised",
                region_h,
            )
        else:
            if not endpoint_h:
                endpoint_h = f"https://{region_h}.your-objectstorage.com"
            try:
                hetzner_object_storage_service = ObjectStorageService(
                    provider="hetzner",
                    access_key=resolve_secret(config.hetzner.object_storage.access_key),
                    secret_key=resolve_secret(config.hetzner.object_storage.secret_key),
                    region=region_h,
                    endpoint_url=endpoint_h,
                )
            except ValueError as exc:
                logger.warning(
                    "Hetzner Object Storage: invalid config (%s) — service not initialised",
                    exc,
                )

    # OVH Object Storage — similarly gated on access_key being present and
    # either region or endpoint_url being set.
    if config.ovh.object_storage.access_key:
        region_o = config.ovh.object_storage.region
        endpoint_o = config.ovh.object_storage.endpoint_url
        if not endpoint_o and not region_o:
            logger.warning(
                "OVH Object Storage: region or endpoint_url required"
                " — service not initialised"
            )
        elif region_o and not S3_REGION_RE.match(region_o):
            logger.warning(
                "OVH Object Storage: invalid region %r — service not initialised",
                region_o,
            )
        else:
            if not endpoint_o:
                endpoint_o = f"https://s3.{region_o}.io.cloud.ovh.net"
            try:
                ovh_object_storage_service = ObjectStorageService(
                    provider="ovh",
                    access_key=resolve_secret(config.ovh.object_storage.access_key),
                    secret_key=resolve_secret(config.ovh.object_storage.secret_key),
                    region=region_o,
                    endpoint_url=endpoint_o,
                )
            except ValueError as exc:
                logger.warning(
                    "OVH Object Storage: invalid config (%s) — service not initialised",
                    exc,
                )

    return aws_object_storage_service, hetzner_object_storage_service, ovh_object_storage_service
