"""Factory for constructing per-provider ObjectStorageService instances.

Used by the account registry, the single place every surface gets object
storage from, so they all see the same availability under identical config.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from servonaut.services.object_storage_regions import OVH_S3_REGIONS, canonical_ovh_s3_region

logger = logging.getLogger(__name__)

# Endpoint templates for providers whose endpoint derives from the region.
_DERIVED_ENDPOINTS = {
    "hetzner": "https://{region}.your-objectstorage.com",
    "ovh": "https://s3.{region}.io.cloud.ovh.net",
}
# Providers whose ListBuckets answers for the endpoint's region only. With a
# derived endpoint, buckets are looked for in each of these regions.
_SEARCH_REGIONS: Dict[str, Tuple[str, ...]] = {
    "ovh": tuple(code for _, code in OVH_S3_REGIONS),
}
_TITLES = {"aws": "AWS", "hetzner": "Hetzner", "ovh": "OVH"}


def build_aws_object_storage(
    storage_config, default_region: str = "", account: Optional[Any] = None
) -> Optional[object]:
    """Build the AWS S3 service for one account.

    Always attempted: without configured keys, requests are signed by the
    account's credentials (its profile, or the ambient chain for the primary
    account). The region is validated first, because an invalid region string
    (e.g. an attacker-supplied config value) would be interpolated into the
    derived endpoint URL.
    """
    from servonaut.config.secrets import resolve_secret
    from servonaut.services.object_storage_service import ObjectStorageService, S3_REGION_RE

    region = storage_config.region or default_region
    if region and not S3_REGION_RE.match(region):
        logger.warning(
            "AWS Object Storage: invalid region %r — service not initialised", region,
        )
        return None
    try:
        return ObjectStorageService(
            provider="aws",
            access_key=resolve_secret(storage_config.access_key),
            secret_key=resolve_secret(storage_config.secret_key),
            region=region,
            endpoint_url=storage_config.endpoint_url,
            account=account,
        )
    except ValueError as exc:
        logger.warning("AWS Object Storage: invalid config (%s) — service not initialised", exc)
        return None


def build_keyed_object_storage(provider: str, storage_config) -> Optional[object]:
    """Build Hetzner or OVH Object Storage from one credentials block.

    Independent of the compute service (cloud and object storage are separate
    products). Only built when an access key is set and either a region or an
    endpoint URL is; otherwise the derived endpoint URL would be malformed
    (e.g. ``https://.your-objectstorage.com``).

    An OVH endpoint derived from the region also searches the other OVH
    regions for buckets; an endpoint set by hand is the only one asked.
    """
    from servonaut.config.secrets import resolve_secret
    from servonaut.services.object_storage_service import ObjectStorageService, S3_REGION_RE

    title = _TITLES[provider]
    if not storage_config.access_key:
        return None
    region = storage_config.region
    if provider == "ovh":
        region = canonical_ovh_s3_region(region)
    endpoint = storage_config.endpoint_url
    if not endpoint and not region:
        logger.warning(
            "%s Object Storage: region or endpoint_url required — service not initialised",
            title,
        )
        return None
    if region and not S3_REGION_RE.match(region):
        logger.warning(
            "%s Object Storage: invalid region %r — service not initialised", title, region,
        )
        return None
    template = ""
    search_regions: Tuple[str, ...] = ()
    if not endpoint:
        endpoint = _DERIVED_ENDPOINTS[provider].format(region=region)
        search_regions = _SEARCH_REGIONS.get(provider, ())
        if search_regions:
            template = _DERIVED_ENDPOINTS[provider]
    try:
        return ObjectStorageService(
            provider=provider,
            access_key=resolve_secret(storage_config.access_key),
            secret_key=resolve_secret(storage_config.secret_key),
            region=region,
            endpoint_url=endpoint,
            endpoint_template=template,
            search_regions=search_regions,
        )
    except ValueError as exc:
        logger.warning(
            "%s Object Storage: invalid config (%s) — service not initialised", title, exc,
        )
        return None
