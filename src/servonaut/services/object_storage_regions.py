"""Known S3 / Object Storage regions per provider.

Regions are a finite, provider-controlled enum — not user-typed free
text — so the setup screens render them as ``Select`` dropdowns rather
than ``Input`` widgets.  Centralising the lists here lets the form, the
factory, and any future validator all read from the same source of
truth.

Each entry is ``(label, region_code)``.  The label is what's shown in
the dropdown; the code is what's persisted to
:attr:`servonaut.config.schema.ObjectStorageConfig.region` and used by
the factory to derive the endpoint URL (when one is not explicitly
configured).

Lists are intentionally conservative — they cover the regions a typical
user is most likely to need.  Add new entries here as providers expand;
the factory will accept any string today (it only enforces a regex
shape), so a stale list reduces dropdown coverage but never breaks
existing configurations.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# (label, code) tuples consumed by Textual's Select widget.

AWS_S3_REGIONS: List[Tuple[str, str]] = [
    ("us-east-1 — US East (N. Virginia)", "us-east-1"),
    ("us-east-2 — US East (Ohio)", "us-east-2"),
    ("us-west-1 — US West (N. California)", "us-west-1"),
    ("us-west-2 — US West (Oregon)", "us-west-2"),
    ("ca-central-1 — Canada (Central)", "ca-central-1"),
    ("eu-west-1 — Europe (Ireland)", "eu-west-1"),
    ("eu-west-2 — Europe (London)", "eu-west-2"),
    ("eu-west-3 — Europe (Paris)", "eu-west-3"),
    ("eu-central-1 — Europe (Frankfurt)", "eu-central-1"),
    ("eu-north-1 — Europe (Stockholm)", "eu-north-1"),
    ("eu-south-1 — Europe (Milan)", "eu-south-1"),
    ("ap-northeast-1 — Asia Pacific (Tokyo)", "ap-northeast-1"),
    ("ap-northeast-2 — Asia Pacific (Seoul)", "ap-northeast-2"),
    ("ap-northeast-3 — Asia Pacific (Osaka)", "ap-northeast-3"),
    ("ap-southeast-1 — Asia Pacific (Singapore)", "ap-southeast-1"),
    ("ap-southeast-2 — Asia Pacific (Sydney)", "ap-southeast-2"),
    ("ap-south-1 — Asia Pacific (Mumbai)", "ap-south-1"),
    ("ap-east-1 — Asia Pacific (Hong Kong)", "ap-east-1"),
    ("sa-east-1 — South America (São Paulo)", "sa-east-1"),
    ("me-south-1 — Middle East (Bahrain)", "me-south-1"),
    ("af-south-1 — Africa (Cape Town)", "af-south-1"),
]
AWS_S3_DEFAULT_REGION = "us-east-1"


# Hetzner Object Storage:
# https://docs.hetzner.com/storage/object-storage/overview
# Endpoint format: https://<region>.your-objectstorage.com
HETZNER_S3_REGIONS: List[Tuple[str, str]] = [
    ("nbg1 — Nuremberg (Germany)", "nbg1"),
    ("fsn1 — Falkenstein (Germany)", "fsn1"),
    ("hel1 — Helsinki (Finland)", "hel1"),
]
HETZNER_S3_DEFAULT_REGION = "nbg1"


# OVHcloud Object Storage (Standard + High Performance both use the same
# region codes for the S3 endpoint):
# https://docs.ovhcloud.com/en/guides/storage-and-backup/object-storage/s3-location
# Endpoint format: https://s3.<region>.io.cloud.ovh.net
#
# Each region answers ListBuckets with its own buckets only, so this list is
# also the set of regions searched for buckets when the endpoint is derived
# from the region (see ObjectStorageService ``search_regions``).
OVH_S3_REGIONS: List[Tuple[str, str]] = [
    ("gra — Gravelines (France)", "gra"),
    ("sbg — Strasbourg (France)", "sbg"),
    ("rbx — Roubaix (France)", "rbx"),
    ("eu-west-par — Paris (France, 3-AZ)", "eu-west-par"),
    ("eu-south-mil — Milan (Italy, 3-AZ)", "eu-south-mil"),
    ("de — Frankfurt (Germany)", "de"),
    ("uk — London (United Kingdom)", "uk"),
    ("waw — Warsaw (Poland)", "waw"),
    ("bhs — Beauharnois (Canada)", "bhs"),
    ("ca-east-tor — Toronto (Canada)", "ca-east-tor"),
    ("sgp — Singapore", "sgp"),
    ("ap-southeast-syd — Sydney (Australia)", "ap-southeast-syd"),
    ("ap-south-mum — Mumbai (India)", "ap-south-mum"),
]
OVH_S3_DEFAULT_REGION = "gra"

# Codes earlier releases offered that OVHcloud never served, mapped to the
# real one.  ``syd`` was in the Sydney dropdown entry; its endpoint does not
# resolve, so a saved ``syd`` is read as ``ap-southeast-syd``.
_OVH_S3_REGION_ALIASES: Dict[str, str] = {"syd": "ap-southeast-syd"}


def canonical_ovh_s3_region(region: str) -> str:
    """Return the OVH S3 region code *region* stands for (unchanged if unknown)."""
    return _OVH_S3_REGION_ALIASES.get(region, region)
