"""The neutral inventory every journey uses.

Names are generic (``web-1``, ``db-1``), instance ids are sequential
placeholders, private addresses are RFC 1918 and the only "public" addresses
are well-known public resolvers. Nothing here refers to real infrastructure,
so screenshots and logs uploaded from CI stay safe to publish.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from e2e.harness.fake_providers.hetzner import HetznerState
from e2e.harness.fake_providers.hetzner import SeedServer as HetznerHost
from e2e.harness.fake_providers.ovh import DEFAULT_ENDPOINT as OVH_DEFAULT_ENDPOINT
from e2e.harness.fake_providers.ovh import OvhState
from e2e.harness.fake_providers.ovh import SeedCloudInstance as OvhCloudHost
from e2e.harness.fake_providers.ovh import SeedDedicated as OvhDedicatedHost
from e2e.harness.fake_providers.ovh import SeedVps as OvhVpsHost


@dataclass(frozen=True)
class AwsHost:
    """An EC2 instance, as the fleet table and the instance cache see it."""

    name: str
    instance_id: str
    state: str
    instance_type: str
    region: str
    private_ip: Optional[str]
    public_ip: Optional[str] = None
    key_name: str = "e2e-key"

    def cache_row(self) -> dict:
        """The dict ``AWSService`` stores in the instance cache for this host."""
        return {
            "id": self.instance_id,
            "name": self.name,
            "type": self.instance_type,
            "state": self.state,
            "public_ip": self.public_ip,
            "private_ip": self.private_ip,
            "region": self.region,
            "key_name": self.key_name,
        }


@dataclass(frozen=True)
class CustomHost:
    """A non-cloud server added through the Custom Servers screen."""

    name: str
    host: str
    username: str
    port: int
    ssh_key: str
    provider: str = "colo"
    group: str = "web"


APP_1 = AwsHost("app-1", "i-0000000000000001", "running", "t3.micro", "us-east-1", "10.0.1.21")
DB_1 = AwsHost("db-1", "i-0000000000000002", "stopped", "t3.small", "eu-west-1", "10.0.2.31")
BASTION_1 = AwsHost(
    "bastion-1", "i-0000000000000003", "running", "t3.nano", "us-east-1", "10.0.0.10", "1.1.1.1"
)
EDGE_1 = AwsHost(
    "edge-1", "i-0000000000000004", "running", "t3.micro", "us-east-1", "10.0.0.14", "9.9.9.9"
)
# Only in AWS, never in a seeded cache: appears when the fleet refreshes.
API_1 = AwsHost("api-1", "i-0000000000000006", "running", "t3.micro", "us-east-1", "10.0.1.22")
WORKER_1 = AwsHost(
    "worker-1", "i-0000000000000007", "running", "t3.micro", "us-east-1", "10.0.1.23"
)
# A running instance with no address at all: connecting must fail cleanly.
QUEUE_1 = AwsHost("queue-1", "i-0000000000000005", "running", "t3.micro", "us-east-1", None)

AWS_FLEET = (APP_1, DB_1, BASTION_1, EDGE_1)

# web-1 is not in any seeded config: journeys add it through the UI.
WEB_1 = CustomHost(
    name="web-1",
    host="10.0.0.11",
    username="deploy",
    port=2222,
    ssh_key="~/.ssh/e2e_web1",
)

# Connection profile that reaches private-only AWS hosts through bastion-1.
BASTION_PROFILE = "via-bastion"
BASTION_USER = "ec2-user"


def cache_rows(*hosts: AwsHost) -> list[dict]:
    """Instance-cache rows for *hosts* (the whole AWS fleet by default)."""
    return [host.cache_row() for host in (hosts or AWS_FLEET)]


# ---------------------------------------------------------------------------
# Hetzner Cloud and OVHcloud (served by e2e/harness/fake_providers)
# ---------------------------------------------------------------------------
#
# The same rules apply: generic names, sequential ids, reserved ``.test``
# hostnames, RFC 1918 private addresses, and only well-known public resolver
# addresses as "public" ones. Cloud instance ids are UUIDs derived at run time.

HZ_CACHE_1 = HetznerHost(4200001, "cache-1", "running", "cx23", "fsn1", "8.8.8.8")
HZ_BUILD_1 = HetznerHost(4200002, "build-1", "off", "cx32", "nbg1", "8.8.4.4")
HETZNER_FLEET = (HZ_CACHE_1, HZ_BUILD_1)

OVH_VPS_MAIL_1 = OvhVpsHost(
    "vps-e2e00001.vps.e2e.test", "mail-1", "running", "vps-value-1-2-40", "os-gra7", ("1.0.0.1",)
)
OVH_VPS_PROXY_1 = OvhVpsHost(
    "vps-e2e00002.vps.e2e.test", "proxy-1", "stopped", "vps-value-1-2-40", "os-sbg5", ("9.9.9.10",)
)
OVH_DEDICATED_STORAGE_1 = OvhDedicatedHost(
    "ns0000001.e2e.test", "storage-1.e2e.test", "ok", "gra3", ("149.112.112.112",)
)
# A Public Cloud project id has the API's shape: 32 hexadecimal characters.
OVH_PROJECT_ID = "0e2e0000000000000000000000000001"
OVH_BATCH_1 = OvhCloudHost("batch-1", "ACTIVE", "GRA7", "208.67.222.222", "10.0.3.10")
OVH_BATCH_2 = OvhCloudHost("batch-2", "SHUTOFF", "SBG5", None, "10.0.3.11")
OVH_VPS_FLEET = (OVH_VPS_MAIL_1, OVH_VPS_PROXY_1)
OVH_DEDICATED_FLEET = (OVH_DEDICATED_STORAGE_1,)
OVH_CLOUD_FLEET = (OVH_BATCH_1, OVH_BATCH_2)


def ovh_cloud_id(host: OvhCloudHost, project_id: str = OVH_PROJECT_ID) -> str:
    """The composite id Servonaut shows for a Public Cloud instance."""
    return f"{project_id}/{host.instance_id}"


def seed_provider_fleet(providers: Any, *, hetzner: bool = True, ovh: bool = True) -> None:
    """Put the standard Hetzner and OVH inventory into the fakes."""
    if hetzner:
        providers.hetzner.seed_servers(HETZNER_FLEET)
    if ovh:
        providers.ovh.seed_vps(OVH_VPS_FLEET)
        providers.ovh.seed_dedicated(OVH_DEDICATED_FLEET)
        providers.ovh.seed_cloud_project(OVH_PROJECT_ID, OVH_CLOUD_FLEET)


# ---------------------------------------------------------------------------
# A second account per provider
# ---------------------------------------------------------------------------
#
# Journeys about several accounts per provider give each provider a second
# account. Both accounts of a provider hold a server named web-1, so the
# fleet shows that name twice and a journey has to tell the servers apart by
# account. The primary inventories above stay as they are; the web-1 of each
# primary account is only seeded together with the second account. Everything
# else follows the rules above, and no id repeats within a provider (ids are
# unique across a provider's accounts). Account labels are unique across all
# providers, so each second account has a label of its own.

SHARED_NAME = "web-1"
AWS_SECOND_ACCOUNT = "prod"
HETZNER_SECOND_ACCOUNT = "staging"
OVH_SECOND_ACCOUNT = "backup"

# AWS: the primary account's web-1 (moto's default account) and the second
# account's inventory (see MotoAws.seed_account).
AWS_WEB_1 = AwsHost(
    SHARED_NAME, "i-0000000000000011", "running", "t3.micro", "us-east-1", "10.0.1.31"
)
AWS_SECOND_WEB_1 = AwsHost(
    SHARED_NAME, "i-0000000000000101", "running", "t3.micro", "us-east-1", "10.0.5.21"
)
AWS_SECOND_JOBS_1 = AwsHost(
    "jobs-1", "i-0000000000000102", "stopped", "t3.small", "us-east-1", "10.0.5.31"
)
AWS_SECOND_FLEET = (AWS_SECOND_WEB_1, AWS_SECOND_JOBS_1)

HZ_WEB_1 = HetznerHost(4200003, SHARED_NAME, "running", "cx23", "fsn1", "1.1.1.2")
HZ_SECOND_WEB_1 = HetznerHost(4300001, SHARED_NAME, "running", "cx23", "hel1", "94.140.14.14")
HZ_SECOND_LB_1 = HetznerHost(4300002, "lb-1", "running", "cx32", "fsn1", "94.140.15.15")
HETZNER_SECOND_FLEET = (HZ_SECOND_WEB_1, HZ_SECOND_LB_1)

OVH_VPS_WEB_1 = OvhVpsHost(
    "vps-e2e00003.vps.e2e.test", SHARED_NAME, "running", "vps-value-1-2-40", "os-gra7",
    ("1.0.0.2",),
)
OVH_SECOND_VPS_WEB_1 = OvhVpsHost(
    "vps-e2e00011.vps.e2e.test", SHARED_NAME, "running", "vps-value-1-2-40", "os-gra7",
    ("208.67.220.220",),
)
OVH_SECOND_PROJECT_ID = "0e2e0000000000000000000000000002"
OVH_SECOND_BATCH_3 = OvhCloudHost("batch-3", "ACTIVE", "GRA7", "208.67.222.220", "10.0.6.10")
OVH_SECOND_VPS_FLEET = (OVH_SECOND_VPS_WEB_1,)
OVH_SECOND_CLOUD_FLEET = (OVH_SECOND_BATCH_3,)

# Every region an AWS host above lives in. Seeded configs list instances from
# these regions only: discovering every region the endpoint offers costs one
# call per region on each refresh, which is slow on a busy machine.
AWS_REGIONS = tuple(sorted({
    host.region
    for host in (*AWS_FLEET, API_1, WORKER_1, QUEUE_1, AWS_WEB_1, *AWS_SECOND_FLEET)
}))


def seed_second_accounts(
    providers: Any,
    *,
    hetzner: bool = True,
    ovh: bool = True,
    ovh_endpoint: str = OVH_DEFAULT_ENDPOINT,
) -> tuple[Optional[HetznerState], Optional[OvhState]]:
    """Add the second Hetzner and OVH accounts to the fakes, with their inventory.

    Each primary account also gets its web-1, the name both accounts share.
    The new accounts are labelled HETZNER_SECOND_ACCOUNT and
    OVH_SECOND_ACCOUNT and answer the placeholder credentials
    ``HomeSeeder.hetzner_account`` and ``HomeSeeder.ovh_account`` write for
    the same label (the OVH one on *ovh_endpoint*). Returns the new
    ``(hetzner, ovh)`` states.
    """
    hetzner_project = ovh_account = None
    if hetzner:
        providers.hetzner.seed_servers([HZ_WEB_1])
        hetzner_project = providers.add_hetzner_project(HETZNER_SECOND_ACCOUNT)
        hetzner_project.seed_servers(HETZNER_SECOND_FLEET)
    if ovh:
        providers.ovh.seed_vps([OVH_VPS_WEB_1])
        ovh_account = providers.add_ovh_account(OVH_SECOND_ACCOUNT, ovh_endpoint)
        ovh_account.seed_vps(OVH_SECOND_VPS_FLEET)
        ovh_account.seed_cloud_project(OVH_SECOND_PROJECT_ID, OVH_SECOND_CLOUD_FLEET)
    return hetzner_project, ovh_account
