"""The neutral inventory every journey uses.

Names are generic (``web-1``, ``db-1``), instance ids are sequential
placeholders, private addresses are RFC 1918 and the only "public" addresses
are well-known public resolvers. Nothing here refers to real infrastructure,
so screenshots and logs uploaded from CI stay safe to publish.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
