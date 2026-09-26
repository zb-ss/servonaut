"""Local AWS endpoint (moto server) and fleet seeding.

One moto server per test process on a loopback port; journeys reach it
through ``AWS_ENDPOINT_URL``, the same variable a user would set for any
other AWS-compatible endpoint. Seeded instances live in a private subnet
without public addressing, so the fleet only ever shows RFC 1918 addresses.
"""

from __future__ import annotations

import json
import urllib.request
from collections import defaultdict
from typing import Iterable

import boto3
from moto.server import ThreadedMotoServer

from e2e.harness.fleet import AwsHost

_CREDENTIALS = {
    "aws_access_key_id": "testing",
    "aws_secret_access_key": "testing",
    "aws_session_token": "testing",
}


class MotoAws:
    """A running moto server plus helpers to seed it."""

    def __init__(self) -> None:
        self._server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
        # region -> (subnet id, image id); key pairs already created per region.
        self._networks: dict[str, tuple[str, str]] = {}
        self._key_pairs: set[tuple[str, str]] = set()

    def start(self) -> "MotoAws":
        self._server.start()
        return self

    def stop(self) -> None:
        self._server.stop()

    @property
    def url(self) -> str:
        host, port = self._server.get_host_and_port()
        return f"http://{host}:{port}"

    def reset(self) -> None:
        """Drop every resource (moto's own reset endpoint)."""
        request = urllib.request.Request(f"{self.url}/moto-api/reset", data=b"", method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        self._networks.clear()
        self._key_pairs.clear()

    def client(self, service: str, region: str = "us-east-1"):
        return boto3.client(service, region_name=region, endpoint_url=self.url, **_CREDENTIALS)

    def seed_fleet(self, hosts: Iterable[AwsHost]) -> dict[str, str]:
        """Launch *hosts* with their Name tags; returns name → moto instance id."""
        by_region: dict[str, list[AwsHost]] = defaultdict(list)
        for host in hosts:
            by_region[host.region].append(host)
        launched: dict[str, str] = {}
        for region, region_hosts in by_region.items():
            ec2 = self.client("ec2", region)
            subnet_id, image_id = self._network(ec2, region)
            for key_name in {host.key_name for host in region_hosts}:
                if (region, key_name) not in self._key_pairs:
                    ec2.create_key_pair(KeyName=key_name)
                    self._key_pairs.add((region, key_name))
            for host in region_hosts:
                params = {
                    "ImageId": image_id,
                    "MinCount": 1,
                    "MaxCount": 1,
                    "InstanceType": host.instance_type,
                    "KeyName": host.key_name,
                    "SubnetId": subnet_id,
                    "TagSpecifications": [
                        {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": host.name}]}
                    ],
                }
                if host.private_ip:
                    params["PrivateIpAddress"] = host.private_ip
                instance_id = ec2.run_instances(**params)["Instances"][0]["InstanceId"]
                if host.state == "stopped":
                    ec2.stop_instances(InstanceIds=[instance_id])
                launched[host.name] = instance_id
        return launched

    def _network(self, ec2, region: str) -> tuple[str, str]:
        """A private subnet (no public addressing) and an image, per region."""
        if region not in self._networks:
            vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
            subnet = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/16")["Subnet"]
            image_id = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
            self._networks[region] = (subnet["SubnetId"], image_id)
        return self._networks[region]

    def describe_names(self, region: str = "us-east-1") -> list[str]:
        """Name tags of the instances in *region* (for assertions)."""
        reservations = self.client("ec2", region).describe_instances()["Reservations"]
        names = []
        for reservation in reservations:
            for instance in reservation["Instances"]:
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                names.append(tags.get("Name", ""))
        return names


def dump_state(moto: MotoAws) -> str:
    """A short JSON description of the seeded instances (failure artifacts)."""
    try:
        return json.dumps({"us-east-1": moto.describe_names("us-east-1")})
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        return json.dumps({"error": str(exc)})
