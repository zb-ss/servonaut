"""Local AWS endpoint (moto server) and fleet seeding.

One moto server per test process on a loopback port; journeys reach it
through ``AWS_ENDPOINT_URL``, the same variable a user would set for any
other AWS-compatible endpoint. Seeded instances live in a private subnet
without public addressing, so the fleet only ever shows RFC 1918 addresses.

The other seeders cover the AWS screens and tools beyond the fleet: WAF-style
log events, WAF IP sets, security groups, network ACLs, S3 objects and IAM
roles to assume. Account ids are the example ids from the AWS documentation.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

import boto3
from moto.server import ThreadedMotoServer

from e2e.harness.fleet import AwsHost

# Example account ids from the AWS documentation. moto answers requests made
# with an assumed role's credentials in the role's own account, so giving the
# read and write roles different accounts shows which one made a call.
READ_ROLE_ACCOUNT = "111122223333"
MUTATE_ROLE_ACCOUNT = "444455556666"
# The account the suite's own credentials act in (moto's default).
DEFAULT_ACCOUNT = "123456789012"
# Newest seeded log event: a little in the past, well inside any time window.
_NEWEST_LOG_EVENT_AGE_SECONDS = 30

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

    # ------------------------------------------------------------------
    # CloudWatch Logs
    # ------------------------------------------------------------------

    def seed_log_events(
        self,
        group: str,
        messages: Iterable[Any] = (),
        *,
        region: str = "us-east-1",
        stream: str = "e2e-stream",
        spacing_seconds: int = 5,
    ) -> int:
        """Create *group* and write *messages* as its most recent events.

        Events are *spacing_seconds* apart, oldest first, the newest half a
        minute ago. Dict messages are JSON-encoded, as WAF and load balancers
        write them, and a ``timestamp`` key set to None becomes the event's
        own time in milliseconds (see :func:`waf_log_record`). Returns the
        number of events written.
        """
        logs = self.client("logs", region)
        logs.create_log_group(logGroupName=group)
        messages = list(messages)
        if not messages:
            return 0
        logs.create_log_stream(logGroupName=group, logStreamName=stream)
        newest_ms = int((time.time() - _NEWEST_LOG_EVENT_AGE_SECONDS) * 1000)
        count = len(messages)
        events = []
        for index, message in enumerate(messages):
            stamp = newest_ms - (count - 1 - index) * spacing_seconds * 1000
            if isinstance(message, dict):
                if "timestamp" in message and message["timestamp"] is None:
                    message = {**message, "timestamp": stamp}
                message = json.dumps(message)
            events.append({"timestamp": stamp, "message": message})
        logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
        return count

    # ------------------------------------------------------------------
    # Network controls (IP ban targets)
    # ------------------------------------------------------------------

    def seed_waf_ip_set(
        self, name: str, *, region: str = "us-east-1", addresses: Iterable[str] = ()
    ) -> dict[str, str]:
        """A regional WAFv2 IP set; returns its ``Id`` and ``Name``."""
        summary = self.client("wafv2", region).create_ip_set(
            Name=name,
            Scope="REGIONAL",
            IPAddressVersion="IPV4",
            Addresses=list(addresses),
            Description="e2e ban list",
        )["Summary"]
        return {"Id": summary["Id"], "Name": summary["Name"]}

    def waf_addresses(self, ip_set: Mapping[str, str], *, region: str = "us-east-1") -> list[str]:
        response = self.client("wafv2", region).get_ip_set(
            Name=ip_set["Name"], Scope="REGIONAL", Id=ip_set["Id"]
        )
        return sorted(response["IPSet"]["Addresses"])

    def seed_security_group(
        self, name: str, *, region: str = "us-east-1", ec2: Any = None
    ) -> str:
        """A security group in a fresh VPC; returns its id.

        Pass *ec2* to create it with another client, for example one acting
        in a role's account (see :meth:`client_as`).
        """
        ec2 = ec2 or self.client("ec2", region)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        return ec2.create_security_group(
            GroupName=name, Description="e2e security group", VpcId=vpc_id
        )["GroupId"]

    def ingress_ranges(
        self, group_id: str, *, region: str = "us-east-1", ec2: Any = None
    ) -> list[dict]:
        """Every ingress CIDR range of a security group, with its description."""
        ec2 = ec2 or self.client("ec2", region)
        group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
        return [
            {"CidrIp": r.get("CidrIp"), "Description": r.get("Description", "")}
            for permission in group.get("IpPermissions", [])
            for r in permission.get("IpRanges", [])
        ]

    def seed_network_acl(self, *, region: str = "us-east-1") -> str:
        """An empty network ACL in a fresh VPC; returns its id."""
        ec2 = self.client("ec2", region)
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        return ec2.create_network_acl(VpcId=vpc_id)["NetworkAcl"]["NetworkAclId"]

    def nacl_denies(self, nacl_id: str, *, region: str = "us-east-1") -> dict[int, str]:
        """Inbound deny entries of a network ACL: rule number → CIDR."""
        acl = self.client("ec2", region).describe_network_acls(NetworkAclIds=[nacl_id])
        return {
            entry["RuleNumber"]: entry["CidrBlock"]
            for entry in acl["NetworkAcls"][0].get("Entries", [])
            if entry.get("RuleAction") == "deny" and not entry.get("Egress")
        }

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------

    def seed_bucket(
        self, name: str, objects: Optional[Mapping[str, bytes]] = None, *, region: str = "us-east-1"
    ) -> None:
        """A bucket holding *objects* (key → content)."""
        s3 = self.client("s3", region)
        s3.create_bucket(Bucket=name)
        for key, body in (objects or {}).items():
            s3.put_object(Bucket=name, Key=key, Body=body)

    def object_bytes(self, bucket: str, key: str, *, region: str = "us-east-1") -> bytes:
        return self.client("s3", region).get_object(Bucket=bucket, Key=key)["Body"].read()

    # ------------------------------------------------------------------
    # IAM roles assumed through STS
    # ------------------------------------------------------------------

    @staticmethod
    def role_arn(name: str, account_id: str) -> str:
        return f"arn:aws:iam::{account_id}:role/{name}"

    def seed_role(self, name: str, account_id: str) -> str:
        """An IAM role in *account_id* that the suite's credentials may assume.

        Returns its ARN. moto lets a caller assume any role, so the role is
        created from inside its own account.
        """
        arn = self.role_arn(name, account_id)
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        self.client_as(arn, "iam").create_role(
            RoleName=name, AssumeRolePolicyDocument=json.dumps(trust)
        )
        return arn

    def client_as(self, role_arn: str, service: str, region: str = "us-east-1") -> Any:
        """A client acting with the temporary credentials of *role_arn*."""
        credentials = self.client("sts", region).assume_role(
            RoleArn=role_arn, RoleSessionName="e2e-inspector"
        )["Credentials"]
        return boto3.client(
            service,
            region_name=region,
            endpoint_url=self.url,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )


def waf_log_record(
    client_ip: str,
    action: str,
    *,
    uri: str = "/",
    method: str = "GET",
    status: int = 200,
) -> dict:
    """One AWS WAF log record, with the fields Servonaut reads.

    ``httpRequest.clientIp`` and ``action`` drive Top IPs; ``uri`` and
    ``responseCodeSent`` drive the group-by summaries. ``timestamp`` is left
    None: :meth:`MotoAws.seed_log_events` fills in each event's own time.
    """
    return {
        "timestamp": None,
        "formatVersion": 1,
        "webaclId": "e2e-web-acl",
        "terminatingRuleId": "Default_Action" if action == "ALLOW" else "e2e-block-rule",
        "terminatingRuleType": "REGULAR",
        "action": action,
        "httpSourceName": "ALB",
        "httpSourceId": "e2e-load-balancer",
        "httpRequest": {
            "clientIp": client_ip,
            "country": "ZZ",
            "uri": uri,
            "args": "",
            "httpVersion": "HTTP/1.1",
            "httpMethod": method,
        },
        "responseCodeSent": status,
    }


def dump_state(moto: MotoAws) -> str:
    """A short JSON description of the seeded instances (failure artifacts)."""
    try:
        return json.dumps({"us-east-1": moto.describe_names("us-east-1")})
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        return json.dumps({"error": str(exc)})
