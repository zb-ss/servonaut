"""AWS EC2 instance fetching and management service with caching support."""

from __future__ import annotations

import asyncio
import re
from typing import List, Optional, Tuple
import logging

import boto3

from servonaut.services.cache_service import CacheService
from servonaut.services.interfaces import InstanceServiceInterface

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AWSError(Exception):
    """Base exception for AWS service errors."""


class AWSNotConfiguredError(AWSError):
    """Raised when AWS credentials or region are not configured."""


class AWSFetchError(AWSError):
    """Raised when the instance inventory could not be fetched at all.

    Separates "AWS answered with zero instances" (a valid, cacheable result)
    from "the call never succeeded" (profile, credentials, network), so a
    failed refresh is never persisted as an empty fleet.
    """


# ---------------------------------------------------------------------------
# Module-level compiled regexes for input validation
# ---------------------------------------------------------------------------

_INSTANCE_ID_RE = re.compile(r'^i-[0-9a-f]{8,17}$')
_REGION_RE = re.compile(r'^[a-z]{2}-[a-z]+-\d$')
_AMI_ID_RE = re.compile(r'^ami-[0-9a-f]{8,17}$')
_SUBNET_ID_RE = re.compile(r'^subnet-[0-9a-f]{8,17}$')
_SG_ID_RE = re.compile(r'^sg-[0-9a-f]{8,17}$')
_INSTANCE_TYPE_RE = re.compile(r'^[a-z0-9]+\.[a-z0-9]+$')
_KEY_NAME_RE = re.compile(r'^[\w .\-/]{1,255}$')
_NAME_TAG_RE = re.compile(r'^[^\x00-\x1f\x7f]{1,255}$')


class AWSService(InstanceServiceInterface):
    """Service for fetching EC2 instances from AWS with caching."""

    def __init__(self, cache_service: CacheService):
        """Initialize AWS service.

        Args:
            cache_service: Cache service instance for instance data.
        """
        self.cache_service = cache_service
        # Why the last refresh could not be trusted, or None after a complete
        # successful fetch. Surfaces (TUI notify, MCP list_instances) read it
        # to tell the operator they are looking at cached data.
        self.last_fetch_error: Optional[str] = None
        self._failed_regions: List[str] = []

    async def fetch_instances(self) -> List[dict]:
        """Fetch instances from AWS across all regions.

        Returns:
            List of instance dictionaries with keys: id, name, type, state,
            public_ip, private_ip, region, key_name.

        Raises:
            AWSFetchError: the region list could not be read or every region
                failed. Callers must not treat that as "no instances".
        """
        logger.debug("Fetching instances from AWS")

        # Run blocking boto3 calls in thread pool
        # Python 3.8 compat: use run_in_executor instead of to_thread
        loop = asyncio.get_event_loop()
        instances = await loop.run_in_executor(None, self._fetch_all_regions)

        logger.info(f"Fetched {len(instances)} instances from AWS")
        return instances

    async def fetch_instances_cached(self, force_refresh: bool = False) -> List[dict]:
        """Fetch instances with caching support.

        Args:
            force_refresh: If True, bypass cache and fetch from AWS.

        Returns:
            List of instance dictionaries.
        """
        if not force_refresh:
            cached = self.cache_service.load()
            if cached is not None:
                logger.debug(f"Using cached instances (age: {self.cache_service.get_age()})")
                return cached

        try:
            instances = await self.fetch_instances()
        except AWSFetchError as exc:
            self.last_fetch_error = str(exc)
            stale = self.cache_service.load_any()
            if stale is not None:
                logger.warning(
                    "AWS fetch failed (%s); keeping %d cached instances",
                    exc, len(stale),
                )
                return stale
            logger.warning("AWS fetch failed (%s); no cached instances to fall back on", exc)
            return []

        if self._failed_regions:
            # A partial inventory is shown but never persisted: writing it
            # would silently drop every instance in the failed regions.
            self.last_fetch_error = (
                f"{len(self._failed_regions)} region(s) failed: "
                + ", ".join(self._failed_regions)
            )
            logger.warning("AWS fetch incomplete (%s); cache left untouched", self.last_fetch_error)
            return instances

        self.last_fetch_error = None
        self.cache_service.save(instances)
        return instances

    def _fetch_all_regions(self) -> List[dict]:
        """Blocking fetch of instances across all AWS regions.

        Returns:
            List of instance dictionaries.
        """
        self._failed_regions = []
        try:
            ec2_client = boto3.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        except Exception as e:
            logger.error(f"Error fetching AWS regions: {e}")
            raise AWSFetchError(f"could not list AWS regions: {e}") from e

        instances: List[dict] = []
        last_error: Optional[Exception] = None
        for region in regions:
            try:
                logger.debug(f"Fetching instances from region: {region}")
                instances.extend(self._fetch_region(region))
            except Exception as e:
                logger.error(f"Error fetching instances from {region}: {e}")
                self._failed_regions.append(region)
                last_error = e

        if regions and len(self._failed_regions) == len(regions):
            raise AWSFetchError(
                f"all {len(regions)} AWS regions failed: {last_error}"
            ) from last_error
        return instances

    def _fetch_region(self, region: str) -> List[dict]:
        """Fetch instances from a specific region.

        Args:
            region: AWS region name (e.g., 'us-east-1').

        Returns:
            List of instance dictionaries for this region.
        """
        ec2 = boto3.resource('ec2', region_name=region)
        region_instances = []

        for instance in ec2.instances.all():
            instance_data = self._extract_instance_data(instance, region)
            region_instances.append(instance_data)

        return region_instances

    def _extract_instance_data(self, instance, region: str) -> dict:
        """Extract instance data into standardized dictionary.

        Args:
            instance: boto3 EC2 Instance resource.
            region: AWS region name.

        Returns:
            Instance dictionary with keys: id, name, type, state, public_ip,
            private_ip, region, key_name.
        """
        # Extract Name tag
        name = ''
        for tag in instance.tags or []:
            if tag['Key'] == 'Name':
                name = tag['Value']
                break

        return {
            'id': instance.id,
            'name': name,
            'type': instance.instance_type,
            'state': instance.state['Name'],
            'public_ip': instance.public_ip_address,
            'private_ip': instance.private_ip_address,
            'region': region,
            'key_name': instance.key_name
        }

    # ------------------------------------------------------------------
    # Input validators
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_instance_id(instance_id: str) -> None:
        """Raise ValueError if *instance_id* is not a valid EC2 instance ID.

        Args:
            instance_id: String to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not instance_id or not _INSTANCE_ID_RE.match(instance_id):
            raise ValueError(
                f"Invalid EC2 instance ID {instance_id!r}. "
                "Expected format: i-[0-9a-f]{{8,17}}"
            )

    @staticmethod
    def _validate_region(region: str) -> None:
        """Raise ValueError if *region* is not a valid AWS region name.

        Args:
            region: Region string to validate (e.g. ``"us-east-1"``).

        Raises:
            ValueError: If the format is invalid.
        """
        if not region or not _REGION_RE.match(region):
            raise ValueError(
                f"Invalid AWS region {region!r}. "
                "Expected format: <area>-<direction>-<number> (e.g. us-east-1)"
            )

    @staticmethod
    def _validate_ami_id(ami_id: str) -> None:
        """Raise ValueError if *ami_id* is not a valid AMI ID.

        Args:
            ami_id: AMI ID string to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not ami_id or not _AMI_ID_RE.match(ami_id):
            raise ValueError(
                f"Invalid AMI ID {ami_id!r}. "
                "Expected format: ami-[0-9a-f]{{8,17}}"
            )

    @staticmethod
    def _validate_subnet_id(subnet_id: str) -> None:
        """Raise ValueError if *subnet_id* is not a valid subnet ID.

        Args:
            subnet_id: Subnet ID string to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not subnet_id or not _SUBNET_ID_RE.match(subnet_id):
            raise ValueError(
                f"Invalid subnet ID {subnet_id!r}. "
                "Expected format: subnet-[0-9a-f]{{8,17}}"
            )

    @staticmethod
    def _validate_sg_id(sg_id: str) -> None:
        """Raise ValueError if *sg_id* is not a valid security group ID.

        Args:
            sg_id: Security group ID string to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not sg_id or not _SG_ID_RE.match(sg_id):
            raise ValueError(
                f"Invalid security group ID {sg_id!r}. "
                "Expected format: sg-[0-9a-f]{{8,17}}"
            )

    @staticmethod
    def _validate_instance_type(instance_type: str) -> None:
        """Raise ValueError if *instance_type* is not a valid EC2 instance type.

        Args:
            instance_type: Instance type string (e.g. ``"t3.micro"``).

        Raises:
            ValueError: If the format is invalid.
        """
        if not instance_type or not _INSTANCE_TYPE_RE.match(instance_type):
            raise ValueError(
                f"Invalid instance type {instance_type!r}. "
                "Expected format: <family>.<size> (e.g. t3.micro)"
            )

    @staticmethod
    def _validate_key_name(key_name: str) -> None:
        """Raise ValueError if *key_name* is not a valid EC2 key pair name.

        Args:
            key_name: Key pair name to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not key_name or not _KEY_NAME_RE.match(key_name):
            raise ValueError(
                f"Invalid key pair name {key_name!r}. "
                "Must be 1–255 chars, alphanumeric and . - / space allowed."
            )

    @staticmethod
    def _validate_name_tag(name_tag: str) -> None:
        """Raise ValueError if *name_tag* contains invalid characters.

        Args:
            name_tag: EC2 Name tag value to validate.

        Raises:
            ValueError: If the format is invalid.
        """
        if not name_tag or not _NAME_TAG_RE.match(name_tag):
            raise ValueError(
                f"Invalid Name tag {name_tag!r}. "
                "Must be 1–255 printable characters."
            )

    @staticmethod
    def _validate_count(count: int) -> None:
        """Raise ValueError if *count* is outside the allowed range 1–10.

        Args:
            count: Number of instances to launch.

        Raises:
            ValueError: If *count* is out of range.
        """
        if not isinstance(count, int) or not (1 <= count <= 10):
            raise ValueError(
                f"Invalid instance count {count!r}. Must be an integer between 1 and 10."
            )

    # ------------------------------------------------------------------
    # EC2 lifecycle write methods
    # ------------------------------------------------------------------

    async def start_instance(self, instance_id: str, region: str) -> dict:
        """Start a stopped EC2 instance.

        Args:
            instance_id: EC2 instance ID (e.g. ``"i-0abc12345678def90"``).
            region: AWS region where the instance lives.

        Returns:
            Raw ``StartInstances`` response dict from boto3.

        Raises:
            ValueError: If *instance_id* or *region* fails validation.
        """
        self._validate_instance_id(instance_id)
        self._validate_region(region)
        return await asyncio.to_thread(self._start_instance_sync, instance_id, region)

    def _start_instance_sync(self, instance_id: str, region: str) -> dict:
        ec2 = boto3.client('ec2', region_name=region)
        return ec2.start_instances(InstanceIds=[instance_id])

    async def stop_instance(self, instance_id: str, region: str) -> dict:
        """Stop a running EC2 instance (EBS-backed, can be restarted).

        Args:
            instance_id: EC2 instance ID.
            region: AWS region where the instance lives.

        Returns:
            Raw ``StopInstances`` response dict from boto3.

        Raises:
            ValueError: If *instance_id* or *region* fails validation.
        """
        self._validate_instance_id(instance_id)
        self._validate_region(region)
        return await asyncio.to_thread(self._stop_instance_sync, instance_id, region)

    def _stop_instance_sync(self, instance_id: str, region: str) -> dict:
        ec2 = boto3.client('ec2', region_name=region)
        return ec2.stop_instances(InstanceIds=[instance_id])

    async def reboot_instance(self, instance_id: str, region: str) -> dict:
        """Reboot a running EC2 instance.

        Args:
            instance_id: EC2 instance ID.
            region: AWS region where the instance lives.

        Returns:
            Raw ``RebootInstances`` response dict from boto3.

        Raises:
            ValueError: If *instance_id* or *region* fails validation.
        """
        self._validate_instance_id(instance_id)
        self._validate_region(region)
        return await asyncio.to_thread(self._reboot_instance_sync, instance_id, region)

    def _reboot_instance_sync(self, instance_id: str, region: str) -> dict:
        ec2 = boto3.client('ec2', region_name=region)
        return ec2.reboot_instances(InstanceIds=[instance_id])

    async def terminate_instance(self, instance_id: str, region: str) -> dict:
        """Permanently terminate an EC2 instance.

        Args:
            instance_id: EC2 instance ID.
            region: AWS region where the instance lives.

        Returns:
            Raw ``TerminateInstances`` response dict from boto3.

        Raises:
            ValueError: If *instance_id* or *region* fails validation.
        """
        self._validate_instance_id(instance_id)
        self._validate_region(region)
        return await asyncio.to_thread(self._terminate_instance_sync, instance_id, region)

    def _terminate_instance_sync(self, instance_id: str, region: str) -> dict:
        ec2 = boto3.client('ec2', region_name=region)
        return ec2.terminate_instances(InstanceIds=[instance_id])

    async def run_instances(
        self,
        *,
        region: str,
        ami_id: str,
        instance_type: str,
        key_name: str,
        subnet_id: str,
        security_group_ids: List[str],
        name_tag: str,
        count: int = 1,
    ) -> List[dict]:
        """Launch one or more new EC2 instances.

        Args:
            region: AWS region to launch in.
            ami_id: AMI ID to use (e.g. ``"ami-0abc12345678def90"``).
            instance_type: EC2 instance type (e.g. ``"t3.micro"``).
            key_name: Name of the EC2 key pair to assign.
            subnet_id: VPC subnet ID for network placement.
            security_group_ids: Non-empty list of security group IDs.
            name_tag: Value for the ``Name`` tag on the launched instances.
            count: Number of instances to launch (1–10, default 1).

        Returns:
            List of instance dicts extracted from the ``RunInstances`` response,
            each containing ``id``, ``state``, ``type``, ``region``.

        Raises:
            ValueError: If any argument fails validation.
        """
        self._validate_region(region)
        self._validate_ami_id(ami_id)
        self._validate_instance_type(instance_type)
        self._validate_key_name(key_name)
        self._validate_subnet_id(subnet_id)
        if not security_group_ids:
            raise ValueError("security_group_ids must be a non-empty list")
        for sg_id in security_group_ids:
            self._validate_sg_id(sg_id)
        self._validate_name_tag(name_tag)
        self._validate_count(count)

        return await asyncio.to_thread(
            self._run_instances_sync,
            region,
            ami_id,
            instance_type,
            key_name,
            subnet_id,
            security_group_ids,
            name_tag,
            count,
        )

    def _run_instances_sync(
        self,
        region: str,
        ami_id: str,
        instance_type: str,
        key_name: str,
        subnet_id: str,
        security_group_ids: List[str],
        name_tag: str,
        count: int,
    ) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            SubnetId=subnet_id,
            SecurityGroupIds=security_group_ids,
            MinCount=count,
            MaxCount=count,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': name_tag}],
                }
            ],
        )
        return [
            {
                'id': inst['InstanceId'],
                'state': inst['State']['Name'],
                'type': inst['InstanceType'],
                'region': region,
            }
            for inst in response.get('Instances', [])
        ]

    # ------------------------------------------------------------------
    # Describe helpers (read-only, async via to_thread)
    # ------------------------------------------------------------------

    async def list_regions(self, bootstrap_region: str = "us-east-1") -> List[str]:
        """List all enabled AWS regions.

        ``describe_regions`` is a global call, but boto3 still needs *some*
        region to construct the EC2 client endpoint. ``bootstrap_region`` is
        only used to build that client — the result is the full region list
        regardless of which region the call is made from. Callers should pass
        the user's configured default region so the lookup works even when no
        ambient ``AWS_DEFAULT_REGION`` / ``~/.aws/config`` region is set.

        Args:
            bootstrap_region: Region used to construct the EC2 client.
                Falls back to ``us-east-1`` when empty.

        Returns:
            Sorted list of region name strings.
        """
        return await asyncio.to_thread(self._list_regions_sync, bootstrap_region)

    def _list_regions_sync(self, bootstrap_region: str = "us-east-1") -> List[str]:
        ec2 = boto3.client('ec2', region_name=bootstrap_region or "us-east-1")
        response = ec2.describe_regions(AllRegions=False)
        return sorted(r['RegionName'] for r in response.get('Regions', []))

    async def list_amis(
        self,
        region: str,
        name_filter: str = "",
        owners: Tuple[str, ...] = ("amazon",),
        max_results: int = 50,
    ) -> List[dict]:
        """List available AMIs in *region*, sorted newest-first.

        Args:
            region: AWS region to search.
            name_filter: Optional glob pattern for AMI name filtering.
                Applied via the ``Name`` filter; ``*`` wildcards allowed.
                If empty, no name filter is applied.
            owners: Tuple of AMI owner IDs / aliases (default ``("amazon",)``).
            max_results: Maximum number of AMIs to return (default 50).

        Returns:
            List of AMI dicts with keys: ``image_id``, ``name``,
            ``description``, ``creation_date``, ``architecture``,
            ``virtualization_type``.

        Raises:
            ValueError: If *region* fails validation.
        """
        self._validate_region(region)
        return await asyncio.to_thread(
            self._list_amis_sync, region, name_filter, list(owners), max_results
        )

    def _list_amis_sync(
        self,
        region: str,
        name_filter: str,
        owners: List[str],
        max_results: int,
    ) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        filters = [{'Name': 'state', 'Values': ['available']}]
        if name_filter:
            filters.append({'Name': 'name', 'Values': [f'*{name_filter}*']})
        response = ec2.describe_images(Owners=owners, Filters=filters)
        images = response.get('Images', [])
        # Sort descending by creation date then cap
        images.sort(key=lambda x: x.get('CreationDate', ''), reverse=True)
        images = images[:max_results]
        return [
            {
                'image_id': img['ImageId'],
                'name': img.get('Name', ''),
                'description': img.get('Description', ''),
                'creation_date': img.get('CreationDate', ''),
                'architecture': img.get('Architecture', ''),
                'virtualization_type': img.get('VirtualizationType', ''),
            }
            for img in images
        ]

    async def list_instance_types(
        self, region: str, max_results: int = 100
    ) -> List[dict]:
        """List available EC2 instance types in *region*.

        Args:
            region: AWS region to query.
            max_results: Maximum number of instance types to return.

        Returns:
            List of dicts with keys: ``instance_type``, ``vcpus``,
            ``memory_mib``.

        Raises:
            ValueError: If *region* fails validation.
        """
        self._validate_region(region)
        return await asyncio.to_thread(self._list_instance_types_sync, region, max_results)

    def _list_instance_types_sync(self, region: str, max_results: int) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_instance_types(MaxResults=max_results)
        return [
            {
                'instance_type': it['InstanceType'],
                'vcpus': it.get('VCpuInfo', {}).get('DefaultVCpus', 0),
                'memory_mib': it.get('MemoryInfo', {}).get('SizeInMiB', 0),
            }
            for it in response.get('InstanceTypes', [])
        ]

    async def list_key_pairs(self, region: str) -> List[dict]:
        """List EC2 key pairs in *region*.

        Args:
            region: AWS region to query.

        Returns:
            List of dicts with keys: ``key_name``, ``key_pair_id``,
            ``fingerprint``.

        Raises:
            ValueError: If *region* fails validation.
        """
        self._validate_region(region)
        return await asyncio.to_thread(self._list_key_pairs_sync, region)

    def _list_key_pairs_sync(self, region: str) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_key_pairs()
        return [
            {
                'key_name': kp['KeyName'],
                'key_pair_id': kp.get('KeyPairId', ''),
                'fingerprint': kp.get('KeyFingerprint', ''),
            }
            for kp in response.get('KeyPairs', [])
        ]

    async def list_subnets(self, region: str) -> List[dict]:
        """List VPC subnets in *region*.

        Args:
            region: AWS region to query.

        Returns:
            List of dicts with keys: ``subnet_id``, ``vpc_id``,
            ``availability_zone``, ``cidr_block``, ``available_ip_count``.

        Raises:
            ValueError: If *region* fails validation.
        """
        self._validate_region(region)
        return await asyncio.to_thread(self._list_subnets_sync, region)

    def _list_subnets_sync(self, region: str) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_subnets()
        return [
            {
                'subnet_id': sn['SubnetId'],
                'vpc_id': sn.get('VpcId', ''),
                'availability_zone': sn.get('AvailabilityZone', ''),
                'cidr_block': sn.get('CidrBlock', ''),
                'available_ip_count': sn.get('AvailableIpAddressCount', 0),
            }
            for sn in response.get('Subnets', [])
        ]

    async def list_security_groups(self, region: str) -> List[dict]:
        """List EC2 security groups in *region*.

        Args:
            region: AWS region to query.

        Returns:
            List of dicts with keys: ``group_id``, ``group_name``,
            ``description``, ``vpc_id``.

        Raises:
            ValueError: If *region* fails validation.
        """
        self._validate_region(region)
        return await asyncio.to_thread(self._list_security_groups_sync, region)

    def _list_security_groups_sync(self, region: str) -> List[dict]:
        ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_security_groups()
        return [
            {
                'group_id': sg['GroupId'],
                'group_name': sg.get('GroupName', ''),
                'description': sg.get('Description', ''),
                'vpc_id': sg.get('VpcId', ''),
            }
            for sg in response.get('SecurityGroups', [])
        ]
