"""AWS EC2 instance fetching service with caching support."""

from __future__ import annotations
import asyncio
import boto3
from typing import List, Optional
import logging

from servonaut.services.cache_service import CacheService
from servonaut.services.interfaces import InstanceServiceInterface

logger = logging.getLogger(__name__)


class AWSService(InstanceServiceInterface):
    """Service for fetching EC2 instances from AWS with caching."""

    def __init__(self, cache_service: CacheService):
        """Initialize AWS service.

        Args:
            cache_service: Cache service instance for instance data.
        """
        self.cache_service = cache_service

    async def fetch_instances(self) -> List[dict]:
        """Fetch instances from AWS across all regions.

        Returns:
            List of instance dictionaries with keys: id, name, type, state,
            public_ip, private_ip, region, key_name.
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

        instances = await self.fetch_instances()
        self.cache_service.save(instances)
        return instances

    def _fetch_all_regions(self) -> List[dict]:
        """Blocking fetch of instances across all AWS regions.

        Returns:
            List of instance dictionaries.
        """
        try:
            ec2_client = boto3.client('ec2')
            regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        except Exception as e:
            logger.error(f"Error fetching AWS regions: {e}")
            return []

        instances = []
        for region in regions:
            try:
                logger.debug(f"Fetching instances from region: {region}")
                region_instances = self._fetch_region(region)
                instances.extend(region_instances)
            except Exception as e:
                logger.error(f"Error fetching instances from {region}: {e}")
                continue

        return instances

    def _fetch_region(self, region: str) -> List[dict]:
        """Fetch instances from a specific region.

        Args:
            region: AWS region name (e.g., 'us-east-1').

        Returns:
            List of instance dictionaries for this region.
        """
        try:
            ec2 = boto3.resource('ec2', region_name=region)
            region_instances = []

            for instance in ec2.instances.all():
                instance_data = self._extract_instance_data(instance, region)
                region_instances.append(instance_data)

            return region_instances

        except Exception as e:
            logger.error(f"Error fetching instances from region {region}: {e}")
            return []

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
