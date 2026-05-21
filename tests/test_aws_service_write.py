"""Tests for AWSService write methods and describe helpers."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch, call

import pytest

from servonaut.services.aws_service import AWSService, AWSError, AWSNotConfiguredError
from servonaut.services.cache_service import CacheService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cache_service():
    svc = MagicMock(spec=CacheService)
    svc.load.return_value = None
    return svc


@pytest.fixture
def aws_service(cache_service):
    return AWSService(cache_service)


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestValidators:

    def test_validate_instance_id_ok(self, aws_service) -> None:
        aws_service._validate_instance_id("i-0abc12345678def90")  # no raise

    def test_validate_instance_id_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="instance ID"):
            aws_service._validate_instance_id("not-an-id")

    def test_validate_instance_id_empty(self, aws_service) -> None:
        with pytest.raises(ValueError):
            aws_service._validate_instance_id("")

    def test_validate_region_ok(self, aws_service) -> None:
        aws_service._validate_region("us-east-1")

    def test_validate_region_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="region"):
            aws_service._validate_region("notaregion")

    def test_validate_ami_id_ok(self, aws_service) -> None:
        aws_service._validate_ami_id("ami-0abc12345678def90")

    def test_validate_ami_id_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="AMI"):
            aws_service._validate_ami_id("not-an-ami")

    def test_validate_subnet_id_ok(self, aws_service) -> None:
        aws_service._validate_subnet_id("subnet-0abc12345678def90")

    def test_validate_subnet_id_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="subnet"):
            aws_service._validate_subnet_id("bad-id")

    def test_validate_sg_id_ok(self, aws_service) -> None:
        aws_service._validate_sg_id("sg-0abc12345678def90")

    def test_validate_sg_id_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="security group"):
            aws_service._validate_sg_id("notansg")

    def test_validate_count_ok(self, aws_service) -> None:
        aws_service._validate_count(1)
        aws_service._validate_count(10)

    def test_validate_count_bad(self, aws_service) -> None:
        with pytest.raises(ValueError, match="count"):
            aws_service._validate_count(0)
        with pytest.raises(ValueError, match="count"):
            aws_service._validate_count(11)

    def test_validate_name_tag_bad_control_char(self, aws_service) -> None:
        with pytest.raises(ValueError, match="Name tag"):
            aws_service._validate_name_tag("bad\x00name")

    def test_validate_name_tag_empty(self, aws_service) -> None:
        with pytest.raises(ValueError, match="Name tag"):
            aws_service._validate_name_tag("")


# ---------------------------------------------------------------------------
# start_instance
# ---------------------------------------------------------------------------

class TestStartInstance:

    def test_calls_start_instances_api(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.start_instances.return_value = {"StartingInstances": []}
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.start_instance("i-0abc12345678def90", "us-east-1"))
        mock_ec2.start_instances.assert_called_once_with(InstanceIds=["i-0abc12345678def90"])

    def test_validates_instance_id(self, aws_service) -> None:
        with pytest.raises(ValueError, match="instance ID"):
            asyncio.run(aws_service.start_instance("bad-id", "us-east-1"))

    def test_validates_region(self, aws_service) -> None:
        with pytest.raises(ValueError, match="region"):
            asyncio.run(aws_service.start_instance("i-0abc12345678def90", "notaregion"))


# ---------------------------------------------------------------------------
# stop_instance
# ---------------------------------------------------------------------------

class TestStopInstance:

    def test_calls_stop_instances_api(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.stop_instances.return_value = {}
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.stop_instance("i-0abc12345678def90", "eu-west-1"))
        mock_ec2.stop_instances.assert_called_once_with(InstanceIds=["i-0abc12345678def90"])

    def test_validates_inputs(self, aws_service) -> None:
        with pytest.raises(ValueError):
            asyncio.run(aws_service.stop_instance("bad", "us-east-1"))


# ---------------------------------------------------------------------------
# reboot_instance
# ---------------------------------------------------------------------------

class TestRebootInstance:

    def test_calls_reboot_instances_api(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.reboot_instances.return_value = {}
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.reboot_instance("i-0abc12345678def90", "us-west-2"))
        mock_ec2.reboot_instances.assert_called_once_with(InstanceIds=["i-0abc12345678def90"])


# ---------------------------------------------------------------------------
# terminate_instance
# ---------------------------------------------------------------------------

class TestTerminateInstance:

    def test_calls_terminate_instances_api(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.terminate_instances.return_value = {}
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.terminate_instance("i-0abc12345678def90", "us-east-1"))
        mock_ec2.terminate_instances.assert_called_once_with(InstanceIds=["i-0abc12345678def90"])


# ---------------------------------------------------------------------------
# run_instances (TagSpecifications)
# ---------------------------------------------------------------------------

class TestRunInstances:

    def _make_mock_ec2(self):
        mock_ec2 = MagicMock()
        mock_ec2.run_instances.return_value = {
            "Instances": [
                {
                    "InstanceId": "i-0newinstance123",
                    "State": {"Name": "pending"},
                    "InstanceType": "t3.micro",
                }
            ]
        }
        return mock_ec2

    def test_calls_run_instances_with_tag_specs(self, aws_service) -> None:
        mock_ec2 = self._make_mock_ec2()
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.run_instances(
                region="us-east-1",
                ami_id="ami-0abc12345678def90",
                instance_type="t3.micro",
                key_name="my-key",
                subnet_id="subnet-0abc12345678def90",
                security_group_ids=["sg-0abc12345678def90"],
                name_tag="test-server",
                count=1,
            ))
        call_kwargs = mock_ec2.run_instances.call_args[1]
        tag_specs = call_kwargs["TagSpecifications"]
        assert len(tag_specs) == 1
        assert tag_specs[0]["ResourceType"] == "instance"
        assert tag_specs[0]["Tags"] == [{"Key": "Name", "Value": "test-server"}]

    def test_returns_list_of_instance_dicts(self, aws_service) -> None:
        mock_ec2 = self._make_mock_ec2()
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.run_instances(
                region="us-east-1",
                ami_id="ami-0abc12345678def90",
                instance_type="t3.micro",
                key_name="my-key",
                subnet_id="subnet-0abc12345678def90",
                security_group_ids=["sg-0abc12345678def90"],
                name_tag="test-server",
                count=1,
            ))
        assert len(result) == 1
        assert result[0]["id"] == "i-0newinstance123"
        assert result[0]["region"] == "us-east-1"

    def test_validates_empty_security_group_list(self, aws_service) -> None:
        with pytest.raises(ValueError, match="security_group_ids"):
            asyncio.run(aws_service.run_instances(
                region="us-east-1",
                ami_id="ami-0abc12345678def90",
                instance_type="t3.micro",
                key_name="my-key",
                subnet_id="subnet-0abc12345678def90",
                security_group_ids=[],
                name_tag="test",
                count=1,
            ))

    def test_passes_correct_ami_and_type(self, aws_service) -> None:
        mock_ec2 = self._make_mock_ec2()
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.run_instances(
                region="us-east-1",
                ami_id="ami-0abc12345678def90",
                instance_type="t3.micro",
                key_name="my-key",
                subnet_id="subnet-0abc12345678def90",
                security_group_ids=["sg-0abc12345678def90"],
                name_tag="server-1",
                count=1,
            ))
        call_kwargs = mock_ec2.run_instances.call_args[1]
        assert call_kwargs["ImageId"] == "ami-0abc12345678def90"
        assert call_kwargs["InstanceType"] == "t3.micro"


# ---------------------------------------------------------------------------
# list_amis
# ---------------------------------------------------------------------------

class TestListAmis:

    def test_applies_name_filter(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_images.return_value = {"Images": []}
        with patch("boto3.client", return_value=mock_ec2):
            asyncio.run(aws_service.list_amis("us-east-1", name_filter="al2023"))
        filters = mock_ec2.describe_images.call_args[1]["Filters"]
        name_filter = next(f for f in filters if f["Name"] == "name")
        assert "al2023" in name_filter["Values"][0]

    def test_caps_results(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        images = [
            {
                "ImageId": f"ami-{i:017x}",
                "Name": f"image-{i}",
                "CreationDate": f"2024-0{min(i+1,9)}-01T00:00:00Z",
                "Architecture": "x86_64",
                "VirtualizationType": "hvm",
            }
            for i in range(10)
        ]
        mock_ec2.describe_images.return_value = {"Images": images}
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_amis("us-east-1", max_results=3))
        assert len(result) == 3

    def test_returns_plain_dicts(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_images.return_value = {
            "Images": [
                {
                    "ImageId": "ami-0abc12345678def90",
                    "Name": "test-ami",
                    "CreationDate": "2024-01-01T00:00:00Z",
                    "Architecture": "x86_64",
                    "VirtualizationType": "hvm",
                    "Description": "Test AMI",
                }
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_amis("us-east-1"))
        assert isinstance(result[0], dict)
        assert "image_id" in result[0]
        assert "name" in result[0]


# ---------------------------------------------------------------------------
# list_regions
# ---------------------------------------------------------------------------

class TestListRegions:

    def test_returns_sorted_list(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            "Regions": [
                {"RegionName": "us-west-2"},
                {"RegionName": "eu-west-1"},
                {"RegionName": "ap-southeast-1"},
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_regions())
        assert result == sorted(result)
        assert "us-west-2" in result

    def test_builds_client_with_default_bootstrap_region(self, aws_service) -> None:
        """Regression: describe_regions needs a region to build the EC2 client.

        Without an explicit region_name boto3 raises "You must specify a
        region" whenever no ambient AWS_DEFAULT_REGION / ~/.aws/config region
        is set — caught by tpmcp E2E on the launch wizard.
        """
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {"Regions": []}
        with patch("boto3.client", return_value=mock_ec2) as mock_client:
            asyncio.run(aws_service.list_regions())
        assert mock_client.call_args.kwargs.get("region_name") == "us-east-1"

    def test_honors_explicit_bootstrap_region(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {"Regions": []}
        with patch("boto3.client", return_value=mock_ec2) as mock_client:
            asyncio.run(aws_service.list_regions(bootstrap_region="ap-southeast-2"))
        assert mock_client.call_args.kwargs.get("region_name") == "ap-southeast-2"

    def test_empty_bootstrap_region_falls_back(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {"Regions": []}
        with patch("boto3.client", return_value=mock_ec2) as mock_client:
            asyncio.run(aws_service.list_regions(bootstrap_region=""))
        assert mock_client.call_args.kwargs.get("region_name") == "us-east-1"


# ---------------------------------------------------------------------------
# list_instance_types
# ---------------------------------------------------------------------------

class TestListInstanceTypes:

    def test_returns_plain_dicts(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_instance_types.return_value = {
            "InstanceTypes": [
                {
                    "InstanceType": "t3.micro",
                    "VCpuInfo": {"DefaultVCpus": 2},
                    "MemoryInfo": {"SizeInMiB": 1024},
                }
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_instance_types("us-east-1"))
        assert result[0]["instance_type"] == "t3.micro"
        assert result[0]["vcpus"] == 2
        assert result[0]["memory_mib"] == 1024


# ---------------------------------------------------------------------------
# list_key_pairs
# ---------------------------------------------------------------------------

class TestListKeyPairs:

    def test_returns_plain_dicts(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [
                {
                    "KeyName": "my-key",
                    "KeyPairId": "key-0abc123",
                    "KeyFingerprint": "ab:cd:ef",
                }
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_key_pairs("us-east-1"))
        assert result[0]["key_name"] == "my-key"


# ---------------------------------------------------------------------------
# list_subnets
# ---------------------------------------------------------------------------

class TestListSubnets:

    def test_returns_plain_dicts(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_subnets.return_value = {
            "Subnets": [
                {
                    "SubnetId": "subnet-0abc12345678def90",
                    "VpcId": "vpc-0abc",
                    "AvailabilityZone": "us-east-1a",
                    "CidrBlock": "10.0.1.0/24",
                    "AvailableIpAddressCount": 251,
                }
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_subnets("us-east-1"))
        assert result[0]["subnet_id"] == "subnet-0abc12345678def90"
        assert result[0]["available_ip_count"] == 251


# ---------------------------------------------------------------------------
# list_security_groups
# ---------------------------------------------------------------------------

class TestListSecurityGroups:

    def test_returns_plain_dicts(self, aws_service) -> None:
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-0abc12345678def90",
                    "GroupName": "web-sg",
                    "Description": "Web security group",
                    "VpcId": "vpc-0abc",
                }
            ]
        }
        with patch("boto3.client", return_value=mock_ec2):
            result = asyncio.run(aws_service.list_security_groups("us-east-1"))
        assert result[0]["group_id"] == "sg-0abc12345678def90"
        assert result[0]["group_name"] == "web-sg"
