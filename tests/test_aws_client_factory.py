"""Tests for AWSClientFactory (STS control-plane role + region pinning)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from servonaut.config.schema import AWSConfig
from servonaut.services.aws_client_factory import (
    AWSClientFactory,
    build_aws_client_factory,
)


def test_role_for_default_and_per_account():
    cfg = AWSConfig(
        control_plane_role_arn="arn:aws:iam::111:role/default",
        control_plane_role_arns={"222": "arn:aws:iam::222:role/special"},
    )
    f = AWSClientFactory(cfg)
    assert f.role_for() == "arn:aws:iam::111:role/default"
    assert f.role_for("222") == "arn:aws:iam::222:role/special"
    # Unknown account falls back to the default role.
    assert f.role_for("999") == "arn:aws:iam::111:role/default"
    assert f.uses_assumed_role() is True


def test_mutate_role_is_separate_from_read_role():
    """Writes must never assume the read-only role; they use the mutate role
    (or ambient creds) so a correctly-provisioned read-only role doesn't
    AccessDeny every mutate=true call."""
    cfg = AWSConfig(
        control_plane_role_arn="arn:aws:iam::111:role/read",
        control_plane_mutate_role_arn="arn:aws:iam::111:role/write",
        control_plane_role_arns={"222": "arn:aws:iam::222:role/read"},
        control_plane_mutate_role_arns={"222": "arn:aws:iam::222:role/write"},
    )
    f = AWSClientFactory(cfg)
    assert f.role_for() == "arn:aws:iam::111:role/read"
    assert f.role_for(mutate=True) == "arn:aws:iam::111:role/write"
    assert f.role_for("222", mutate=True) == "arn:aws:iam::222:role/write"


def test_mutate_without_mutate_role_falls_back_to_ambient():
    # Read role set, NO mutate role → write path must use ambient creds, NOT
    # assume the read-only role.
    cfg = AWSConfig(control_plane_role_arn="arn:aws:iam::111:role/read")
    f = AWSClientFactory(cfg)
    assert f.role_for(mutate=True) == ""  # ambient
    with patch("servonaut.services.aws_client_factory.boto3") as boto3_mock:
        f.client("wafv2", region="us-east-1", mutate=True)
    boto3_mock.client.assert_called_once_with("wafv2", region_name="us-east-1")
    assert all(c.args[0] != "sts" for c in boto3_mock.client.call_args_list)


def test_no_role_uses_ambient_chain():
    """With no role configured, client() must NOT call STS — ambient creds."""
    f = AWSClientFactory(AWSConfig())  # empty role config
    assert f.uses_assumed_role() is False
    with patch("servonaut.services.aws_client_factory.boto3") as boto3_mock:
        f.client("ec2", region="us-east-1")
    # Exactly one client built; no assume_role anywhere.
    boto3_mock.client.assert_called_once_with("ec2", region_name="us-east-1")
    # sts client (for assume_role) must never have been requested.
    assert all(
        call.args and call.args[0] != "sts"
        for call in boto3_mock.client.call_args_list
    )


def test_assume_role_builds_client_with_temp_creds_and_caches():
    cfg = AWSConfig(
        control_plane_role_arn="arn:aws:iam::111:role/r",
        assume_role_session_name="servonaut-test",
    )
    f = AWSClientFactory(cfg)

    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIA",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
            "Expiration": expiry,
        }
    }
    svc_client = MagicMock()

    def _client(service, **kwargs):
        return sts if service == "sts" else svc_client

    with patch("servonaut.services.aws_client_factory.boto3") as boto3_mock:
        boto3_mock.client.side_effect = _client
        f.client("wafv2", region="us-east-1")
        f.client("ec2", region="us-east-1")  # second call: creds cached

    # assume_role called exactly once (cached on the second client build).
    sts.assume_role.assert_called_once()
    kwargs = sts.assume_role.call_args.kwargs
    assert kwargs["RoleArn"] == "arn:aws:iam::111:role/r"
    assert kwargs["RoleSessionName"] == "servonaut-test"
    # The service clients were built with the temp credentials.
    svc_calls = [
        c for c in boto3_mock.client.call_args_list if c.args[0] != "sts"
    ]
    assert all(
        c.kwargs.get("aws_session_token") == "TOKEN" for c in svc_calls
    )


def test_external_id_passed_when_set():
    cfg = AWSConfig(
        control_plane_role_arn="arn:aws:iam::111:role/r",
        control_plane_external_id="ext-secret-123",
    )
    f = AWSClientFactory(cfg)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "A", "SecretAccessKey": "S",
            "SessionToken": "T", "Expiration": expiry,
        }
    }
    with patch("servonaut.services.aws_client_factory.boto3") as boto3_mock:
        boto3_mock.client.side_effect = (
            lambda service, **k: sts if service == "sts" else MagicMock()
        )
        f.client("ec2")
    assert sts.assume_role.call_args.kwargs["ExternalId"] == "ext-secret-123"


def test_build_factory_from_appconfig():
    app_cfg = MagicMock()
    app_cfg.aws = AWSConfig(default_region="ap-south-1")
    f = build_aws_client_factory(app_cfg)
    assert isinstance(f, AWSClientFactory)
    assert f.default_region == "ap-south-1"
