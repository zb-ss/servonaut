"""Verification reports carry the credential tier actually probed."""
import asyncio
from unittest.mock import AsyncMock

import pytest

from servonaut.services.bw_ssh_config_service import BwSshConfigService
from servonaut.services.team_service import TeamService


@pytest.mark.parametrize("tier", ["ca", "vault", "personal", "team", "local"])
def test_personal_and_team_reports_include_resolution_tier(tier):
    api = AsyncMock()
    asyncio.run(BwSshConfigService(api).report_personal_instance_verify("aws", "i-example", "verified", resolution_tier=tier))
    assert api.post.call_args.kwargs["json"]["resolution_tier"] == tier
    asyncio.run(TeamService(api).report_team_server_ssh_verify("example", "server-1", "verified", resolution_tier=tier))
    assert api.post.call_args.kwargs["json"]["resolution_tier"] == tier


def test_invalid_tier_is_rejected_before_transport():
    api = AsyncMock()
    with pytest.raises(ValueError):
        asyncio.run(TeamService(api).report_team_server_ssh_verify("example", "server-1", "verified", resolution_tier="unknown"))
    api.post.assert_not_awaited()
