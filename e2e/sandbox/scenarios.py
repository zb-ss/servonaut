"""What a QA sandbox holds: one home, the fakes' inventory, and a fleet summary.

``single``
    The typical user: one account per provider. The AWS fleet (``app-1``,
    ``db-1``, ``bastion-1``, ``edge-1``) with a fresh instance cache, the
    Hetzner and OVH fleets, the custom server ``web-1``, WAF-style CloudWatch
    logs and a few CloudTrail events.
``multi-account``
    Everything in ``single`` plus a second account per provider
    (``fleet.AWS_SECOND_ACCOUNT``, ``HETZNER_SECOND_ACCOUNT``,
    ``OVH_SECOND_ACCOUNT``), each holding a server named ``web-1``, with log
    groups and CloudTrail events of their own.

In both, two servers accept SSH on the loopback SSH servers: ``web-1`` (a
custom server on the target) and ``app-1`` (reached through ``bastion-1``).
Every other address is refused by the SSH pass-through, as an unreachable
server would be.

Imported only after the hermetic environment is in place (it imports
``servonaut``).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from servonaut.utils.instance_resolver import display_name, qualified_reference

from e2e.harness import aws, fleet, remote_fleet
from e2e.harness.aws import waf_log_record
from e2e.harness.cloudtrail_stub import cloudtrail_event
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh
from e2e.harness.seed import HomeSeeder
from e2e.sandbox.state import MULTI_ACCOUNT, SCENARIOS

REGION = "us-east-1"
WAF_LOG_GROUP = "aws-waf-logs-qa"
SECOND_WAF_LOG_GROUP = "aws-waf-logs-qa-second"
APP_LOG_GROUP = "/qa/app"
# Profile holding the static keys the second AWS account's role is assumed with.
AWS_BASE_PROFILE = "base"
CLOUDTRAIL_USER = "qa-operator"


@dataclass(frozen=True)
class FleetEntry:
    """One server as the sandbox's user meets it."""

    shown: str  # the name the fleet table shows
    reference: str  # a reference that always picks this server (CLI, MCP)
    provider: str
    account: str
    instance_id: str
    state: str  # as the provider's API reports it
    ssh: bool  # a real SSH session works (loopback SSH server)


@dataclass
class Seeded:
    fleet: list[FleetEntry]
    notes: list[str]


def _entry(
    provider: str,
    account: str,
    name: str,
    instance_id: str,
    state: str,
    *,
    qualified: bool,
    ssh: bool = False,
) -> FleetEntry:
    """A fleet entry, named with the product's own display rules."""
    row = {
        "name": name,
        "id": instance_id,
        "account": account,
        "account_qualified": qualified,
        "is_custom": provider == "custom",
        "is_hetzner": provider == "hetzner",
        "is_ovh": provider == "ovh",
    }
    if provider == "custom":
        row["account"] = ""
    return FleetEntry(
        shown=display_name(row),
        reference=qualified_reference(row),
        provider=provider,
        account=row["account"] or "-",
        instance_id=instance_id,
        state=state,
        ssh=ssh,
    )


def _waf_traffic() -> list[dict]:
    """A small mix of allowed and blocked requests from public resolver addresses."""
    return (
        [waf_log_record("9.9.9.9", "ALLOW", uri=f"/page/{n}") for n in range(4)]
        + [waf_log_record("9.9.9.9", "BLOCK", uri="/wp-login.php", status=403) for _ in range(2)]
        + [waf_log_record("1.1.1.1", "BLOCK", uri="/xmlrpc.php", status=403) for _ in range(3)]
        + [waf_log_record("8.8.8.8", "ALLOW", uri="/") for _ in range(2)]
    )


def _trail(*names: str) -> list[dict]:
    """Management events a few minutes apart, newest last."""
    now = datetime.now(timezone.utc)
    return [
        cloudtrail_event(name, now - timedelta(minutes=5 * (len(names) - index)),
                         username=CLOUDTRAIL_USER, region=REGION)
        for index, name in enumerate(names)
    ]


class ScenarioSeeder:
    """Seeds the fakes and one home for a scenario."""

    def __init__(self, *, home: Any, moto: Any, cloudtrail: Any, providers: Any,
                 world: Any, api_url: str) -> None:
        self.home = home
        self.moto = moto
        self.cloudtrail = cloudtrail
        self.providers = providers
        self.world = world
        self.seeder = HomeSeeder(home, api_url=api_url)

    def seed(self, scenario: str) -> Seeded:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; choose one of {', '.join(SCENARIOS)}")
        multi = scenario == MULTI_ACCOUNT
        entries: list[FleetEntry] = []
        entries += self._aws(multi)
        entries += self._hetzner(multi)
        entries += self._ovh(multi)
        entries.append(self._custom_web_1())
        self._config(multi)
        notes = [
            "SSH works for the servers marked ssh=yes; every other address is refused "
            "like an unreachable host. Both reach the same loopback SSH server (hostname "
            f"{self.world.target.name}); {remote_fleet.APP_1.name} only through "
            f"{fleet.BASTION_1.name}, by a connection rule.",
            f"CloudWatch: log groups {WAF_LOG_GROUP} (WAF records) and {APP_LOG_GROUP} in {REGION}.",
            f"CloudTrail: a few management events by {CLOUDTRAIL_USER} in {REGION}.",
        ]
        if multi:
            notes.append(
                f"Second accounts: AWS {fleet.AWS_SECOND_ACCOUNT} (profile, assumed role), "
                f"Hetzner {fleet.HETZNER_SECOND_ACCOUNT}, OVH {fleet.OVH_SECOND_ACCOUNT}; "
                f"each holds a server named {fleet.SHARED_NAME}. The AWS second account has "
                f"log group {SECOND_WAF_LOG_GROUP} and CloudTrail events of its own."
            )
        return Seeded(fleet=entries, notes=notes)

    # -- AWS ------------------------------------------------------------

    def _aws(self, multi: bool) -> list[FleetEntry]:
        primary_hosts = list(fleet.AWS_FLEET) + ([fleet.AWS_WEB_1] if multi else [])
        ids = self.moto.seed_fleet(primary_hosts)
        # The cache holds what the endpoint returns: moto's ids, private addresses only.
        rows = [replace(h, instance_id=ids[h.name], public_ip=None).cache_row() for h in primary_hosts]
        self.seeder.cache(rows, fresh=True)
        self.moto.seed_log_events(WAF_LOG_GROUP, _waf_traffic(), region=REGION)
        self.moto.seed_log_events(
            APP_LOG_GROUP, ["GET /health 200", "GET /login 200", "POST /login 401"], region=REGION
        )
        self.cloudtrail.seed(
            _trail("RunInstances", "StopInstances", "StartInstances", "AuthorizeSecurityGroupIngress"),
            region=REGION,
        )
        label = "aws"
        entries = [
            _entry("aws", label, h.name, ids[h.name], h.state, qualified=multi,
                   ssh=h.name == remote_fleet.APP_1.name)
            for h in primary_hosts
        ]
        if not multi:
            return entries

        second = fleet.AWS_SECOND_ACCOUNT
        role = self.moto.seed_role(aws.ACCOUNT_ROLE, aws.SECOND_ACCOUNT)
        second_ids = self.moto.seed_fleet(fleet.AWS_SECOND_FLEET, role_arn=role)
        self.seeder.aws_profile(AWS_BASE_PROFILE)
        self.seeder.aws_profile(second, role_arn=role, source_profile=AWS_BASE_PROFILE)
        second_rows = [
            replace(h, instance_id=second_ids[h.name], public_ip=None).cache_row()
            for h in fleet.AWS_SECOND_FLEET
        ]
        self.seeder.cache(second_rows, fresh=True, account=second)
        self.moto.seed_log_events(SECOND_WAF_LOG_GROUP, _waf_traffic()[:5], region=REGION,
                                  role_arn=role)
        self.cloudtrail.seed(_trail("RebootInstances", "CreateBucket"), region=REGION,
                             account=aws.SECOND_ACCOUNT)
        entries += [
            _entry("aws", second, h.name, second_ids[h.name], h.state, qualified=True)
            for h in fleet.AWS_SECOND_FLEET
        ]
        return entries

    # -- Hetzner and OVH ---------------------------------------------------

    def _hetzner(self, multi: bool) -> list[FleetEntry]:
        fleet.seed_provider_fleet(self.providers, ovh=False)
        primary = list(fleet.HETZNER_FLEET)
        entries = []
        if multi:
            fleet.seed_second_accounts(self.providers, ovh=False)
            primary.append(fleet.HZ_WEB_1)
            entries += [
                _entry("hetzner", fleet.HETZNER_SECOND_ACCOUNT, h.name, str(h.server_id),
                       h.status, qualified=True)
                for h in fleet.HETZNER_SECOND_FLEET
            ]
        return [
            _entry("hetzner", fake_hetzner.PRIMARY_LABEL, h.name, str(h.server_id), h.status,
                   qualified=multi)
            for h in primary
        ] + entries

    def _ovh(self, multi: bool) -> list[FleetEntry]:
        fleet.seed_provider_fleet(self.providers, hetzner=False)
        label = fake_ovh.PRIMARY_LABEL
        vps = list(fleet.OVH_VPS_FLEET)
        if multi:
            fleet.seed_second_accounts(self.providers, hetzner=False)
            vps.append(fleet.OVH_VPS_WEB_1)
        entries = [
            _entry("ovh", label, v.display_name, v.service_name, v.state, qualified=multi)
            for v in vps
        ]
        entries += [
            _entry("ovh", label, d.reverse, d.service_name, d.state, qualified=multi)
            for d in fleet.OVH_DEDICATED_FLEET
        ]
        entries += [
            _entry("ovh", label, c.name, fleet.ovh_cloud_id(c), c.status, qualified=multi)
            for c in fleet.OVH_CLOUD_FLEET
        ]
        if multi:
            second = fleet.OVH_SECOND_ACCOUNT
            entries += [
                _entry("ovh", second, v.display_name, v.service_name, v.state, qualified=True)
                for v in fleet.OVH_SECOND_VPS_FLEET
            ]
            entries += [
                _entry("ovh", second, c.name, fleet.ovh_cloud_id(c, fleet.OVH_SECOND_PROJECT_ID),
                       c.status, qualified=True)
                for c in fleet.OVH_SECOND_CLOUD_FLEET
            ]
        return entries

    # -- SSH and config ------------------------------------------------------

    def _custom_web_1(self) -> FleetEntry:
        self.world.install_client_key(self.home, remote_fleet.WEB_1_KEY)
        server = remote_fleet.web_1(self.world)
        return _entry("custom", "", server.name, f"custom-{server.name}", "-",
                      qualified=False, ssh=True)

    def _config(self, multi: bool) -> None:
        # app-1 is reached through bastion-1 at its private address.
        assert remote_fleet.APP_1.private_ip is not None
        self.world.route(remote_fleet.APP_1.private_ip)
        self.world.install_client_key(self.home, f"{remote_fleet.APP_1.key_name}.pem")
        seed = self.seeder
        aws_accounts = [seed.aws_account(fleet.AWS_SECOND_ACCOUNT)] if multi else []
        hetzner_accounts = [seed.hetzner_account(fleet.HETZNER_SECOND_ACCOUNT)] if multi else []
        ovh_accounts = [seed.ovh_account(fleet.OVH_SECOND_ACCOUNT)] if multi else []
        seed.config(
            aws=seed.aws_config(default_region=REGION, accounts=aws_accounts),
            hetzner=seed.hetzner_config(accounts=hetzner_accounts),
            ovh=seed.ovh_config(accounts=ovh_accounts),
            custom_servers=[remote_fleet.web_1(self.world)],
            cloudwatch_default_region=REGION,
            cloudtrail_default_region=REGION,
            **remote_fleet.bastion_config(),
        )


def fleet_summary(entries: Iterable[FleetEntry]) -> list[dict]:
    return [asdict(entry) for entry in entries]
