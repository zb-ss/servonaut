"""Seed a sandbox home with Servonaut state, built through the real schema.

Configs are never hand-written JSON: :meth:`HomeSeeder.config` builds an
``AppConfig`` and saves it with ``ConfigManager.save``, so a fixture can only
contain what the application itself would write. The instance cache uses the
same format ``CacheService`` writes.

Extra provider accounts are config entries too (:meth:`HomeSeeder.aws_account`,
:meth:`~HomeSeeder.hetzner_account`, :meth:`~HomeSeeder.ovh_account`), with
the placeholder credentials the provider fakes answer for the same label.
AWS accounts are named profiles in the sandbox's shared AWS files
(:meth:`HomeSeeder.aws_profile`).
"""

from __future__ import annotations

import configparser
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional

from servonaut.config.accounts import AWS, AccountRef, account_cache_path
from servonaut.config.manager import ConfigManager
from servonaut.config.schema import CONFIG_VERSION, AppConfig

from e2e.harness import fleet
from e2e.harness.fake_providers import hetzner as fake_hetzner
from e2e.harness.fake_providers import ovh as fake_ovh
from e2e.harness.shims import TERMINAL

# The v5 → v6 migration raises this one value (and only this value).
_V5_CLOUDTRAIL_MAX_EVENTS = 100


def _with_overrides(config: Any, overrides: dict[str, Any]) -> Any:
    """*config* with each override set; an unknown field is an error."""
    for name, value in overrides.items():
        if not hasattr(config, name):
            raise AttributeError(f"{type(config).__name__} has no field {name!r}")
        setattr(config, name, value)
    return config


def aws_access_key(profile: str) -> str:
    """The placeholder access key id a static profile written by the seeder holds."""
    return f"e2e-{profile}-access-key"


class HomeSeeder:
    """Writes Servonaut state into one sandbox home.

    *api_url* is the FakeCloud base URL: seeded configs point the relay at
    it, exactly as the app would derive on its own, so the app does not need
    to rewrite the config at start-up.
    """

    def __init__(self, home: Path, *, api_url: Optional[str] = None) -> None:
        self.home = home
        self.api_url = api_url

    @property
    def data_dir(self) -> Path:
        return self.home / ".servonaut"

    @property
    def config_path(self) -> Path:
        return self.data_dir / "config.json"

    @property
    def cache_path(self) -> Path:
        return self.data_dir / "cache.json"

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def build_config(self, **overrides: Any) -> AppConfig:
        """Return an ``AppConfig`` with the suite's safe defaults applied.

        The terminal is always pinned to the fake terminal, so no code path
        can fall back to detecting a real terminal emulator on the host.
        """
        config = AppConfig()
        config.terminal_emulator = TERMINAL
        config.memory.redaction_enabled = True
        if self.api_url:
            from servonaut.services.relay_manager import derive_relay_urls

            config.relay.base_url, config.relay.mercure_url = derive_relay_urls(self.api_url)
        for name, value in overrides.items():
            if not hasattr(config, name):
                raise AttributeError(f"AppConfig has no field {name!r}")
            setattr(config, name, value)
        if config.terminal_emulator != TERMINAL:
            raise ValueError("seeded configs must keep the fake terminal emulator")
        return config

    def config(self, **overrides: Any) -> AppConfig:
        """Build a config (see :meth:`build_config`) and save it."""
        config = self.build_config(**overrides)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        ConfigManager(config_path=self.config_path).save(config)
        return config

    @staticmethod
    def hetzner_config(**overrides: Any) -> Any:
        """An enabled ``HetznerConfig`` with the primary project's placeholder token.

        Pass it as ``seed.config(hetzner=...)``; the ``providers`` fixture
        points the client at the local stand-in. Extra projects go in
        ``accounts=[HomeSeeder.hetzner_account(...)]``.
        """
        from servonaut.config.schema import HetznerConfig

        config = HetznerConfig(enabled=True, api_token=fake_hetzner.PRIMARY_TOKEN)
        return _with_overrides(config, overrides)

    @staticmethod
    def hetzner_account(label: str, **overrides: Any) -> Any:
        """A ``HetznerAccount`` with the token the fake's project *label* answers.

        The project itself comes from ``providers.add_hetzner_project(label)``
        (or ``fleet.seed_second_accounts``).
        """
        from servonaut.config.schema import HetznerAccount

        account = HetznerAccount(label=label, api_token=fake_hetzner.token_for(label))
        return _with_overrides(account, overrides)

    @staticmethod
    def ovh_config(*, oauth2: bool = False, **overrides: Any) -> Any:
        """An enabled ``OVHConfig`` covering the fleet's cloud project.

        Classic keys by default; *oauth2* uses the primary account's OAuth2
        client instead. Extra accounts go in
        ``accounts=[HomeSeeder.ovh_account(...)]``.
        """
        from servonaut.config.schema import OVHConfig

        config = OVHConfig(
            enabled=True,
            endpoint=fake_ovh.DEFAULT_ENDPOINT,
            cloud_project_ids=[fleet.OVH_PROJECT_ID],
            **_ovh_credentials(fake_ovh.PRIMARY_CREDENTIALS, oauth2),
        )
        return _with_overrides(config, overrides)

    @staticmethod
    def ovh_account(label: str, *, oauth2: bool = False, **overrides: Any) -> Any:
        """An ``OVHAccount`` with the credentials the fake's account *label* answers.

        Classic keys by default, its OAuth2 client with *oauth2*. It covers
        the second inventory's cloud project; the account itself comes from
        ``providers.add_ovh_account(label, endpoint)`` (or
        ``fleet.seed_second_accounts``), so pass the same ``endpoint`` here.
        """
        from servonaut.config.schema import OVHAccount

        account = OVHAccount(
            label=label,
            endpoint=fake_ovh.DEFAULT_ENDPOINT,
            cloud_project_ids=[fleet.OVH_SECOND_PROJECT_ID],
            **_ovh_credentials(fake_ovh.credentials_for(label), oauth2),
        )
        return _with_overrides(account, overrides)

    @staticmethod
    def aws_config(**overrides: Any) -> Any:
        """An ``AWSConfig`` (the primary account keeps the ambient credentials).

        Extra accounts go in ``accounts=[HomeSeeder.aws_account(...)]``.
        """
        from servonaut.config.schema import AWSConfig

        return _with_overrides(AWSConfig(), overrides)

    @staticmethod
    def aws_account(label: str, profile: Optional[str] = None, **overrides: Any) -> Any:
        """An ``AWSAccount`` reached through the named profile *profile* (default: *label*).

        Write the profile with :meth:`aws_profile`. ``regions`` is empty by
        default, so the account lists every region, as the schema's default.
        """
        from servonaut.config.schema import AWSAccount

        return _with_overrides(AWSAccount(label=label, profile=profile or label), overrides)

    def previous_version_config(self, **overrides: Any) -> dict:
        """Save the config as the release before the current schema wrote it.

        The document is produced from a real ``AppConfig`` and then rewound
        one schema step, so it holds exactly what the previous release saved.
        """
        if CONFIG_VERSION != 6:
            raise NotImplementedError(
                f"add the rewind step for schema v{CONFIG_VERSION - 1}"
            )
        self.config(**overrides)
        data = self.read_config()
        data["version"] = CONFIG_VERSION - 1
        data["cloudtrail_max_events"] = _V5_CLOUDTRAIL_MAX_EVENTS
        self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.config_path.chmod(0o600)
        backups = self.data_dir / "backups"
        if backups.exists():
            # Written by the save above; a fresh upgrade has none.
            for backup in backups.iterdir():
                backup.unlink()
        return data

    def read_config(self) -> dict:
        """The config document currently on disk."""
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # AWS shared config and credentials files
    # ------------------------------------------------------------------

    @property
    def aws_config_path(self) -> Path:
        """The shared config file (``AWS_CONFIG_FILE`` points here)."""
        return self.home / ".aws" / "config"

    @property
    def aws_credentials_path(self) -> Path:
        """The shared credentials file (``AWS_SHARED_CREDENTIALS_FILE`` points here)."""
        return self.home / ".aws" / "credentials"

    def aws_profile(
        self,
        name: str,
        *,
        role_arn: Optional[str] = None,
        source_profile: Optional[str] = None,
        region: str = "us-east-1",
    ) -> None:
        """Add the named profile *name* to the sandbox's shared AWS files.

        Without *role_arn* the profile holds static placeholder keys of its
        own (:func:`aws_access_key`), which moto runs in its default account.
        With *role_arn* it assumes that role with the keys of
        *source_profile*, a static profile added before, so its requests run
        in the role's account (see ``MotoAws.seed_account``). A profile named
        explicitly wins over the suite's environment credentials, as it does
        for a user.
        """
        config = _read_ini(self.aws_config_path)
        credentials = _read_ini(self.aws_credentials_path)
        settings = {"region": region}
        if role_arn:
            if source_profile is None or not credentials.has_section(source_profile):
                raise ValueError(
                    f"profile {name!r} needs a static source profile added first, "
                    f"not {source_profile!r}"
                )
            settings.update(role_arn=role_arn, source_profile=source_profile)
        else:
            credentials[name] = {
                "aws_access_key_id": aws_access_key(name),
                "aws_secret_access_key": f"e2e-{name}-secret-key",
            }
            _write_ini(self.aws_credentials_path, credentials)
        config[name if name == "default" else f"profile {name}"] = settings
        _write_ini(self.aws_config_path, config)

    # ------------------------------------------------------------------
    # Instance cache
    # ------------------------------------------------------------------

    def cache(
        self,
        rows: Iterable[dict] | None = None,
        *,
        fresh: bool = True,
        ttl_seconds: int = AppConfig().cache_ttl_seconds,
        account: Optional[str] = None,
    ) -> Path:
        """Write the AWS instance cache; *fresh* False makes it older than the TTL.

        *account* names an extra AWS account, whose cache is a file of its own.
        """
        rows = list(rows) if rows is not None else fleet.cache_rows()
        stamp = datetime.now()
        if not fresh:
            stamp -= timedelta(seconds=ttl_seconds + 600)
        path = self.cache_path
        if account is not None:
            key = AccountRef(AWS, account, primary=False).key
            path = Path(account_cache_path(str(self.cache_path), key))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"timestamp": stamp.isoformat(), "instances": rows}, indent=2),
            encoding="utf-8",
        )
        return path

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------

    def ssh_key(self, name: str) -> Path:
        """A placeholder key file (the SSH shims never read it)."""
        ssh_dir = self.home / ".ssh"
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = ssh_dir / name
        path.write_text("placeholder key for the e2e suite\n", encoding="utf-8")
        path.chmod(0o600)
        return path


def _ovh_credentials(credentials: fake_ovh.OvhCredentials, oauth2: bool) -> dict[str, str]:
    """The config fields for one of an OVH account's credential sets."""
    if oauth2:
        return {"client_id": credentials.client_id, "client_secret": credentials.client_secret}
    return {
        "application_key": credentials.application_key,
        "application_secret": credentials.application_secret,
        "consumer_key": credentials.consumer_key,
    }


def _read_ini(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding="utf-8")
    return parser


def _write_ini(path: Path, parser: configparser.ConfigParser) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        parser.write(handle)
    path.chmod(0o600)
