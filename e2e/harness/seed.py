"""Seed a sandbox home with Servonaut state, built through the real schema.

Configs are never hand-written JSON: :meth:`HomeSeeder.config` builds an
``AppConfig`` and saves it with ``ConfigManager.save``, so a fixture can only
contain what the application itself would write. The instance cache uses the
same format ``CacheService`` writes.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional

from servonaut.config.manager import ConfigManager
from servonaut.config.schema import CONFIG_VERSION, AppConfig

from e2e.harness import fleet
from e2e.harness.shims import TERMINAL

# The v5 → v6 migration raises this one value (and only this value).
_V5_CLOUDTRAIL_MAX_EVENTS = 100


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
        """An enabled ``HetznerConfig`` with a placeholder token.

        Pass it as ``seed.config(hetzner=...)``; the ``providers`` fixture
        points the client at the local stand-in.
        """
        from servonaut.config.schema import HetznerConfig

        config = HetznerConfig(enabled=True, api_token="hz-fake-token")
        for name, value in overrides.items():
            if not hasattr(config, name):
                raise AttributeError(f"HetznerConfig has no field {name!r}")
            setattr(config, name, value)
        return config

    @staticmethod
    def ovh_config(**overrides: Any) -> Any:
        """An enabled ``OVHConfig`` (classic keys) covering the fleet's cloud project."""
        from servonaut.config.schema import OVHConfig

        config = OVHConfig(
            enabled=True,
            endpoint="ovh-eu",
            application_key="ak-fake",
            application_secret="as-fake",
            consumer_key="ck-fake",
            cloud_project_ids=[fleet.OVH_PROJECT_ID],
        )
        for name, value in overrides.items():
            if not hasattr(config, name):
                raise AttributeError(f"OVHConfig has no field {name!r}")
            setattr(config, name, value)
        return config

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
    # Instance cache
    # ------------------------------------------------------------------

    def cache(
        self,
        rows: Iterable[dict] | None = None,
        *,
        fresh: bool = True,
        ttl_seconds: int = AppConfig().cache_ttl_seconds,
    ) -> Path:
        """Write the AWS instance cache; *fresh* False makes it older than the TTL."""
        rows = list(rows) if rows is not None else fleet.cache_rows()
        stamp = datetime.now()
        if not fresh:
            stamp -= timedelta(seconds=ttl_seconds + 600)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(
            json.dumps({"timestamp": stamp.isoformat(), "instances": rows}, indent=2),
            encoding="utf-8",
        )
        return self.cache_path

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
