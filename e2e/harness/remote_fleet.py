"""Fleet entries that point at the loopback SSH servers.

The inventory stays neutral (:mod:`e2e.harness.fleet`); only the addresses
change so the real OpenSSH client can reach :class:`~e2e.harness.sshd.SshWorld`:

* ``web-1`` is a custom server on ``127.0.0.1`` at the target's port;
* ``app-1`` is the AWS instance from the standard fleet, private-only,
  reached through the bastion (``bastion-1`` is an alias in the sandbox SSH
  config) at its private address, which the bastion forwards to the target.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from e2e.harness import fleet
from e2e.harness.sshd import BASTION_ALIAS, LOOPBACK, SshWorld

WEB_1_KEY = "e2e_web1"
WEB_1_KEY_PATH = f"~/.ssh/{WEB_1_KEY}"
APP_1 = fleet.APP_1


def web_1(world: SshWorld) -> Any:
    """``web-1`` as a custom server on the loopback target."""
    from servonaut.config.schema import CustomServer

    return CustomServer(
        name=fleet.WEB_1.name,
        host=LOOPBACK,
        username=fleet.WEB_1.username,
        port=world.target.port,
        ssh_key=WEB_1_KEY_PATH,
        provider=fleet.WEB_1.provider,
        group=fleet.WEB_1.group,
    )


def seed_web_1(world: SshWorld, seeder: Any, home: Path, **config: Any) -> Any:
    """Config with ``web-1``, its key in ``~/.ssh``; returns the saved config."""
    world.install_client_key(home, WEB_1_KEY)
    return seeder.config(custom_servers=[web_1(world)], **config)


def bastion_config() -> dict[str, Any]:
    """Config fields that send ``app-*`` hosts through ``bastion-1`` (ProxyJump)."""
    from servonaut.config.schema import ConnectionProfile, ConnectionRule

    return {
        "connection_profiles": [
            ConnectionProfile(
                name=fleet.BASTION_PROFILE,
                bastion_host=BASTION_ALIAS,
                bastion_user=fleet.BASTION_USER,
            )
        ],
        "connection_rules": [
            ConnectionRule(
                name="private apps",
                match_conditions={"name_contains": "app-"},
                profile_name=fleet.BASTION_PROFILE,
            )
        ],
    }


def seed_app_1_behind_bastion(world: SshWorld, seeder: Any, home: Path, **config: Any) -> Any:
    """The AWS fleet in the cache, ``app-1`` routed through the bastion."""
    assert APP_1.private_ip is not None
    world.route(APP_1.private_ip)
    world.install_client_key(home, f"{APP_1.key_name}.pem")
    saved = seeder.config(**bastion_config(), **config)
    seeder.cache(fleet.cache_rows(), fresh=True)
    return saved
