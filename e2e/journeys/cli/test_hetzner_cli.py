"""Journey: manage Hetzner Cloud from the command line.

``servonaut hetzner`` runs as a real child process against the local Hetzner
stand-in. ``list`` shows the project's servers; ``create`` builds a server
with the requested type, image, location and key in one request. It asks
before creating, so a script passes ``--yes``; without it and without a
terminal it refuses and creates nothing. It also refuses to create a server
without any SSH key. ``destroy``
deletes only after the server's name is typed back, and a wrong answer or a
closed input deletes nothing; ``ssh-keys add`` registers a public key from a
file and rejects a file that holds no public key.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.bootstrap import load_guard
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr]

DEPLOY_KEY = ("e2e-deploy", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Edeploykeyonly00000000000000000 deploy")
CI_KEY = ("e2e-ci", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2Ecikeyonly0000000000000000000000 ci")


def _home(journey, **hetzner):
    sandbox = journey.new_sandbox()
    seeder = HomeSeeder(sandbox.home)
    seeder.config(hetzner=seeder.hetzner_config(**hetzner))
    return sandbox


def _audit(sandbox) -> list[tuple[str, str, bool]]:
    path = sandbox.home / ".servonaut" / "hetzner_audit.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [(r["action"], r["target"], r["success"]) for r in rows]


def test_list_and_create(journey, providers, cli):
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    key = providers.hetzner.seed_ssh_key(*DEPLOY_KEY)
    sandbox = _home(journey)

    listed = cli(sandbox, "hetzner", "list", "--json")
    assert listed.returncode == 0, listed.describe()
    servers = {s["name"]: s for s in json.loads(listed.stdout)}
    assert set(servers) == {h.name for h in fleet.HETZNER_FLEET}
    assert servers[fleet.HZ_CACHE_1.name]["public_ip"] == fleet.HZ_CACHE_1.public_ip
    assert servers[fleet.HZ_BUILD_1.name]["state"] == "stopped"

    table = cli(sandbox, "hetzner", "list", "--state", "running")
    assert table.returncode == 0, table.describe()
    assert fleet.HZ_CACHE_1.name in table.stdout
    assert fleet.HZ_BUILD_1.name not in table.stdout

    # Without a terminal to ask on, create needs --yes and creates nothing.
    unconfirmed = cli(sandbox, "hetzner", "create", "web-2", "--ssh-key", DEPLOY_KEY[0])
    assert unconfirmed.returncode == 3, unconfirmed.describe()
    assert "Pass --yes" in unconfirmed.stderr
    assert providers.requests("hetzner", method="POST") == []

    # Without a key on the command line or in the config, nothing is created.
    refused = cli(sandbox, "hetzner", "create", "web-2", "--yes")
    assert refused.returncode == 1, refused.describe()
    assert "Refusing to create a Hetzner server without SSH keys" in refused.stderr
    assert providers.requests("hetzner", method="POST") == []

    created = cli(
        sandbox, "hetzner", "create", "web-2",
        "--type", "cx32", "--image", "debian-12", "--location", "nbg1",
        "--ssh-key", DEPLOY_KEY[0], "--yes", "--json",
    )
    assert created.returncode == 0, created.describe()
    instance = json.loads(created.stdout)
    assert (instance["name"], instance["type"], instance["state"]) == ("web-2", "cx32", "running")

    posts = providers.requests("hetzner", method="POST", path="/servers")
    assert len(posts) == 1
    body = posts[0]["body"]
    assert {k: body[k] for k in ("name", "server_type", "image", "location", "ssh_keys")} == {
        "name": "web-2",
        "server_type": "cx32",
        "image": "debian-12",
        "location": "nbg1",
        "ssh_keys": [key["id"]],
    }
    assert providers.hetzner.server_named("web-2") is not None
    assert _audit(sandbox) == [
        ("create_server", "web-2", False),  # the refused attempt is audited too
        ("create_server", "web-2", True),
    ]
    assert load_guard().read_log(journey.guard_log) == []


def test_destroy_needs_the_name_typed_back(journey, providers, cli):
    providers.hetzner.seed_servers(fleet.HETZNER_FLEET)
    sandbox = _home(journey)
    doomed = fleet.HZ_CACHE_1

    wrong = cli(sandbox, "hetzner", "destroy", doomed.name, stdin=f"{fleet.HZ_BUILD_1.name}\n")
    assert wrong.returncode == 3, wrong.describe()
    assert "Confirmation mismatch" in wrong.stderr
    assert f"About to PERMANENTLY DELETE Hetzner server: '{doomed.name}'" in wrong.stdout

    closed = cli(sandbox, "hetzner", "destroy", doomed.name, stdin="")
    assert closed.returncode == 3, closed.describe()
    assert "Cancelled." in closed.stdout
    assert providers.requests("hetzner", method="DELETE") == []

    confirmed = cli(sandbox, "hetzner", "destroy", doomed.name, stdin=f"{doomed.name}\n")
    assert confirmed.returncode == 0, confirmed.describe()
    assert f"Deleted Hetzner server '{doomed.name}'." in confirmed.stdout

    deletes = providers.requests("hetzner", method="DELETE")
    assert [e["api_path"] for e in deletes] == [f"/servers/{doomed.server_id}"]
    assert providers.hetzner.server(doomed.server_id) is None
    assert providers.hetzner.server(fleet.HZ_BUILD_1.server_id) is not None

    # --yes skips the prompt (for scripts); an unknown server deletes nothing.
    missing = cli(sandbox, "hetzner", "destroy", "no-such-server", "--yes")
    assert missing.returncode == 1, missing.describe()
    assert "Server not found: no-such-server" in missing.stderr
    assert len(providers.requests("hetzner", method="DELETE")) == 1
    assert _audit(sandbox) == [
        ("delete_server", doomed.name, True),
        ("delete_server", "no-such-server", False),
    ]


def test_ssh_keys_add_from_a_file(journey, providers, cli):
    sandbox = _home(journey)
    good = sandbox.base / "e2e_ci.pub"
    good.write_text(CI_KEY[1] + "\n", encoding="utf-8")
    bad = sandbox.base / "not_a_key.pub"
    bad.write_text("this is not a public key\n", encoding="utf-8")

    rejected = cli(sandbox, "hetzner", "ssh-keys", "add", CI_KEY[0], "--public-key-file", str(bad))
    assert rejected.returncode == 4, rejected.describe()
    assert "public key must start with an SSH algorithm prefix" in rejected.stderr
    assert providers.requests("hetzner", method="POST") == []

    added = cli(sandbox, "hetzner", "ssh-keys", "add", CI_KEY[0], "--public-key-file", str(good))
    assert added.returncode == 0, added.describe()
    assert f"Registered SSH key '{CI_KEY[0]}'" in added.stdout
    posts = providers.requests("hetzner", method="POST", path="/ssh_keys")
    assert [(p["body"]["name"], p["body"]["public_key"]) for p in posts] == [CI_KEY]

    # The same key again is refused by Hetzner and reported, not hidden.
    again = cli(sandbox, "hetzner", "ssh-keys", "add", CI_KEY[0], "--public-key-file", str(good))
    assert again.returncode == 1, again.describe()
    assert "already exists" in again.stderr

    listed = cli(sandbox, "hetzner", "ssh-keys", "list", "--json")
    assert listed.returncode == 0, listed.describe()
    assert [k["name"] for k in json.loads(listed.stdout)] == [CI_KEY[0]]


def test_not_configured_is_reported(journey, providers, cli):
    sandbox = journey.new_sandbox()
    HomeSeeder(sandbox.home).config()

    result = cli(sandbox, "hetzner", "list")
    assert result.returncode == 2, result.describe()
    assert "Hetzner is not configured" in result.stderr
    assert providers.requests("hetzner") == []
