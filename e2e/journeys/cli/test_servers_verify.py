"""Journey: ``servonaut servers verify`` probes SSH access with a vault key.

A signed-in user checks that the Bitwarden key stored for a server really
opens it. The command asks the Servonaut API which vault item holds the key,
fetches it with the ``bw`` CLI, runs a non-interactive ``ssh`` probe with the
key in a private temporary file (removed afterwards), and reports the
outcome back to the API. A working key exits 0, a refused one exits 1, and
without a session the command stops before probing anything.
"""

from __future__ import annotations

import json

import pytest

from e2e.harness import fleet
from e2e.harness.fake_cloud.routes_misc import ssh_ref_item_id
from e2e.harness.known_bugs import ProductBug, known_bug
from e2e.harness.seed import HomeSeeder

pytestmark = [pytest.mark.e2e_pr]

WEB_1 = fleet.WEB_1
WEB_1_ID = f"custom-{WEB_1.name}"
# What the fake vault returns as the key body: never parsed, the ssh probe is a stand-in.
KEY_BODY = "placeholder key for the e2e suite"


class VerifyProbeIgnoresServerPort(ProductBug):
    """The verify probe dials port 22 for a server configured on another port."""


def _prepare(journey, fake_cloud, cli, *, ssh_rc: int):
    """A signed-in sandbox whose config holds web-1, a vault, and a scripted ssh."""
    from servonaut.config.schema import CustomServer

    sandbox = journey.new_sandbox()
    HomeSeeder(sandbox.home, api_url=fake_cloud.url).config(
        custom_servers=[
            CustomServer(
                name=WEB_1.name,
                host=WEB_1.host,
                username=WEB_1.username,
                port=WEB_1.port,
                ssh_key=WEB_1.ssh_key,
                provider=WEB_1.provider,
                group=WEB_1.group,
            )
        ]
    )
    fake_cloud.configure(token_outcomes=["success"])
    login = cli(sandbox, "login", "--no-browser")
    assert login.returncode == 0, login.describe()

    # A `bw` stand-in next to the other fake tools, answering for the one item
    # the API names for web-1. The vault counts as unlocked via BW_SESSION.
    ssh_script = journey.shims.path_of("ssh").read_text(encoding="utf-8")
    bw = journey.shims.path_of("bw")
    bw.write_text(ssh_script.replace(' ssh "$@"', ' bw "$@"'), encoding="utf-8")
    bw.chmod(0o755)
    item_id = ssh_ref_item_id(WEB_1.provider, WEB_1_ID)
    journey.shims.when(
        "bw", rf"^get item {item_id}$",
        stdout=json.dumps({"id": item_id, "sshKey": {"privateKey": KEY_BODY}}),
    )
    journey.env_overrides["BW_SESSION"] = "bw-fake-session"
    journey.shims.when("ssh", rf"BatchMode=yes.*{WEB_1.username}@{WEB_1.host} true$", rc=ssh_rc)
    return sandbox, item_id


def _probe(journey) -> list[str]:
    probes = [call.argv for call in journey.shims.calls("ssh")]
    assert len(probes) == 1, probes
    return probes[0]


def _reports(fake_cloud) -> list[dict]:
    return fake_cloud.requests(f"/api/v1/me/instances/{WEB_1.provider}/{WEB_1_ID}/ssh-verify-report")


def test_a_working_vault_key_is_verified_and_reported(journey, fake_cloud, cli):
    sandbox, item_id = _prepare(journey, fake_cloud, cli, ssh_rc=0)

    result = cli(sandbox, "servers", "verify", WEB_1.name)
    assert result.returncode == 0, result.describe()
    assert f"[OK] Verified: {WEB_1.name} ({WEB_1.provider}/{WEB_1_ID})" in result.stdout

    assert [call.argv for call in journey.shims.calls("bw")] == [["get", "item", item_id]]
    argv = _probe(journey)
    assert argv[argv.index("-o") + 1] == "BatchMode=yes"
    key_path = argv[argv.index("-i") + 1]
    # The key lived in a private temporary file that is gone again.
    assert key_path.startswith(str(sandbox.home / ".servonaut" / "tmp"))
    assert not (sandbox.home / ".servonaut" / "tmp").exists() or not any(
        (sandbox.home / ".servonaut" / "tmp").iterdir()
    )

    reports = _reports(fake_cloud)
    assert len(reports) == 1
    assert reports[0]["body"]["status"] == "verified"
    assert reports[0]["body"]["checked_by_client"].startswith("servonaut-cli/")
    assert reports[0]["bearer_ok"]


def test_a_refused_key_is_reported_as_auth_failed(journey, fake_cloud, cli):
    sandbox, _ = _prepare(journey, fake_cloud, cli, ssh_rc=255)

    result = cli(sandbox, "servers", "verify", WEB_1.name)
    assert result.returncode == 1, result.describe()
    assert f"[FAIL] auth_failed: {WEB_1.name}" in result.stdout
    assert [r["body"]["status"] for r in _reports(fake_cloud)] == ["auth_failed"]


@known_bug(
    "servers verify probes a custom server on port 22 unless --port is given, "
    "ignoring the port saved with the server",
    raises=VerifyProbeIgnoresServerPort,
)
def test_the_probe_uses_the_servers_own_port(journey, fake_cloud, cli):
    sandbox, _ = _prepare(journey, fake_cloud, cli, ssh_rc=0)

    result = cli(sandbox, "servers", "verify", WEB_1.name)
    assert result.returncode == 0, result.describe()
    argv = _probe(journey)
    if "-p" not in argv:
        raise VerifyProbeIgnoresServerPort(" ".join(argv))
    assert argv[argv.index("-p") + 1] == str(WEB_1.port)


def test_verify_needs_a_session_and_probes_nothing(journey, fake_cloud, cli):
    sandbox = journey.new_sandbox()
    HomeSeeder(sandbox.home, api_url=fake_cloud.url).config()

    result = cli(sandbox, "servers", "verify", WEB_1.name)
    assert result.returncode == 2, result.describe()
    assert "Not logged in. Run `servonaut login` first." in result.stderr
    assert journey.shims.calls("ssh") == []
    assert fake_cloud.requests() == []
