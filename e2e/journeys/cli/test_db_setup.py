"""Journey: ``servonaut db setup`` finds DB credentials and stores them safely.

With Bitwarden set up as the personal secret store (``servonaut secrets
setup`` against a scripted ``bws``), ``servonaut db setup edge-1`` scans the
box read-only over SSH (the scripted ``ssh`` answers with a Joomla
``configuration.php`` and a ``.env``). The output lists each candidate with
its password masked and a staging token; the user types a token and
confirms, and the password goes straight into the Bitwarden project while
the local config gains a ``db_profile`` that points at it by name. The
plaintext password never appears in the output or in any request to the
service, in any encoding. Answering the prompt with a blank line cancels
without storing anything; a mistyped token, or one from an earlier run,
is refused without storing anything; and without a secret store the
command refuses to scan.

Observation, not a gap: ``bws secret create`` takes the value as an
argument, so the password is on ``bws``'s command line (and in the process
table) while it runs. That is how the Bitwarden CLI works; the stand-in
records only a digest of it.

No real SSH connection is made; that tier needs a real ``sshd``.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.bitwarden_shim import digest
from e2e.harness.db_scan import BLOG_PASSWORD, SHOP_PASSWORD, script_db_scan
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.interactive import InteractiveCli

pytestmark = [pytest.mark.e2e_pr]

HOST = fleet.EDGE_1
TOKEN_VARIABLE = "BWS_ACCESS_TOKEN"


def _bitwarden_store(journey, cli, home) -> tuple[FakeBitwarden, str]:
    vault = FakeBitwarden(journey.shims, tools=("bws",))
    project = vault.add_project("servers")
    journey.env_overrides[TOKEN_VARIABLE] = vault.access_token
    setup = cli(home, "secrets", "setup", "--yes")
    assert setup.returncode == 0, setup.describe()
    return vault, project


def _db_setup(journey, servonaut_cmd, home) -> InteractiveCli:
    return InteractiveCli.start(
        servonaut_cmd,
        "db",
        "setup",
        HOST.name,
        env=journey.child_env(home),
        cwd=home.base,
        armed_log=journey.armed_log,
        log=journey.children,
    )


def _profiles(home) -> list[dict]:
    config = json.loads((home.home / ".servonaut" / "config.json").read_text(encoding="utf-8"))
    return config["db_profiles"]


def _save_shop(journey, servonaut_cmd, home) -> tuple[str, object]:
    """Run ``db setup``, pick the shop database and confirm; return its token."""
    with _db_setup(journey, servonaut_cmd, home) as child:
        child.expect(r"Found 2 DB credential candidate\(s\) for edge-1")
        shop = child.expect(
            r"token=(dbstg_\S+)  \[shop\] mysql shop@localhost:3306/shop  pw=\*\*\*\*a1f"
        ).group(1)
        child.expect(r"token=dbstg_\S+  \[blog\] postgres blog@10\.0\.2\.31:5432/blog")
        child.expect(r"Token to save \(blank to cancel\): ")
        child.send(shop)
        child.expect(r"Store credentials for 'edge-1' from dbstg_\S+ into your secret store")
        child.send("y")
    return shop, child.result


def test_db_setup_stores_the_password_in_the_vault(
    journey, fake_cloud, cli, account_home, servonaut_cmd
):
    home = account_home("db-setup")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    _, result = _save_shop(journey, servonaut_cmd, home)
    assert result.returncode == 0, result.describe()
    assert re.search(
        r"Saved db_profile for edge-1 \[shop\]: mysql shop@localhost:3306/shop "
        r"\(password stored in .* as 'db/edge-1/shop'\)",
        result.stdout,
    ), result.describe()

    # The scan only read the box: output is discarded, never written.
    (scan,) = journey.shims.calls("ssh")
    remote = scan.argv[-1]
    assert "find " in remote and "sed -n" in remote
    assert not re.search(r"(^|[\s;|&])(rm|mv|cp|tee|dd)\s", remote)
    assert {target for target in re.findall(r"\d?>>?\s*([^\s;|&]+)", remote)} == {"/dev/null"}

    # The password went to Bitwarden, and nowhere else.
    assert vault.secrets(project) == {"db/edge-1/shop": SHOP_PASSWORD}
    assert [p["password_secret"] for p in _profiles(home)] == ["db/edge-1/shop"]
    (profile,) = _profiles(home)
    assert (profile["instance"], profile["engine"], profile["user"], profile["database"]) == (
        "edge-1", "mysql", "shop", "shop"
    )
    for password in (SHOP_PASSWORD, BLOG_PASSWORD):
        assert password not in result.stdout + result.stderr
    fake_cloud.assert_absent_on_wire(SHOP_PASSWORD, BLOG_PASSWORD, vault.access_token)
    (create,) = [c for c in vault.calls("bws") if c.argv[2:4] == ["secret", "create"]]
    assert create.env[TOKEN_VARIABLE] and vault.access_token not in create.joined
    # Observation (a bws CLI limitation): the value itself is an argument.
    assert create.argv[4:] == ["db/edge-1/shop", digest(SHOP_PASSWORD), project]
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))


def test_a_wrong_or_spent_token_stores_nothing(
    journey, fake_cloud, cli, account_home, servonaut_cmd
):
    home = account_home("db-setup-tokens")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    typo = cli(home, "db", "setup", HOST.name, stdin="dbstg_not-a-token\ny\n")
    assert typo.returncode == 1, typo.describe()
    assert "Error: unknown or expired staging token 'dbstg_not-a-token'" in typo.stdout
    assert vault.secrets(project) == {} and _profiles(home) == []

    spent, first = _save_shop(journey, servonaut_cmd, home)
    assert first.returncode == 0, first.describe()
    # A token from an earlier run is not valid in a new one.
    again = cli(home, "db", "setup", HOST.name, stdin=f"{spent}\ny\n")
    assert again.returncode == 1, again.describe()
    assert f"Error: unknown or expired staging token {spent!r}" in again.stdout
    assert vault.secrets(project) == {"db/edge-1/shop": SHOP_PASSWORD}
    assert [p["password_secret"] for p in _profiles(home)] == ["db/edge-1/shop"]
    creates = [c for c in vault.calls("bws") if c.argv[2:4] == ["secret", "create"]]
    assert len(creates) == 1


def test_blank_answer_cancels_without_storing(journey, fake_cloud, cli, account_home):
    home = account_home("db-setup-cancel")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    result = cli(home, "db", "setup", HOST.name, stdin="\n")
    assert result.returncode == 0, result.describe()
    assert "token=dbstg_" in result.stdout
    assert result.stdout.rstrip().endswith("Cancelled.")
    assert vault.secrets(project) == {}
    assert _profiles(home) == []


def test_db_setup_needs_a_secret_store(journey, fake_cloud, cli, account_home):
    home = account_home("db-setup-signed-out", signed_in=False)
    script_db_scan(journey.shims, HOST)

    result = cli(home, "db", "setup", HOST.name)
    assert result.returncode == 1, result.describe()
    assert "No secret store is active. Run `servonaut login` first" in result.stdout
    assert journey.shims.calls("ssh") == []
