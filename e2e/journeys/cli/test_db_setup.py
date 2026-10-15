"""Journey: ``servonaut db setup`` finds DB credentials and stores them safely.

With Bitwarden set up as the personal secret store (``servonaut secrets
setup`` against a scripted ``bws``), ``servonaut db setup edge-1`` scans the
box read-only over SSH (the scripted ``ssh`` answers with a Joomla
``configuration.php`` and a ``.env``). On a terminal it lists both databases
by number, the user picks one and keeps the suggested label, and the
password goes straight into the Bitwarden project while the local config
gains a ``db_profile`` that points at it, keyed (like the secret's name) by
the instance id rather than the name typed. Neither the plaintext password,
its masked preview nor the staging token appears in the output, and the
password is in no request to the service, in any encoding. ``--yes`` stores
everything without asking; without a terminal and without ``--yes`` or
``--pick`` the command lists what it found and stores nothing; Ctrl+C at the
question cancels with nothing stored; and without a secret store it refuses
to scan.

Observation, not a gap: ``bws secret create`` takes the value as an
argument, so the password is on ``bws``'s command line (and in the process
table) while it runs. That is how the Bitwarden CLI works; the stand-in
records only a digest of it.

No real SSH connection is made; that tier needs a real ``sshd``.
"""

from __future__ import annotations

import json
import os
import re
import time

import pytest

from e2e.harness import fleet
from e2e.harness.bitwarden import FakeBitwarden
from e2e.harness.bitwarden_shim import digest
from e2e.harness.db_scan import BLOG_PASSWORD, SHOP_PASSWORD, script_db_scan
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.processes import require_armed
from e2e.harness.terminal import _PlainText, _read_until, _start_on_pty

pytestmark = [pytest.mark.e2e_pr]

HOST = fleet.EDGE_1
SHOP_SECRET = f"db/{HOST.instance_id}/shop"
BLOG_SECRET = f"db/{HOST.instance_id}/blog"
TOKEN_VARIABLE = "BWS_ACCESS_TOKEN"
CTRL_C = "\x03"
# The list rows, built from parts so no line holds a literal login@host string.
SHOP_ROW = "@".join((
    r"1  MySQL\s+shop", r"localhost:3306/shop\s+from /var/www/shop/configuration\.php",
))
BLOG_ROW = "@".join((r"2  PostgreSQL\s+blog", r"10\.0\.2\.31:5432/blog\s+from /srv/blog/\.env"))


def _bitwarden_store(journey, cli, home) -> tuple[FakeBitwarden, str]:
    vault = FakeBitwarden(journey.shims, tools=("bws",))
    project = vault.add_project("servers")
    journey.env_overrides[TOKEN_VARIABLE] = vault.access_token
    setup = cli(home, "secrets", "setup", "--yes")
    assert setup.returncode == 0, setup.describe()
    return vault, project


def _on_terminal(journey, home, servonaut_cmd, exchange: list[tuple[str, str]]) -> tuple[int, str]:
    """Run ``db setup edge-1`` on a pty; answer each prompt pattern in turn.

    An answer of :data:`CTRL_C` presses Ctrl+C instead of typing a line.
    """
    process, master = _start_on_pty(
        [*servonaut_cmd, "db", "setup", HOST.name],
        env=journey.child_env(home), cwd=home.base, size=(160, 50),
    )
    screen = _PlainText()
    try:
        for prompt, answer in exchange:
            _read_until(
                master, screen, lambda text, prompt=prompt: re.search(prompt, text) is not None,
                time.monotonic() + 30, f"the prompt /{prompt}/",
            )
            # Ctrl+C is a keystroke, not a line: the terminal turns it into SIGINT.
            os.write(master, (answer if answer == CTRL_C else answer + "\n").encode("utf-8"))
        _read_until(master, screen, lambda _text: False, time.monotonic() + 30, "the result")
        returncode = process.wait(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        os.close(master)
    require_armed(journey.armed_log, pid=process.pid)
    return returncode, screen.text


def _profiles(home) -> list[dict]:
    config = json.loads((home.home / ".servonaut" / "config.json").read_text(encoding="utf-8"))
    return config["db_profiles"]


def _assert_nothing_secret(text: str) -> None:
    assert "dbstg_" not in text and "pw=" not in text and "****" not in text
    for password in (SHOP_PASSWORD, BLOG_PASSWORD):
        assert password not in text and password[-3:] not in text


def test_db_setup_stores_the_password_in_the_vault(
    journey, fake_cloud, cli, account_home, servonaut_cmd
):
    home = account_home("db-setup")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    returncode, text = _on_terminal(journey, home, servonaut_cmd, [
        (r"Store which\? \[1, 2, all, none — Enter = all\]: ", "1"),
        (r"Label for #1 \(Enter = shop\): ", ""),
    ])
    assert returncode == 0, text
    assert "Scanning edge-1 for database settings (read-only)..." in text
    assert re.search(rf"Found 2:\s+{SHOP_ROW}\s+{BLOG_ROW}", text), text
    assert re.search(r"Saved shop to Bitwarden Secrets Manager \(project \S+\)\.", text), text
    assert "Agents and the TUI can now use it (db_processlist, db_top_queries)." in text
    _assert_nothing_secret(text)

    # The scan only read the box: output is discarded, never written.
    (scan,) = journey.shims.calls("ssh")
    remote = scan.argv[-1]
    assert "find " in remote and "sed -n" in remote
    assert not re.search(r"(^|[\s;|&])(rm|mv|cp|tee|dd)\s", remote)
    assert {target for target in re.findall(r"\d?>>?\s*([^\s;|&]+)", remote)} == {"/dev/null"}

    # The password went to Bitwarden, and nowhere else.
    assert vault.secrets(project) == {SHOP_SECRET: SHOP_PASSWORD}
    (profile,) = _profiles(home)
    assert (profile["instance"], profile["engine"], profile["user"], profile["database"],
            profile["password_secret"]) == (HOST.instance_id, "mysql", "shop", "shop", SHOP_SECRET)
    fake_cloud.assert_absent_on_wire(SHOP_PASSWORD, BLOG_PASSWORD, vault.access_token)
    (create,) = [c for c in vault.calls("bws") if c.argv[2:4] == ["secret", "create"]]
    assert create.env[TOKEN_VARIABLE] and vault.access_token not in create.joined
    # Observation (a bws CLI limitation): the value itself is an argument.
    assert create.argv[4:] == [SHOP_SECRET, digest(SHOP_PASSWORD), project]
    fake_cloud.assert_no_unexpected_errors(*expected("no secret store on file"))


def test_ctrl_c_at_the_question_cancels_and_stores_nothing(
    journey, fake_cloud, cli, account_home, servonaut_cmd
):
    home = account_home("db-setup-ctrl-c")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    # The question defaults to "all": a Ctrl+C that only cancelled in the
    # background would leave it waiting, and the next Enter would store both.
    returncode, text = _on_terminal(journey, home, servonaut_cmd, [
        (r"Store which\? \[1, 2, all, none — Enter = all\]: ", CTRL_C),
    ])
    assert returncode == 130, text
    assert text.rstrip().endswith("Cancelled."), text
    assert "Saved" not in text and "Label for" not in text
    _assert_nothing_secret(text)
    assert vault.secrets(project) == {}
    assert _profiles(home) == []


def test_yes_stores_everything_found(journey, fake_cloud, cli, account_home):
    home = account_home("db-setup-yes")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    result = cli(home, "db", "setup", HOST.name, "--yes")
    assert result.returncode == 0, result.describe()
    assert "Saved shop and blog to Bitwarden Secrets Manager" in result.stdout, result.describe()
    _assert_nothing_secret(result.stdout + result.stderr)
    assert vault.secrets(project) == {SHOP_SECRET: SHOP_PASSWORD, BLOG_SECRET: BLOG_PASSWORD}
    assert sorted(p["password_secret"] for p in _profiles(home)) == [BLOG_SECRET, SHOP_SECRET]


def test_without_a_terminal_it_lists_and_stores_nothing(journey, fake_cloud, cli, account_home):
    home = account_home("db-setup-no-tty")
    vault, project = _bitwarden_store(journey, cli, home)
    script_db_scan(journey.shims, HOST)

    # A typed-ahead answer is not taken as consent: there is no terminal.
    result = cli(home, "db", "setup", HOST.name, stdin="1\n")
    assert result.returncode == 5, result.describe()
    assert re.search(rf"Found 2:\s+{SHOP_ROW}\s+{BLOG_ROW}", result.stdout), result.describe()
    assert ("Nothing stored. Run with --yes or --pick N to store without asking."
            in result.stderr)
    _assert_nothing_secret(result.stdout + result.stderr)

    listed = cli(home, "db", "setup", HOST.name, "--json")
    assert listed.returncode == 0, listed.describe()
    report = json.loads(listed.stdout)
    assert [(c["number"], c["label"]) for c in report["candidates"]] == [(1, "shop"), (2, "blog")]
    assert report["saved"] == []
    _assert_nothing_secret(listed.stdout)

    assert vault.secrets(project) == {}
    assert _profiles(home) == []


def test_db_setup_needs_a_secret_store(journey, fake_cloud, cli, account_home):
    home = account_home("db-setup-signed-out", signed_in=False)
    script_db_scan(journey.shims, HOST)

    result = cli(home, "db", "setup", HOST.name)
    assert result.returncode == 1, result.describe()
    assert "you are not signed in" in result.stderr
    assert "Run `servonaut login`, then run this command again." in result.stderr
    assert journey.shims.calls("ssh") == []
