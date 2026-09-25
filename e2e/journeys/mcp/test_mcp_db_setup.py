"""Journey: an MCP client sets up DB credentials without ever seeing them.

Signed in on a Solo plan (the local secret store), an agent calls
``db_setup_scan`` for edge-1: the box is read over SSH (the scripted
``ssh`` answers with two apps' config files) and the result lists each
candidate with its password masked and a staging token. ``db_setup_save``
with one token stores that password in the local secret store and writes
a ``db_profile`` that points at it by name; ``db_setup_remove`` undoes
both. The profile belongs to the instance the caller names, while the
database host stays the one found on the box. No tool result, audit row or
request carries a plaintext password, and a spent token cannot be saved
twice.

Known gap: saved without an ``instance_id``, the profile (and the name of
its secret) is attached to the database host found in the config file,
``localhost`` here, instead of the instance that was scanned. Every box
whose app talks to a local database would then share, and overwrite, one
``db/localhost/<site>`` secret.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.db_scan import BLOG_PASSWORD, SHOP_PASSWORD, script_db_scan
from e2e.harness.fake_cloud.wire import expected
from e2e.harness.known_gap import KnownGap

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HOST = fleet.EDGE_1


def _secrets_file(home):
    return home / ".servonaut" / "secrets.json"


def _profiles(home) -> list[dict]:
    config = json.loads((home / ".servonaut" / "config.json").read_text(encoding="utf-8"))
    return config["db_profiles"]


async def test_scan_save_and_remove(mcp, journey, fake_cloud, account_home):
    script_db_scan(journey.shims, HOST)
    home = account_home("mcp-db-setup")

    async with mcp(home) as session:
        scan = await session.call("db_setup_scan", {"instance_id": HOST.name})
        assert "Found 2 DB credential candidate(s) for edge-1" in scan
        tokens = {
            label: token for token, label in re.findall(r"token=(dbstg_\S+)  \[(\w+)\]", scan)
        }
        assert set(tokens) == {"shop", "blog"}
        assert "pw=****a1f" in scan and "pw=****20c" in scan

        saved = await session.call(
            "db_setup_save", {"token": tokens["blog"], "instance_id": HOST.name}
        )
        assert saved.startswith(
            "Saved db_profile for edge-1 [blog]: postgres blog@10.0.2.31:5432/blog"
        ), saved
        assert "'db/edge-1/blog'" in saved
        again = await session.call(
            "db_setup_save", {"token": tokens["blog"], "instance_id": HOST.name}
        )
        assert again.startswith("Error: unknown or expired staging token")

        stored = json.loads(_secrets_file(home.home).read_text(encoding="utf-8"))
        assert BLOG_PASSWORD in json.dumps(stored)
        (profile,) = _profiles(home.home)
        assert (profile["label"], profile["password_secret"]) == ("blog", "db/edge-1/blog")
        # The caller's instance names the profile; the DB host is the staged one.
        assert (profile["instance"], profile["host"], profile["port"]) == (
            HOST.name, "10.0.2.31", 5432
        )

        removed = await session.call(
            "db_setup_remove", {"instance_id": HOST.name, "app": "blog"}
        )
        assert removed.startswith(
            "Removed db_profile for edge-1 [blog]. Secret 'db/edge-1/blog' deleted from "
        ), removed

    assert _profiles(home.home) == []
    assert BLOG_PASSWORD not in _secrets_file(home.home).read_text(encoding="utf-8")
    for result in (scan, saved, again, removed):
        for password in (SHOP_PASSWORD, BLOG_PASSWORD):
            assert password not in result
    audit = (home.home / ".servonaut" / "mcp_audit.jsonl").read_text(encoding="utf-8")
    for password in (SHOP_PASSWORD, BLOG_PASSWORD):
        assert password not in audit
    fake_cloud.assert_absent_on_wire(SHOP_PASSWORD, BLOG_PASSWORD)
    # The scan first looks for a vault key for edge-1; it has none.
    fake_cloud.assert_no_unexpected_errors(
        *expected("no secret store on file", "no key reference")
    )


@pytest.mark.xfail(
    strict=True,
    raises=KnownGap,
    reason="db_setup_save without instance_id attaches the profile and its secret "
    "name to the database host (localhost) instead of the scanned instance",
)
async def test_save_without_an_instance_keeps_the_scanned_one(
    mcp, journey, fake_cloud, account_home
):
    script_db_scan(journey.shims, HOST)
    home = account_home("mcp-db-default-instance")

    async with mcp(home) as session:
        scan = await session.call("db_setup_scan", {"instance_id": HOST.name})
        (shop,) = re.findall(r"token=(dbstg_\S+)  \[shop\]", scan)
        saved = await session.call("db_setup_save", {"token": shop})

    (profile,) = _profiles(home.home)
    if profile["instance"] == "localhost" and saved.startswith(
        "Saved db_profile for localhost [shop]"
    ):
        raise KnownGap("the profile was attached to the DB host, not the scanned instance")
    assert profile["instance"] == HOST.name, saved
    assert profile["password_secret"] == "db/edge-1/shop"
