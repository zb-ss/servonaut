"""Journey: an MCP client sets up DB credentials without ever seeing them.

Signed in on a Solo plan (the local secret store), an agent calls
``db_setup_scan`` for edge-1: the box is read over SSH (the scripted
``ssh`` answers with two apps' config files) and the result lists each
candidate with its password masked and a staging token. ``db_setup_save``
with one token stores that password in the local secret store and writes
a ``db_profile`` that points at it; ``db_setup_remove`` undoes both. The
profile and its secret are keyed by the id of the instance the caller
names (a name resolves to that id), and saved without an ``instance_id``
they belong to the instance that was scanned, never to the database host
found in the config file, which may be ``localhost`` on many boxes. No tool
result, audit row or request carries a plaintext password, and a spent
token cannot be saved twice.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.db_scan import BLOG_PASSWORD, SHOP_PASSWORD, script_db_scan
from e2e.harness.fake_cloud.wire import expected

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

HOST = fleet.EDGE_1
# Secrets are named after the instance id, whatever name the caller used.
BLOG_SECRET = f"db/{HOST.instance_id}/blog"


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
            f"Saved db_profile for edge-1 ({HOST.instance_id}) [blog]: "
            "postgres blog@10.0.2.31:5432/blog"
        ), saved
        assert f"'{BLOG_SECRET}'" in saved
        again = await session.call(
            "db_setup_save", {"token": tokens["blog"], "instance_id": HOST.name}
        )
        assert again.startswith("Error: unknown or expired staging token")

        stored = json.loads(_secrets_file(home.home).read_text(encoding="utf-8"))
        assert BLOG_PASSWORD in json.dumps(stored)
        (profile,) = _profiles(home.home)
        assert (profile["label"], profile["password_secret"]) == ("blog", BLOG_SECRET)
        # The caller's instance owns the profile; the DB host is the staged one.
        assert (profile["instance"], profile["host"], profile["port"]) == (
            HOST.instance_id, "10.0.2.31", 5432
        )

        removed = await session.call(
            "db_setup_remove", {"instance_id": HOST.name, "app": "blog"}
        )
        assert removed.startswith(
            f"Removed db_profile for edge-1 [blog]. Secret '{BLOG_SECRET}' deleted from "
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
    assert profile["instance"] == HOST.instance_id, saved
    assert profile["password_secret"] == f"db/{HOST.instance_id}/shop"
