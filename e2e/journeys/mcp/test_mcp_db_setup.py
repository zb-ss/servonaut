"""Journey: an MCP client sets up DB credentials without ever seeing them.

Signed in on a Solo plan (the local secret store), an agent calls
``db_setup_scan`` for edge-1: the box is read over SSH (the scripted
``ssh`` answers with two apps' config files) and the result lists each
candidate with its password masked and a staging token. ``db_setup_save``
with one token stores that password in the local secret store and writes
a ``db_profile`` that points at it by name; ``db_setup_remove`` undoes
both. No tool result carries a plaintext password, and a spent token
cannot be saved twice.
"""

from __future__ import annotations

import json
import re

import pytest

from e2e.harness import fleet
from e2e.harness.db_scan import BLOG_PASSWORD, SHOP_PASSWORD, script_db_scan

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
