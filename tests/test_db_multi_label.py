"""Multiple DBs per instance — app/site label discrimination.

One instance can host several websites, each with its own DB. Each is stored
under a label derived from the config path; the read tools select one by
naming the site (``app=``).
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools
from servonaut.services.db_credential_scanner import (
    DBCandidate, derive_app_label, sanitize_label,
)

_PW = "s3cr3t-multi-db-pw"


def _tools(cfg: AppConfig):
    """ServonautTools whose config_manager.update actually mutates the config,
    so multi-save persistence can be exercised."""
    cm = MagicMock()
    cm.get.return_value = cfg

    def _update(**kwargs):
        for k, v in kwargs.items():
            setattr(cfg, k, v)
    cm.update.side_effect = _update

    sp = MagicMock()
    sp.set_secret = AsyncMock()
    sp.delete_secret = AsyncMock(return_value=True)
    sp.get_secret = AsyncMock(return_value=_PW)

    return ServonautTools(
        config_manager=cm, aws_service=MagicMock(),
        custom_server_service=MagicMock(), cache_service=MagicMock(),
        ssh_service=MagicMock(), connection_service=MagicMock(),
        scp_service=MagicMock(), guard=CommandGuard(cfg.mcp),
        audit=MagicMock(), secret_provider=sp,
    )


# ---------------------------------------------------------------------------
# Label derivation
# ---------------------------------------------------------------------------


def test_derive_app_label_domain_and_app():
    assert derive_app_label("/var/www/shop.example.com/.env") == "shop.example.com"
    assert derive_app_label("/home/deploy/blog/current/.env") == "blog"
    assert derive_app_label("/var/www/html/wp-config.php") == ""   # bare root
    assert derive_app_label("") == ""


def test_sanitize_label():
    assert sanitize_label("Shop.Example.com") == "shop.example.com"
    assert sanitize_label("my site/app") == "my-site-app"


# ---------------------------------------------------------------------------
# Save: labelled secret names + coexistence
# ---------------------------------------------------------------------------


def test_two_sites_coexist_with_distinct_secrets():
    cfg = AppConfig()
    t = _tools(cfg)
    t._db_staging["a"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "u1", _PW, "db1",
        "/var/www/shop.example.com/.env")
    t._db_staging["b"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "u2", _PW, "db2",
        "/var/www/blog.example.com/.env")

    out_a = asyncio.run(t.db_setup_save("a", instance_id="web"))
    out_b = asyncio.run(t.db_setup_save("b", instance_id="web"))

    assert "shop.example.com" in out_a and "blog.example.com" in out_b
    # Two profiles, distinct labels + distinct secret names.
    assert len(cfg.db_profiles) == 2
    labels = {p.label for p in cfg.db_profiles}
    assert labels == {"shop.example.com", "blog.example.com"}
    secrets = {p.password_secret for p in cfg.db_profiles}
    assert secrets == {"db/web/shop.example.com", "db/web/blog.example.com"}


def test_resaving_same_site_updates_in_place():
    cfg = AppConfig()
    t = _tools(cfg)
    for _ in range(2):
        t._db_staging["x"] = DBCandidate(
            "mysql", "127.0.0.1", 3306, "u", _PW, "d",
            "/var/www/shop.example.com/.env")
        asyncio.run(t.db_setup_save("x", instance_id="web"))
    # Same (instance, label) → single profile, not duplicated.
    assert len(cfg.db_profiles) == 1
    assert cfg.db_profiles[0].label == "shop.example.com"


def test_explicit_label_override():
    cfg = AppConfig()
    t = _tools(cfg)
    t._db_staging["x"] = DBCandidate(
        "mysql", "127.0.0.1", 3306, "u", _PW, "d", "/var/www/html/.env")
    asyncio.run(t.db_setup_save("x", instance_id="web", label="Storefront"))
    assert cfg.db_profiles[0].label == "Storefront"
    assert cfg.db_profiles[0].password_secret == "db/web/storefront"


# ---------------------------------------------------------------------------
# Read-tool selection via app=
# ---------------------------------------------------------------------------


def _two_db_config():
    return AppConfig(db_profiles=[
        DBProfile(instance="web", label="shop.example.com",
                  password_secret="db/web/shop.example.com", user="u1"),
        DBProfile(instance="web", label="blog.example.com",
                  password_secret="db/web/blog.example.com", user="u2"),
    ])


def test_resolve_db_requires_app_when_multiple():
    t = _tools(_two_db_config())
    t._find_instance = AsyncMock(return_value={"id": "web", "name": "web"})
    _, profile, _, err = asyncio.run(
        t._resolve_db("web", "db_processlist", {}, app="")
    )
    assert profile is None
    assert "2 databases" in err
    assert "shop.example.com" in err and "blog.example.com" in err


def test_resolve_db_selects_by_loose_app_match():
    t = _tools(_two_db_config())
    t._find_instance = AsyncMock(return_value={"id": "web", "name": "web"})
    # "shop" is a unique prefix of shop.example.com
    _, profile, _, err = asyncio.run(
        t._resolve_db("web", "db_processlist", {}, app="shop")
    )
    assert not err
    assert profile.label == "shop.example.com"


def test_resolve_db_app_no_match_lists_sites():
    t = _tools(_two_db_config())
    t._find_instance = AsyncMock(return_value={"id": "web", "name": "web"})
    _, profile, _, err = asyncio.run(
        t._resolve_db("web", "db_processlist", {}, app="nonexistent")
    )
    assert profile is None
    assert "no db on web matches" in err.lower()


def test_resolve_db_single_db_needs_no_app():
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="web", label="", password_secret="db/web", user="u"),
    ])
    t = _tools(cfg)
    t._find_instance = AsyncMock(return_value={"id": "web", "name": "web"})
    _, profile, _, err = asyncio.run(
        t._resolve_db("web", "db_processlist", {})
    )
    assert not err
    assert profile.password_secret == "db/web"


# ---------------------------------------------------------------------------
# Remove one site of several
# ---------------------------------------------------------------------------


def test_remove_requires_app_when_multiple():
    cfg = _two_db_config()
    t = _tools(cfg)
    out = asyncio.run(t.db_setup_remove("web"))
    assert "2 databases" in out
    assert len(cfg.db_profiles) == 2  # nothing removed


def test_remove_one_site_keeps_the_other():
    cfg = _two_db_config()
    t = _tools(cfg)
    out = asyncio.run(t.db_setup_remove("web", app="shop"))
    assert "shop.example.com" in out
    assert len(cfg.db_profiles) == 1
    assert cfg.db_profiles[0].label == "blog.example.com"


def test_remove_unlabelled_default_among_many():
    # An unlabelled "default" DB alongside labelled ones is an unambiguous
    # target (at most one unlabelled profile per instance), so omitting app
    # removes it rather than erroring "name one".
    cfg = AppConfig(db_profiles=[
        DBProfile(instance="web", label="",
                  password_secret="db/web", user="u0"),
        DBProfile(instance="web", label="shop.example.com",
                  password_secret="db/web/shop.example.com", user="u1"),
    ])
    t = _tools(cfg)
    out = asyncio.run(t.db_setup_remove("web"))
    assert "Removed db_profile for web" in out
    assert len(cfg.db_profiles) == 1
    assert cfg.db_profiles[0].label == "shop.example.com"
