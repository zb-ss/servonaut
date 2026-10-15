"""``servonaut db setup``: list what the scan found, store it in one step.

Drives the CLI front end over the real ``ServonautTools`` scan → stage →
save engine, with the SSH round-trip and the secret store faked. The
staging token and the password (even its masked preview) must never reach
the terminal or the JSON output.
"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import signal
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from servonaut.cli import db as cli_db
from servonaut.config.schema import AppConfig
from servonaut.mcp.guards import CommandGuard
from servonaut.mcp.tools import ServonautTools

SHOP_PASSWORD = "pw-shop-fabricated-71c"
BLOG_PASSWORD = "pw-blog-fabricated-93d"
SHOP = (
    "===FILE:/var/www/shop/.env===\n"
    "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n"
    f"DB_USERNAME=shop\nDB_PASSWORD={SHOP_PASSWORD}\nDB_DATABASE=shop\n"
)
BLOG = (
    "===FILE:/srv/blog/.env===\n"
    "DB_CONNECTION=pgsql\nDB_HOST=db\nDB_PORT=5432\n"
    f"DB_USERNAME=blog\nDB_PASSWORD={BLOG_PASSWORD}\nDB_DATABASE=blog\n"
)
SECRETS = (SHOP_PASSWORD, BLOG_PASSWORD, SHOP_PASSWORD[-3:], BLOG_PASSWORD[-3:])
# Connection shapes as the list prints them, built from parts so no test line
# holds a literal login@host string.
SHOP_AT = "@".join(("shop", "127.0.0.1:3306/shop"))
BLOG_AT = "@".join(("blog", "db:5432/blog"))


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="servonaut")
    cli_db.add_db_parser(parser.add_subparsers(dest="subcommand"))
    return parser.parse_args(["db", "setup", *argv])


class _Box:
    """A fleet of one server whose scan answers with *dump*."""

    def __init__(self, dump: str) -> None:
        self.cfg = AppConfig()
        cm = MagicMock()
        cm.get.return_value = self.cfg
        cm.update.side_effect = lambda **kw: [setattr(self.cfg, k, v) for k, v in kw.items()]
        self.provider = SimpleNamespace(provider_name="local", path="/tmp/secrets.json",
                                        set_secret=AsyncMock())
        aws = MagicMock()
        aws.fetch_instances_cached = AsyncMock(return_value=[{"id": "i-web1", "name": "web-1"}])
        custom = MagicMock()
        custom.list_as_instances.return_value = []
        self.tools = ServonautTools(
            config_manager=cm, aws_service=aws, custom_server_service=custom,
            cache_service=MagicMock(), ssh_service=MagicMock(),
            connection_service=MagicMock(), scp_service=MagicMock(),
            guard=CommandGuard(self.cfg.mcp), audit=MagicMock(),
            secret_provider=self.provider,
        )
        self.scans = 0

        async def _exec_ssh(_instance, _command, **_kwargs):
            self.scans += 1
            return dump, ""

        self.tools._exec_ssh = _exec_ssh  # type: ignore[method-assign]

    def stored(self) -> dict[str, str]:
        return {c.args[0]: c.args[1] for c in self.provider.set_secret.call_args_list}

    def run(self, *argv: str, answers: list[str] = (), tty: bool = True) -> int:
        with patch.object(cli_db, "_build_tools", return_value=(self.tools, self.provider)), \
             patch.object(cli_db, "_is_interactive", return_value=tty), \
             patch("builtins.input", side_effect=list(answers)):
            return asyncio.run(cli_db._run_setup(_parse(*argv)))


def _assert_nothing_secret(text: str) -> None:
    assert "dbstg_" not in text
    assert "pw=" not in text and "****" not in text
    for secret in SECRETS:
        assert secret not in text


def test_one_candidate_and_enter_stores_it(capsys):
    box = _Box(SHOP)

    assert box.run("web-1", answers=["", ""]) == 0

    out = capsys.readouterr()
    assert "Scanning web-1 for database settings (read-only)..." in out.out
    assert "Found 1:" in out.out
    assert f"1  MySQL  {SHOP_AT}  from /var/www/shop/.env" in out.out
    assert "Saved shop to the local secret store (/tmp/secrets.json)." in out.out
    assert "Agents and the TUI can now use it (db_processlist, db_top_queries)." in out.out
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD}
    assert [(p.instance, p.label) for p in box.cfg.db_profiles] == [("i-web1", "shop")]
    _assert_nothing_secret(out.out + out.err)


def test_one_candidate_prompts_store_it_then_label():
    box = _Box(SHOP)
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=["", "shop-prod"]) as prompt:
        assert asyncio.run(cli_db._run_setup(_parse("web-1"))) == 0
    assert [c.args[0] for c in prompt.call_args_list] == [
        "Store it? [Y/n]: ", "Label for #1 (Enter = shop): ",
    ]
    assert box.stored() == {"db/i-web1/shop-prod": SHOP_PASSWORD}


def test_answering_no_stores_nothing(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", answers=["n"]) == 0
    assert capsys.readouterr().out.rstrip().endswith("Nothing stored.")
    assert box.stored() == {} and box.cfg.db_profiles == []


def test_several_and_a_number_stores_only_that_one(capsys):
    box = _Box(SHOP + BLOG)

    assert box.run("web-1", answers=["2", ""]) == 0

    out = capsys.readouterr()
    assert "Found 2:" in out.out
    assert f"1  MySQL       {SHOP_AT}  from /var/www/shop/.env" in out.out
    assert f"2  PostgreSQL  {BLOG_AT}         from /srv/blog/.env" in out.out
    assert box.stored() == {"db/i-web1/blog": BLOG_PASSWORD}
    assert "Saved blog to" in out.out
    _assert_nothing_secret(out.out + out.err)


def test_several_and_enter_or_all_stores_every_one(capsys):
    for answer in ("", "all"):
        box = _Box(SHOP + BLOG)
        assert box.run("web-1", answers=[answer, "", ""]) == 0
        assert box.stored() == {
            "db/i-web1/shop": SHOP_PASSWORD, "db/i-web1/blog": BLOG_PASSWORD,
        }
        out = capsys.readouterr().out
        assert "Saved shop and blog to the local secret store" in out
        assert "Agents and the TUI can now use them" in out


def test_a_bad_answer_asks_again():
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", answers=["7", "1", ""]) == 0
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD}


def test_the_same_label_twice_is_asked_again():
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", answers=["all", "site", "site", "site-2"]) == 0
    assert box.stored() == {
        "db/i-web1/site": SHOP_PASSWORD, "db/i-web1/site-2": BLOG_PASSWORD,
    }


def test_yes_stores_everything_without_asking(capsys):
    box = _Box(SHOP + BLOG)
    with patch("builtins.input", side_effect=AssertionError("asked")):
        assert box.run("web-1", "--yes", tty=False) == 0
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD, "db/i-web1/blog": BLOG_PASSWORD}
    _assert_nothing_secret(capsys.readouterr().out)


def test_pick_stores_the_listed_numbers_without_asking():
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--pick", "1,2", tty=False) == 0
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD, "db/i-web1/blog": BLOG_PASSWORD}

    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--pick", "2", tty=True) == 0  # no prompt even on a terminal
    assert box.stored() == {"db/i-web1/blog": BLOG_PASSWORD}


def test_pick_outside_the_list_stores_nothing(capsys):
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--pick", "3", tty=False) == 2
    assert "--pick 3 does not match the list: found 2" in capsys.readouterr().err
    assert box.stored() == {}


def test_pick_that_is_not_a_number_is_refused_before_scanning(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", "--pick", "shop", tty=False) == 2
    assert "--pick takes numbers from the list" in capsys.readouterr().err
    assert box.scans == 0


def test_label_names_the_one_database_stored(capsys):
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--pick", "1", "--label", "shop.example.com", tty=False) == 0
    assert box.stored() == {"db/i-web1/shop.example.com": SHOP_PASSWORD}
    assert "Saved shop.example.com to" in capsys.readouterr().out

    # On a terminal --label replaces the label question: one answer suffices.
    box = _Box(SHOP)
    assert box.run("web-1", "--label", "main", answers=[""]) == 0
    assert box.stored() == {"db/i-web1/main": SHOP_PASSWORD}


def test_label_with_several_chosen_stores_nothing(capsys):
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--yes", "--label", "x", tty=False) == 2
    assert "--label names one database, but 2 were chosen" in capsys.readouterr().err
    assert box.stored() == {}


def test_json_lists_candidates_without_token_or_password_and_stores_nothing(capsys):
    box = _Box(SHOP + BLOG)

    assert box.run("web-1", "--json", tty=False) == 0

    text = capsys.readouterr().out
    report = json.loads(text)
    assert report["instance"] == "web-1" and report["error"] is None
    assert report["saved"] == [] and report["failed"] == []
    assert [c["number"] for c in report["candidates"]] == [1, 2]
    for candidate in report["candidates"]:
        assert set(candidate) == {
            "number", "engine", "user", "host", "port", "database", "source", "label",
        }
    assert report["candidates"][1]["engine"] == "postgres"
    _assert_nothing_secret(text)
    assert box.stored() == {}


def test_json_with_pick_reports_what_was_saved(capsys):
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", "--json", "--pick", "2", tty=False) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["saved"] == [{"number": 2, "label": "blog"}]
    assert box.stored() == {"db/i-web1/blog": BLOG_PASSWORD}


def test_nothing_found_says_where_it_looked(capsys):
    box = _Box("")

    assert box.run("web-1", tty=False) == 0

    out = capsys.readouterr().out
    assert "No database settings found on web-1." in out
    assert ("Looked in the SSH user's home folder, /var/www, /srv, /home, /opt "
            "and /usr/share/nginx.") in out
    assert "servonaut db setup web-1 --search-path /path/to/app" in out


def test_nothing_found_under_a_search_path_names_it(capsys):
    box = _Box("")
    assert box.run("web-1", "--search-path", "/data/apps", tty=False) == 0
    assert "Looked in /data/apps." in capsys.readouterr().out


def test_no_secret_store_says_so_before_any_scan(capsys):
    box = _Box(SHOP)
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, None)), \
         patch("servonaut.services.auth_service.AuthService") as auth:
        auth.return_value.is_authenticated = False
        assert asyncio.run(cli_db._run_setup(_parse("web-1"))) == 1
    err = capsys.readouterr()
    assert "Nothing was scanned: storing database passwords needs a secret store" in err.err
    assert "Run `servonaut login`, then run this command again." in err.err
    assert "Scanning" not in err.out
    assert box.scans == 0


def test_signed_in_without_a_secret_store_points_at_secrets_status(capsys):
    with patch("servonaut.services.auth_service.AuthService") as auth:
        auth.return_value.is_authenticated = True
        message = cli_db._no_secret_store_message()
    assert "your plan does not include one" in message
    assert "`servonaut secrets status`" in message


def test_not_a_terminal_lists_candidates_and_stores_nothing(capsys):
    box = _Box(SHOP + BLOG)
    # A typed-ahead answer on a pipe is not consent: stdin is not a terminal.
    with patch("builtins.input", side_effect=AssertionError("asked")), \
         patch.object(cli_db.sys, "stdin", io.StringIO("1\n")), \
         patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)):
        code = asyncio.run(cli_db._run_setup(_parse("web-1")))
    assert code == 5
    out = capsys.readouterr()
    assert "Found 2:" in out.out
    assert "Nothing stored. Run with --yes or --pick N to store without asking." in out.err
    assert box.stored() == {} and box.cfg.db_profiles == []


def test_ctrl_c_is_cancelled_with_130(capsys):
    box = _Box(SHOP)
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=KeyboardInterrupt):
        assert cli_db.handle_db_command(_parse("web-1")) == 130
    assert capsys.readouterr().out.rstrip().endswith("Cancelled.")
    assert box.stored() == {}


def test_a_scan_error_is_reported(capsys):
    box = _Box(SHOP)

    async def _fails(*_args, **_kwargs):
        raise RuntimeError("Connection refused")

    box.tools._exec_ssh = _fails  # type: ignore[method-assign]
    assert box.run("web-1", "--source", "ssh", tty=False) == 1
    assert "Could not scan web-1 over SSH: Connection refused" in capsys.readouterr().err


def test_an_unusable_search_path_is_a_usage_error(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", "--search-path", "/var/www;id", tty=False) == 2
    assert "--search-path may only contain folder paths" in capsys.readouterr().err
    assert box.scans == 0


def test_two_candidates_with_one_label_are_not_stored_over_each_other(capsys):
    # Both config files sit in the same app folder, so both derive "shop".
    twin = BLOG.replace("/srv/blog/.env", "/var/www/shop/.env.production")
    box = _Box(SHOP + twin)
    assert box.run("web-1", "--yes", tty=False) == 1
    err = capsys.readouterr().err
    assert "Skipped #2: its label ('shop') is stored under the same name as #1" in err
    assert "--pick 2 --label NAME" in err
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD}


def test_labels_that_name_the_same_secret_are_asked_again(capsys):
    # "My Shop" and "my-shop" are different labels but one secret name:
    # storing both would point the first profile at the second password.
    box = _Box(SHOP + BLOG)
    assert box.run("web-1", answers=["all", "My Shop", "my-shop", "blog"]) == 0
    assert "#1 is already stored under that name" in capsys.readouterr().out
    assert box.stored() == {
        "db/i-web1/my-shop": SHOP_PASSWORD, "db/i-web1/blog": BLOG_PASSWORD,
    }
    assert sorted(p.password_secret for p in box.cfg.db_profiles) == [
        "db/i-web1/blog", "db/i-web1/my-shop",
    ]


def _ctrl_c_then(answer: str):
    """A prompt that gets one Ctrl+C, then *answer* (the next Enter) each time.

    Only the first call signals: asyncio's handler raises on a second
    Ctrl+C, which would hide a prompt that ignored the first one.
    """
    presses = []

    def prompt(*_args):
        if not presses:
            presses.append(1)
            os.kill(os.getpid(), signal.SIGINT)
            # Python's default handler raises while this waits; asyncio's
            # handler lets the wait end and the answer through.
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                time.sleep(0.01)
        return answer

    return prompt


def test_ctrl_c_at_a_prompt_cancels_and_stores_nothing(capsys):
    # asyncio.run's own SIGINT handler only cancels its task: input() would
    # keep waiting and the next Enter ("all" by default) would store
    # everything. The answer returned here is what that Enter would send.
    box = _Box(SHOP + BLOG)
    previous = signal.getsignal(signal.SIGINT)
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=_ctrl_c_then("")):
        try:
            code = cli_db.handle_db_command(_parse("web-1"))
        except KeyboardInterrupt:
            pytest.fail("Ctrl+C escaped the command instead of cancelling it")
    assert code == 130
    out = capsys.readouterr().out
    assert out.rstrip().endswith("Cancelled.") and "Saved" not in out
    assert box.stored() == {} and box.cfg.db_profiles == []
    assert signal.getsignal(signal.SIGINT) is previous


def test_ctrl_c_at_the_password_prompt_cancels(capsys):
    box = _Box("")
    answers = ["mysql", "", "", "report", "reports", ""]
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=answers), \
         patch.object(cli_db.getpass, "getpass", side_effect=_ctrl_c_then("typed-pw-fabricated")):
        assert cli_db.handle_db_command(_parse("web-1", "--manual")) == 130
    assert capsys.readouterr().out.rstrip().endswith("Cancelled.")
    assert box.stored() == {}


def test_an_unreachable_server_is_not_reported_as_nothing_found(capsys):
    # With the default source an SSH failure used to read as an empty scan
    # ("Looked in ..."), hiding e.g. a changed host key.
    box = _Box(SHOP)

    async def _fails(*_args, **_kwargs):
        raise RuntimeError("Host key verification failed.")

    box.tools._exec_ssh = _fails  # type: ignore[method-assign]
    assert box.run("web-1", tty=False) == 1
    out = capsys.readouterr()
    assert "Could not scan web-1 over SSH: Host key verification failed." in out.err
    assert "Looked in" not in out.out and "No database settings found" not in out.out


def test_a_local_file_search_path_still_falls_back_to_reading_it(tmp_path, capsys):
    settings = tmp_path / "app.env"
    settings.write_text(SHOP.split("\n", 1)[1], encoding="utf-8")
    box = _Box("")

    async def _fails(*_args, **_kwargs):
        raise RuntimeError("Connection refused")

    box.tools._exec_ssh = _fails  # type: ignore[method-assign]
    assert box.run("web-1", "--search-path", str(settings), "--json", tty=False) == 0
    (candidate,) = json.loads(capsys.readouterr().out)["candidates"]
    assert candidate["user"] == "shop"


def test_more_results_than_the_agent_staging_cap_are_all_stored(capsys):
    count = 55
    dump = "".join(
        f"===FILE:/var/www/site{n}.example.com/.env===\n"
        f"DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_USERNAME=u{n}\n"
        f"DB_PASSWORD=pw-{n}-fabricated\nDB_DATABASE=d{n}\n"
        for n in range(count)
    )
    box = _Box(dump)
    assert box.run("web-1", "--yes", tty=False) == 0
    assert len(box.stored()) == count
    assert box.stored()["db/i-web1/site0.example.com"] == "pw-0-fabricated"
    assert "Could not store" not in capsys.readouterr().err


def test_a_dropped_result_is_not_called_expired():
    message = cli_db._save_error(
        "Error: staging token 'x' was dropped because too many candidates were pending",
    )
    assert "expired" not in message and "--pick" in message


def test_one_candidate_asks_again_on_an_unclear_answer(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", answers=["nope", "none"]) == 0
    assert "Type y to store it or n to leave it." in capsys.readouterr().out
    assert box.stored() == {}

    box = _Box(SHOP)
    assert box.run("web-1", answers=["q", "y", ""]) == 0
    assert box.stored() == {"db/i-web1/shop": SHOP_PASSWORD}


def test_label_with_several_found_asks_for_one_number(capsys):
    box = _Box(SHOP + BLOG)
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=["", "all", "1,2", "2"]) as prompt:
        assert asyncio.run(cli_db._run_setup(_parse("web-1", "--label", "main"))) == 0
    assert prompt.call_args_list[0].args[0] == "Store which one as 'main'? [1, 2, none]: "
    assert len(prompt.call_args_list) == 4  # Enter, all and a list are asked again
    assert "--label names one database: type one number" in capsys.readouterr().out
    assert box.stored() == {"db/i-web1/main": BLOG_PASSWORD}


def test_source_local_without_a_file_is_a_usage_error(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", "--source", "local", tty=False) == 2
    assert "--source local reads the file given with --search-path" in capsys.readouterr().err
    assert box.scans == 0


def test_source_local_with_nothing_found_names_the_file(tmp_path, capsys):
    missing = tmp_path / "missing.env"
    box = _Box(SHOP)
    assert box.run("web-1", "--source", "local", "--search-path", str(missing), tty=False) == 0
    out = capsys.readouterr().out
    assert f"No database settings found in {missing}." in out
    assert "--search-path /path/to/app" not in out
    assert box.scans == 0


def test_unicode_digits_are_not_numbers(capsys):
    box = _Box(SHOP)
    assert box.run("web-1", "--pick", "²", tty=False) == 2
    assert "--pick takes numbers from the list" in capsys.readouterr().err
    with patch("builtins.input", side_effect=["²", "٣", "5432"]):
        assert cli_db._ask_port(3306) == 5432


def test_manual_refuses_an_unknown_server_before_asking(capsys):
    box = _Box("")
    with patch("builtins.input", side_effect=AssertionError("asked")), \
         patch.object(cli_db.getpass, "getpass", side_effect=AssertionError("asked")):
        assert box.run("web-9", "--manual") == 1
    assert "Instance not found: web-9" in capsys.readouterr().err
    assert box.stored() == {}


def test_control_characters_from_the_box_are_not_printed(capsys):
    hostile = SHOP.replace("DB_USERNAME=shop", "DB_USERNAME=sh\x1b[2Jop")
    box = _Box(hostile)
    assert box.run("web-1", "--json", tty=False) == 0
    capsys.readouterr()
    assert box.run("web-1", answers=["n"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "@".join(("sh?[2Jop", "127.0.0.1")) in out


def test_manual_entry_stores_the_typed_password(capsys):
    box = _Box("")
    answers = ["postgres", "db.example.com", "", "report", "reports", "analytics"]
    with patch.object(cli_db, "_build_tools", return_value=(box.tools, box.provider)), \
         patch.object(cli_db, "_is_interactive", return_value=True), \
         patch("builtins.input", side_effect=answers), \
         patch.object(cli_db.getpass, "getpass", return_value="typed-pw-fabricated"):
        assert asyncio.run(cli_db._run_setup(_parse("web-1", "--manual"))) == 0
    out = capsys.readouterr()
    assert box.scans == 0
    assert box.stored() == {"db/i-web1/analytics": "typed-pw-fabricated"}
    (profile,) = box.cfg.db_profiles
    assert (profile.instance, profile.engine, profile.host, profile.port, profile.user,
            profile.database) == ("i-web1", "postgres", "db.example.com", 5432, "report", "reports")
    assert "Saved analytics to the local secret store" in out.out
    assert "typed-pw-fabricated" not in out.out + out.err


def test_manual_needs_a_terminal_and_no_scan_flags(capsys):
    box = _Box("")
    assert box.run("web-1", "--manual", tty=False) == 5
    assert "--manual asks for the password, so run it in a terminal." in capsys.readouterr().err
    assert box.run("web-1", "--manual", "--yes", tty=True) == 2
    assert "--manual does not scan" in capsys.readouterr().err
    assert box.stored() == {}


@pytest.mark.parametrize("text,count,expected", [
    ("1", 2, [1]), ("2,1", 2, [1, 2]), ("1 2", 2, [1, 2]), ("1-3", 3, [1, 2, 3]),
    ("all", 3, [1, 2, 3]), ("0", 2, None), ("3", 2, None), ("x", 2, None),
    ("", 2, None), ("2-1", 2, None), ("4", None, [4]),
    ("²", 2, None), ("٣", 3, None), ("1-²", 2, None),
])
def test_parse_numbers(text: str, count: Any, expected: Any):
    assert cli_db._parse_numbers(text, count) == expected
