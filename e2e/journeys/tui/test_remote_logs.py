"""Journey: follow a server's logs live and switch logs with the picker.

``l`` on ``web-1`` probes the usual log paths over real SSH, starts a live
tail of the first readable one and, in the background, finds more log files
under ``/var/log``. A line written on the server appears in the viewer. The
picker (``l`` again) lists the probed and the discovered logs, filters them
as the user types, and switches the viewer to the chosen file.
"""

from __future__ import annotations

import pytest

from e2e.harness import remote_fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

WEB_1 = remote_fleet.fleet.WEB_1
FRESH = "app[812]: fresh line written during the journey"


def _picker_entries(t) -> list[str]:
    options = t.on_screen("#log_picker_list")
    return [
        str(options.get_option_at_index(i).prompt).strip()
        for i in range(options.option_count)
    ]


async def test_follow_a_log_and_switch_with_the_picker(tui, seed, journey, sshd):
    remote_fleet.seed_web_1(sshd, seed, seed.home)
    seed.cache([], fresh=True)
    remote = sshd.target.remote

    async with tui() as t:
        await t.wait_and_select_instance(WEB_1.name)
        await t.press("l")
        await t.wait_for_screen("LogViewerScreen")
        output = t.on_screen("#log_output")
        await t.wait_until(lambda: "CRON[901]" in t.log_text(output), desc="syslog content")
        assert "Viewing: /var/log/syslog" in t.rendered_text()

        remote.append("/var/log/syslog", f"Jan 01 10:05:00 {WEB_1.name} {FRESH}\n")
        await t.wait_until(lambda: FRESH in t.log_text(output), desc="the new line, live")
        await t.wait_for_toast("^Discovered 1 additional log files$")

        await t.press("l")
        await t.wait_for_screen("LogPickerModal")
        entries = _picker_entries(t)
        assert "/var/log/syslog" in " ".join(entries)
        assert "/var/log/nginx/access.log" in entries
        assert "/var/log/app/worker.log" in entries  # found by the background scan
        await t.type("worker")
        await t.wait_until(
            lambda: [e for e in _picker_entries(t) if e.startswith("/")]
            == ["/var/log/app/worker.log"],
            desc="picker filtered to worker.log",
        )
        await t.press("down", "enter")
        await t.wait_for_screen("LogViewerScreen")
        await t.wait_until(lambda: "worker: job 2 done" in t.log_text(output), desc="worker log")
        assert FRESH not in t.log_text(output)
        assert "Viewing: /var/log/app/worker.log" in t.rendered_text()

        # The first tail ended on the server when the viewer switched away.
        await t.wait_until(
            lambda: [
                e for e in sshd.target.sessions("exit")
                if e["command"] == "tail -n 100 -f /var/log/syslog"
            ],
            desc="syslog tail stopped on the server",
        )

    commands = sshd.target.commands(user=WEB_1.username)
    assert commands[0].startswith("test -r /var/log/syslog && echo /var/log/syslog;")
    assert "find /var/log -maxdepth 2 -type f -readable 2>/dev/null | sort -u" in commands
    assert "tail -n 100 -f /var/log/app/worker.log" in commands


async def test_a_server_without_readable_logs_says_so(tui, seed, journey, sshd):
    remote_fleet.seed_web_1(sshd, seed, seed.home, log_viewer_default_paths=["/var/log/none.log"])
    seed.cache([], fresh=True)

    async with tui() as t:
        await t.wait_and_select_instance(WEB_1.name)
        await t.press("l")
        await t.wait_for_screen("LogViewerScreen")
        await t.wait_for_toast("^No readable log files found$", severity="warning")
        output = t.on_screen("#log_output")
        assert "Press L to pick a log" in t.log_text(output)
