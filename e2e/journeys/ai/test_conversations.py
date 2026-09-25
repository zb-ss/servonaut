"""Journey: browse previous hosted chats, manage them, export one to Markdown.

History in the chat panel opens Previous Chats on the Cloud tab, listing
the account's active conversations. Enter opens one in the chat panel,
where the next message continues it; ``a`` archives and ``d`` deletes after
a confirmation. ``e`` exports the selected one: the file may only land in
the current directory or ``~/Downloads``. A path that climbs out of them,
or points anywhere else, is refused before anything is downloaded, and an
existing file is never overwritten.
"""

from __future__ import annotations

import pytest
from rich.text import Text

from e2e.harness.ai_chat import (
    bubbles,
    open_chat,
    seed_hosted,
    send,
    wait_for_literal_toast,
    wait_for_reply,
    wait_for_shown_toast,
)
from e2e.harness.fake_cloud.chat_script import ChatTurn, conversation_row, token, usage

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

EXPORT = "# Disk usage on web-1\n\n**You:** Why is /var full?\n"
NAME = "[red]disk-usage.md"
REFUSED = "Export rejected: Export path must be inside CWD or ~/Downloads"


@pytest.fixture
def workdir(journey, monkeypatch):
    """The directory the user started Servonaut from (inside the sandbox)."""
    path = journey.directory / "workdir"
    path.mkdir()
    monkeypatch.chdir(path)
    return path


def _export_requests(fake_cloud) -> list[dict]:
    return [r for r in fake_cloud.requests() if r["path"].endswith("/export.md")]


async def _open_history(t) -> None:
    chat = await open_chat(t)
    await t.click(chat.query_one("#btn-chat-history"))
    await t.wait_for_screen("AIConversationsScreen")
    await t.wait_until(lambda: t.table_rows("#convs_table"), desc="conversations listed")


def _titles(t) -> list[str]:
    """The titles as the list shows them (cells are rendered as markup)."""
    table = t.on_screen("#convs_table")
    shown = []
    for key in table.rows:
        cell = table.get_row(key)[0]
        text = Text.from_markup(cell).plain if isinstance(cell, str) else cell.plain
        shown.append(text.split(" · ", 1)[1])
    return shown


async def _select(t, title: str) -> None:
    """Move the list's cursor to the conversation called *title*."""
    table = t.on_screen("#convs_table")
    if not table.has_focus:
        await t.click(table)
    target = _titles(t).index(title)
    for _ in range(table.row_count):
        if table.cursor_row == target:
            return
        await t.press("down" if table.cursor_row < target else "up")
    assert table.cursor_row == target, f"the cursor never reached {title!r}"


async def _confirm(t, key: str, toast: str) -> None:
    await t.press(key)
    await t.wait_for_screen("_ConfirmModal")
    await t.press("y")
    await wait_for_shown_toast(t, toast)


async def _refused(t, path: str) -> None:
    """Export to *path*; it is refused before anything is downloaded."""
    before = len(t.toast_records())
    await _export(t, path)
    await t.wait_until(lambda: len(t.toast_records()) > before, desc=f"answer for {path}")
    toast = t.toast_records()[-1]
    assert (toast.severity, toast.message, toast.markup) == ("error", REFUSED, False), path


async def _export(t, path: str) -> None:
    await t.press("e")
    await t.wait_for_screen("_ExportPathModal")
    await t.fill("#export_path_input", path)
    await t.press("enter")
    await t.wait_for_screen("AIConversationsScreen")


async def test_history_lists_and_exports_inside_the_allowed_folders(
    tui, seed, fake_cloud, workdir
):
    fake_cloud.ai.configure(
        conversations=[
            conversation_row("conv-e2e-1", "Disk usage on web-1"),
            conversation_row("conv-e2e-2", "Old question", status="archived"),
        ],
        exports={"conv-e2e-1": EXPORT},
    )
    seed_hosted(seed, fake_cloud)
    downloads = seed.home / "Downloads"
    downloads.mkdir()
    async with tui() as t:
        await _open_history(t)
        assert _titles(t) == ["Disk usage on web-1"]

        # The file name has brackets: the toast shows them as typed.
        await _export(t, NAME)
        await wait_for_literal_toast(t, f"Exported to {workdir / NAME}")
        assert (workdir / NAME).read_text(encoding="utf-8") == EXPORT

        await _export(t, f"~/Downloads/{NAME}")
        await wait_for_literal_toast(t, f"Exported to {downloads / NAME}")
        assert (downloads / NAME).read_text(encoding="utf-8") == EXPORT

        # Exporting over an existing file is refused, and the file kept.
        (workdir / NAME).write_text("my notes\n", encoding="utf-8")
        await _export(t, NAME)
        # (The message is shortened on screen, so match its start.)
        toast = await t.wait_for_toast_record(
            "^Export rejected: Refusing to overwrite existing file: ", severity="warning"
        )
        assert toast.markup is False
        assert (workdir / NAME).read_text(encoding="utf-8") == "my notes\n"
        assert len(_export_requests(fake_cloud)) == 2


async def test_export_outside_the_allowed_folders_is_refused(
    tui, seed, fake_cloud, journey, workdir
):
    fake_cloud.ai.configure(
        conversations=[conversation_row("conv-e2e-1", "Disk usage on web-1")],
        exports={"conv-e2e-1": EXPORT},
    )
    seed_hosted(seed, fake_cloud)
    async with tui() as t:
        await _open_history(t)
        # Up out of the current directory, up out of Downloads, and an
        # absolute path elsewhere (the sandbox would also stop a write there).
        for path in ("../escaped.md", "~/Downloads/../escaped.md", "/var/tmp/escaped.md"):
            await _refused(t, path)

        assert _export_requests(fake_cloud) == []
        assert not (journey.directory / "escaped.md").exists()
        assert not (seed.home / "escaped.md").exists()


async def test_export_follows_links_to_where_they_lead(tui, seed, fake_cloud, journey, workdir):
    """The check applies to where a path really leads: a link in the current
    directory that points elsewhere is refused, while ~/Downloads may itself
    be a link, and the file lands where it points."""
    fake_cloud.ai.configure(
        conversations=[conversation_row("conv-e2e-1", "Disk usage on web-1")],
        exports={"conv-e2e-1": EXPORT},
    )
    seed_hosted(seed, fake_cloud)
    outside = journey.directory / "outside"
    outside.mkdir()
    (workdir / "out").symlink_to(outside, target_is_directory=True)
    (workdir / "linked.md").symlink_to(outside / "linked.md")
    downloads_target = journey.directory / "downloads-target"
    downloads_target.mkdir()
    (seed.home / "Downloads").symlink_to(downloads_target, target_is_directory=True)
    async with tui() as t:
        await _open_history(t)
        await _refused(t, "out/escaped.md")
        await _refused(t, "linked.md")
        assert list(outside.iterdir()) == []

        await _export(t, "~/Downloads/disk-usage.md")
        await wait_for_literal_toast(t, f"Exported to {downloads_target / 'disk-usage.md'}")
        assert (downloads_target / "disk-usage.md").read_text(encoding="utf-8") == EXPORT
        assert len(_export_requests(fake_cloud)) == 1


async def test_open_archive_and_delete_from_history(tui, seed, fake_cloud):
    fake_cloud.ai.configure(
        conversations=[
            conversation_row(
                "conv-e2e-1",
                "Disk usage on web-1 [/]",
                messages=[
                    {"role": "user", "content": "Why is /var full?"},
                    {"role": "assistant", "content": "Old logs; rotate them."},
                ],
            ),
            conversation_row("conv-e2e-2", "Certificate [b]renewal[/b]"),
            conversation_row("conv-e2e-3", "Old question [/]"),
        ]
    )
    seed_hosted(seed, fake_cloud)
    async with tui() as t:
        await _open_history(t)
        # Titles come from the service; brackets in them are shown as typed.
        await _select(t, "Certificate [b]renewal[/b]")
        await _confirm(t, "a", "Archived: Certificate [b]renewal[/b]")
        await _select(t, "Old question [/]")
        await _confirm(t, "d", "Deleted: Old question [/]")
        assert _titles(t) == ["Disk usage on web-1 [/]"]
        assert [c["id"] for c in fake_cloud.ai.conversations("archived")] == ["conv-e2e-2"]
        assert [c["id"] for c in fake_cloud.ai.conversations()] == ["conv-e2e-1", "conv-e2e-2"]

        # Enter opens the conversation in the chat panel ...
        await _select(t, "Disk usage on web-1 [/]")
        await t.press("enter")
        await wait_for_shown_toast(t, "Opening conversation: Disk usage on web-1 [/]")
        await t.wait_until(
            lambda: [text for _, text in bubbles(t)] == [
                "You\nWhy is /var full?", "◉ Servonaut\nOld logs; rotate them."
            ],
            desc="the conversation's messages",
        )
        # ... and the next message continues it on the service.
        fake_cloud.ai.script(ChatTurn.of(token("Rotated."), usage()))
        await send(t, "Done?")
        assert (await wait_for_reply(t))[-1] == "Rotated."
        [chat] = fake_cloud.ai.chats()
        assert chat["conversation_id"] == "conv-e2e-1"
        assert chat["body"]["messages"][0] == {"role": "user", "content": "Why is /var full?"}
