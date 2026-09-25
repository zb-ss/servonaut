"""Journeys: browse a server's files, open one, and copy files both ways.

``web-1`` is a custom server on the loopback SSH target, reached with the
real OpenSSH client. The file browser (``b``) lists the configured roots
and expands directories on demand. The remote browser behind the log
viewer's "Manage Paths" opens a file it finds, and the transfer screen
(``t``) uploads and downloads with the real ``scp``; bytes are compared on
both sides.
"""

from __future__ import annotations

import pytest

from e2e.harness import remote_fleet

pytestmark = [pytest.mark.e2e_pr, pytest.mark.needs_sshd, pytest.mark.asyncio]

WEB_1 = remote_fleet.fleet.WEB_1
PAYLOAD = bytes(range(256)) * 16  # every byte value, 4 KiB


def _seed(seed, sshd, roots: tuple[str, ...] = ("/var/www/",), **config):
    """web-1 with extra browser roots for web servers."""
    from servonaut.config.schema import ScanRule

    remote = sshd.target.remote
    remote.write(f"/home/{WEB_1.username}/notes.txt", "deploy notes\n")
    remote.write(f"/home/{WEB_1.username}/releases/v1.txt", "release one\n")
    rules = [
        ScanRule(name="web roots", match_conditions={"name_contains": "web-"},
                 scan_paths=list(roots))
    ]
    remote_fleet.seed_web_1(sshd, seed, seed.home, scan_rules=rules, **config)
    seed.cache([], fresh=True)


async def _paste(t, selector: str, text: str) -> None:
    """Replace an input's text the way a user pastes it (one paste, not per-key typing)."""
    from textual import events
    from textual.widgets import Input

    field = t.on_screen(selector, Input)
    await t.click(field)
    await t.wait_until(lambda: field.has_focus, desc=f"focus on {selector}")
    field.clear()  # as the suite's fill() does
    field.post_message(events.Paste(text))
    await t.wait_until(lambda: field.value == text, desc=f"{selector} == {text!r}")


async def _open(t, key: str, screen: str):
    await t.wait_until(lambda: WEB_1.name in [r[1] for r in t.table_rows("InstanceTable")])
    await t.select_instance(WEB_1.name)
    await t.press(key)
    return await t.wait_for_screen(screen)


# ---------------------------------------------------------------------------
# Tree helpers: move the cursor with the keyboard, as a user does.
# ---------------------------------------------------------------------------


def _labels(node) -> list[str]:
    return [child.label.plain for child in node.children]


def _child(node, prefix: str):
    matches = [child for child in node.children if child.label.plain.startswith(prefix)]
    return matches[0] if matches else None


async def _cursor_to(t, tree, node) -> None:
    for _ in range(100):
        if tree.cursor_node is node:
            return
        await t.press("down" if tree.cursor_line < node.line else "up")
    raise AssertionError(f"could not move the cursor to {node.label.plain!r}")


async def _expand(t, tree, parent, prefix: str):
    """Expand the child of *parent* labelled *prefix*; wait for its listing."""
    node = await t.wait_until(lambda: _child(parent, prefix), desc=f"node {prefix!r}")
    await _cursor_to(t, tree, node)
    await t.press("space")
    await t.wait_until(
        lambda: node.children and not _labels(node)[0].startswith("⏳"),
        desc=f"listing of {prefix!r}",
    )
    return node


# ---------------------------------------------------------------------------
# Journeys
# ---------------------------------------------------------------------------


async def test_browse_the_remote_file_tree(tui, seed, journey, sshd):
    _seed(seed, sshd)

    async with tui() as t:
        await _open(t, "b", "FileBrowserScreen")
        tree = t.on_screen("#remote_tree")
        await t.click(tree)
        assert sorted(_labels(tree.root)) == ["📁 /var/www/", "📁 ~/"]

        home = await _expand(t, tree, tree.root, "📁 ~/")
        assert "📄 notes.txt (13B)" in _labels(home)
        releases = await _expand(t, tree, home, "📁 releases")
        assert _labels(releases) == ["📄 v1.txt (12B)"]

        www = await _expand(t, tree, tree.root, "📁 /var/www/")
        html = await _expand(t, tree, www, "📁 html")
        assert _labels(html) == ["📄 index.html (22B)"]

    listed = [c for c in sshd.target.commands(user=WEB_1.username) if c.startswith("ls -la")]
    assert listed == [
        'ls -la "$HOME/"',
        'ls -la "$HOME/releases"',
        'ls -la "/var/www/"',
        'ls -la "/var/www/html"',
    ]


async def test_a_missing_root_folder_is_reported(tui, seed, journey, sshd):
    _seed(seed, sshd, roots=("/srv/gone/",), default_scan_paths=[])

    async with tui() as t:
        await _open(t, "b", "FileBrowserScreen")
        tree = t.on_screen("#remote_tree")
        await t.click(tree)
        gone = await _expand(t, tree, tree.root, "📁 /srv/gone/")
        assert _labels(gone) == ["📭 Path not found on server"]


async def _browse_for_a_log(t):
    """Log viewer → Manage Paths → Browse, then open /var/log/app/worker.log."""
    await _open(t, "l", "LogViewerScreen")
    await t.press("m")
    await t.wait_for_screen("ManagePathsModal")
    await t.click("#manage_browse")
    await t.wait_for_screen("BrowseRemoteScreen")
    tree = await t.wait_until(lambda: t.find("#browse_tree"), desc="remote tree")
    tree = tree[0]
    await t.click(tree)
    var_log = await _expand(t, tree, tree.root, "📁 /var/log")
    app = await _expand(t, tree, var_log, "📁 app")
    worker = await t.wait_until(lambda: _child(app, "📄 worker.log"), desc="worker.log")
    await _cursor_to(t, tree, worker)
    return tree


async def _wait_for_worker_log(t, timeout: float = 20.0):
    await t.wait_for_screen("LogViewerScreen", timeout=timeout)
    output = t.on_screen("#log_output")
    await t.wait_until(
        lambda: "worker: job 2 done" in t.log_text(output), timeout=timeout, desc="file content"
    )
    assert "Viewing: /var/log/app/worker.log" in t.rendered_text()


async def test_open_a_file_found_by_browsing(tui, seed, journey, sshd):
    _seed(seed, sshd)

    async with tui() as t:
        await _browse_for_a_log(t)
        await t.press("f")  # "Add as File"
        await _wait_for_worker_log(t)

    saved = seed.read_config()["log_viewer_custom_paths"]
    assert saved == {f"custom-{WEB_1.name}": ["/var/log/app/worker.log"]}
    assert "tail -n 100 -f /var/log/app/worker.log" in sshd.target.commands()


@pytest.mark.xfail(
    strict=True,
    reason="Enter on a file in the remote log browser does not open it, although the "
    "screen says Enter adds the file",
)
async def test_enter_opens_the_highlighted_file(tui, seed, journey, sshd):
    _seed(seed, sshd)

    async with tui() as t:
        await _browse_for_a_log(t)
        await t.press("enter")
        await _wait_for_worker_log(t, timeout=3)


async def test_upload_and_download_with_scp(tui, seed, journey, sshd):
    _seed(seed, sshd)
    (seed.home / "upload.bin").write_bytes(PAYLOAD)
    remote = sshd.target.remote

    async with tui() as t:
        await _open(t, "t", "SCPTransferScreen")
        await _paste(t, "#local_path_input", "~/upload.bin")
        await _paste(t, "#remote_path_input", "/tmp/upload.bin")
        await t.click("#transfer_button")
        await t.wait_for_toast("^Transfer completed$")
        assert remote.read_bytes("/tmp/upload.bin") == PAYLOAD

        await t.click("#radio_download")
        await _paste(t, "#remote_path_input", "/var/www/html/index.html")
        await _paste(t, "#local_path_input", "~/index.html")
        await t.click("#transfer_button")
        await t.wait_until(
            lambda: [m for _, m in t.toasts() if m == "Transfer completed"][1:],
            desc="second transfer",
        )
        assert (seed.home / "index.html").read_bytes() == remote.read_bytes(
            "/var/www/html/index.html"
        )

        await _paste(t, "#remote_path_input", "/var/www/html/missing.html")
        await t.click("#transfer_button")
        message = await t.wait_for_toast("^Transfer failed", severity="error")
        assert "No such file" in message

    opened = [(e["path"], e["mode"]) for e in sshd.target.sessions("sftp-open")]
    assert opened[:2] == [("/tmp/upload.bin", "write"), ("/var/www/html/index.html", "read")]
