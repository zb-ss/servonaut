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
from e2e.harness.known_issues import known_issue

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
    await t.wait_and_select_instance(WEB_1.name)
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
        'ls -la "$HOME"/',
        'ls -la "$HOME"/releases',
        'ls -la /var/www/',
        'ls -la /var/www/html',
    ]


async def test_a_missing_root_folder_is_reported(tui, seed, journey, sshd):
    _seed(seed, sshd, roots=("/srv/gone/",), default_scan_paths=[])

    async with tui() as t:
        await _open(t, "b", "FileBrowserScreen")
        tree = t.on_screen("#remote_tree")
        await t.click(tree)
        gone = await _expand(t, tree, tree.root, "📁 /srv/gone/")
        # The ordinary Files browser retains the server's diagnostic; the
        # copy picker uses its shorter friendly message instead.
        assert len(_labels(gone)) == 1
        message = _labels(gone)[0]
        assert message.startswith("❌ ")
        assert "/srv/gone/" in message and "No such file or directory" in message


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
    return tree, worker


async def _wait_for_worker_log(t):
    await t.wait_for_screen("LogViewerScreen")
    output = t.on_screen("#log_output")
    await t.wait_until(lambda: "worker: job 2 done" in t.log_text(output), desc="file content")
    await t.wait_for_text("Viewing: /var/log/app/worker.log")


async def test_open_a_file_found_by_browsing(tui, seed, journey, sshd):
    _seed(seed, sshd)

    async with tui() as t:
        await _browse_for_a_log(t)
        await t.press("f")  # "Add as File"
        await _wait_for_worker_log(t)

    saved = seed.read_config()["log_viewer_custom_paths"]
    assert saved == {f"custom-{WEB_1.name}": ["/var/log/app/worker.log"]}
    assert "tail -n 100 -f /var/log/app/worker.log" in sshd.target.commands()


async def test_enter_opens_the_highlighted_file(tui, seed, journey, sshd):
    from textual.widgets import Tree

    _seed(seed, sshd)

    async with tui() as t:
        _tree, worker = await _browse_for_a_log(t)
        browser = t.screen
        # The browser has handled Enter once the tree's selection of the file
        # has reached it: no timeout decides between "ignored" and "slow".
        handled: list = []
        browser.message_signal.subscribe(
            browser,
            lambda m: handled.append(m)
            if isinstance(m, Tree.NodeSelected) and m.node is worker
            else None,
            immediate=True,
        )
        await t.press("enter")
        await t.wait_until(lambda: t.screen is not browser or handled, desc="Enter handled")
        await t.settle(5)
        known_issue(t.screen is browser, "Enter on a file leaves the remote browser open")
        await _wait_for_worker_log(t)


async def test_upload_and_download_with_scp(tui, seed, journey, sshd):
    _seed(seed, sshd)
    (seed.home / "upload.bin").write_bytes(PAYLOAD)
    remote = sshd.target.remote

    async with tui() as t:
        await _open(t, "t", "SCPTransferScreen")
        await _paste(t, "#local_path_input", "~/upload.bin")
        await _paste(t, "#remote_path_input", "/tmp/upload renamed.bin")
        await t.click("#transfer_button")
        await t.wait_for_toast("^Transfer completed$")
        assert remote.read_bytes("/tmp/upload renamed.bin") == PAYLOAD

        await t.click("#radio_download")
        await _paste(t, "#remote_path_input", "/var/www/html/index.html")
        await _paste(t, "#local_path_input", "~/renamed index.html")
        await t.click("#transfer_button")
        await t.wait_until(
            lambda: [m for _, m in t.toasts() if m == "Transfer completed"][1:],
            desc="second transfer",
        )
        assert (seed.home / "renamed index.html").read_bytes() == remote.read_bytes(
            "/var/www/html/index.html"
        )

        await _paste(t, "#remote_path_input", "/var/www/html/missing.html")
        await t.click("#transfer_button")
        message = await t.wait_for_toast("^Transfer failed", severity="error")
        assert "No such file" in message

    opened = [(e["path"], e["mode"]) for e in sshd.target.sessions("sftp-open")]
    assert opened[:2] == [("/tmp/upload renamed.bin", "write"), ("/var/www/html/index.html", "read")]


async def _local_picker(t, side: str, path, *, source: bool) -> None:
    from pathlib import Path
    from servonaut.widgets.local_path_tree import LocalPathTree

    path = Path(path)
    await t.click(f'#{side}_path_browse')
    await t.wait_for_screen('LocalPathPickerModal')
    parent = path.parent if source else path
    await _paste(t, '#path_picker_location', str(parent))
    await t.click('#path_picker_go')
    tree = t.on_screen('#path_picker_tree', LocalPathTree)
    await t.wait_until(
        lambda: Path(tree.path) == parent and not t.screen.is_loading(),
        desc='local folder listing settled',
    )
    if source:
        node = await t.wait_until(
            lambda: next((n for n in tree.root.children if n.data.path == path), None),
            desc='local source entry',
        )
        tree.focus()
        await _cursor_to(t, tree, node)
        await t.wait_until(lambda: t.screen._selected == str(path) and not t.on_screen('#path_picker_choose').disabled, desc='local source ready')
        if path.is_file():
            await t.press('enter')
        else:
            await t.click('#path_picker_choose')
    else:
        await t.wait_until(lambda: not t.on_screen('#path_picker_choose').disabled, desc='local destination ready')
        await t.click('#path_picker_choose')
    await t.wait_for_screen('SCPTransferScreen')
    await t.wait_until(lambda: t.on_screen(f'#{side}_path_input').has_focus, desc='origin focus restored')


async def _remote_picker(t, path: str, *, source: bool, folder: bool = False) -> None:
    import posixpath
    from servonaut.widgets.remote_tree import RemoteTree

    await t.click('#remote_path_browse')
    await t.wait_for_screen('RemotePathPickerModal')
    parent = posixpath.dirname(path.rstrip('/')) if source else path
    await _paste(t, '#path_picker_location', parent)
    await t.click('#path_picker_go')
    tree = t.on_screen('#path_picker_tree', RemoteTree)
    await t.wait_until(
        lambda: tree.root.children and tree.root.children[0].data['path'] == parent and not tree.is_listing,
        desc='remote folder listing settled',
    )
    if source:
        node = await t.wait_until(
            lambda: next((n for n in tree.root.children[0].children if n.data and n.data['path'] == path), None),
            desc='remote source entry',
        )
        tree.focus()
        await _cursor_to(t, tree, node)
        await t.wait_until(lambda: t.screen._selected == path and not t.on_screen('#path_picker_choose').disabled, desc='remote source ready')
        if not folder:
            await t.press('enter')
        else:
            await t.click('#path_picker_choose')
    else:
        await t.wait_until(lambda: not t.on_screen('#path_picker_choose').disabled, desc='remote destination ready')
        await t.click('#path_picker_choose')
    await t.wait_for_screen('SCPTransferScreen')
    await t.wait_until(lambda: t.on_screen('#remote_path_input').has_focus, desc='remote input focus restored')


async def _transfer_completed(t, count: int) -> None:
    await t.click('#transfer_button')
    await t.wait_until(
        lambda: len([message for _, message in t.toasts() if message == 'Transfer completed']) >= count,
        desc=f'completed copy {count}',
    )


async def test_browse_and_upload_file_and_folder_with_existing_folder_consent(tui, seed, journey, sshd):
    _seed(seed, sshd)
    file = seed.home / "payload it's [1].bin"
    file.write_bytes(PAYLOAD)
    folder = seed.home / 'release folder'
    (folder / 'nested').mkdir(parents=True)
    nested = folder / 'nested' / 'part[1].bin'
    nested.write_bytes(PAYLOAD[::-1])
    remote = sshd.target.remote
    remote.write('/tmp/browse-upload/keep.txt', 'keep')

    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await _local_picker(t, 'local', file, source=True)
        await _remote_picker(t, '/tmp/browse-upload/', source=False)
        assert not sshd.target.sessions('sftp-open')
        await _transfer_completed(t, 1)
        assert remote.read_bytes('/tmp/browse-upload/' + file.name) == PAYLOAD

        await _local_picker(t, 'local', folder, source=True)
        await _transfer_completed(t, 2)
        remote_nested = '/tmp/browse-upload/release folder/nested/part[1].bin'
        assert remote.read_bytes(remote_nested) == PAYLOAD[::-1]

        nested.write_bytes(b'changed after first copy')
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        opened_before = len(sshd.target.sessions('sftp-open'))
        await t.click('#scp_folder_cancel')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: not t.on_screen('#transfer_button').disabled, desc='cancel settled')
        assert len(sshd.target.sessions('sftp-open')) == opened_before
        assert remote.read_bytes(remote_nested) == PAYLOAD[::-1]
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        await t.click('#scp_folder_confirm')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: remote.read_bytes(remote_nested) == nested.read_bytes(), desc='confirmed folder bytes')


async def test_browse_and_download_file_and_folder(tui, seed, journey, sshd):
    _seed(seed, sshd)
    remote = sshd.target.remote
    remote.write("/srv/download examples/report it's [1].bin", PAYLOAD)
    remote.write('/srv/download examples/release folder/nested/part[1].bin', PAYLOAD[::-1])
    destination = seed.home / 'downloads'
    destination.mkdir()

    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await t.click('#radio_download')
        await _remote_picker(t, "/srv/download examples/report it's [1].bin", source=True)
        await _local_picker(t, 'local', destination, source=False)
        assert not sshd.target.sessions('sftp-open')
        await _transfer_completed(t, 1)
        assert (destination / "report it's [1].bin").read_bytes() == PAYLOAD
        await _remote_picker(t, '/srv/download examples/release folder', source=True, folder=True)
        await _transfer_completed(t, 2)
        assert (destination / 'release folder' / 'nested' / 'part[1].bin').read_bytes() == PAYLOAD[::-1]


async def test_remote_picker_failure_retry_and_cancel_preserves_inputs(tui, seed, journey, sshd):
    _seed(seed, sshd)
    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await _paste(t, '#local_path_input', '~/unchanged.bin')
        await _paste(t, '#remote_path_input', '/srv/unchanged/')
        await t.click('#remote_path_browse')
        await t.wait_for_screen('RemotePathPickerModal')
        await _paste(t, '#path_picker_location', '~')
        await t.click('#path_picker_go')
        await t.wait_until(lambda: t.on_screen('#path_picker_tree').current_path == '~' and not t.screen.is_loading(), desc='login home listing')
        await t.click('#path_picker_up')
        await t.wait_until(lambda: t.on_screen('#path_picker_tree').current_path == '/home' and not t.screen.is_loading(), desc='resolved parent of login home')
        await _paste(t, '#path_picker_location', '/srv/retry-folder')
        await t.wait_until(lambda: not t.on_screen('#path_picker_go').has_class('-active'), desc='Go ready after home navigation')
        await t.click('#path_picker_go')
        await t.wait_until(lambda: bool(t.screen._error) and not t.screen.is_loading(), desc='missing-path inline error')
        assert t.on_screen('#path_picker_choose').disabled
        sshd.target.remote.write('/srv/retry-folder/recovered.txt', 'recovered')
        sshd.target.remote.write('/srv/retry-folder/1.1.1.1.txt', 'redaction fixture')
        await t.click('#path_picker_retry')
        await t.wait_until(lambda: not t.screen._error and not t.screen.is_loading(), desc='retry listing succeeds')
        assert not t.on_screen('#path_picker_choose').disabled
        tree = t.on_screen('#path_picker_tree')
        sensitive = next(node for node in tree.root.children[0].children if node.data and node.data['path'].endswith('/1.1.1.1.txt'))
        tree.focus()
        await _cursor_to(t, tree, sensitive)
        selected = tree.cursor_node
        raw = t.on_screen('#path_picker_location').value
        await t.press('ctrl+shift+d')
        await t.wait_until(lambda: t.on_screen('#path_picker_location').password, desc='demo masks editable location')
        assert t.on_screen('#path_picker_location').value == raw and tree.cursor_node is selected
        assert '1.1.1.1' not in sensitive.label.plain
        assert sensitive.data['path'] == '/srv/retry-folder/1.1.1.1.txt'
        await t.press('ctrl+shift+d')
        await t.press('escape')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: t.on_screen('#remote_path_input').has_focus, desc='focus after cancel')
        assert t.on_screen('#local_path_input').value == '~/unchanged.bin'
        assert t.on_screen('#remote_path_input').value == '/srv/unchanged/'
        assert not sshd.target.sessions('sftp-open')


async def test_cancel_remote_picker_while_listing_is_pending(tui, seed, journey, sshd, monkeypatch):
    import asyncio
    from servonaut.widgets.remote_tree import RemoteTree

    _seed(seed, sshd)
    started, release = asyncio.Event(), asyncio.Event()
    original = RemoteTree._fetch_directory_async

    async def held_listing(self, path):
        started.set()
        await release.wait()
        return await original(self, path)

    monkeypatch.setattr(RemoteTree, '_fetch_directory_async', held_listing)
    try:
        async with tui() as t:
            await _open(t, 't', 'SCPTransferScreen')
            await t.click('#remote_path_browse')
            await t.wait_for_screen('RemotePathPickerModal')
            await t.wait_until(started.is_set, desc='listing pending')
            assert t.on_screen('#path_picker_choose').disabled
            await t.press('escape')
            await t.wait_for_screen('SCPTransferScreen')
            release.set()
            await t.wait_until(lambda: t.on_screen('#remote_path_input').has_focus, desc='cancel restores focus')
            assert t.on_screen('#remote_path_input').value == ''
            assert not sshd.target.sessions('sftp-open')
    finally:
        release.set()


async def test_download_through_a_symlinked_picker_root(tui, seed, journey, sshd):
    _seed(seed, sshd)
    remote = sshd.target.remote
    remote.write('/srv/releases/1/report.bin', PAYLOAD)
    remote.path('/srv/current').symlink_to('releases/1', target_is_directory=True)
    destination = seed.home / 'downloads'
    destination.mkdir()
    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await t.click('#radio_download')
        await _remote_picker(t, '/srv/current/report.bin', source=True)
        await _local_picker(t, 'local', destination, source=False)
        await _transfer_completed(t, 1)
        assert (destination / 'report.bin').read_bytes() == PAYLOAD


async def test_shellless_accounts_keep_file_copy_and_confirm_folder_overwrite(tui, seed, journey, sshd, monkeypatch):
    _seed(seed, sshd)
    remote = sshd.target.remote
    remote.write('/srv/report.bin', PAYLOAD)
    remote.write('/tmp/uploads/site/payload.bin', b'original')
    folder = seed.home / 'site'
    folder.mkdir()
    (folder / 'payload.bin').write_bytes(PAYLOAD[::-1])

    async def sftp_only(process, user, command):
        process.stderr.write(b'This service allows sftp connections only\n')
        return 1

    # SFTP is served separately; refuse actual SSH exec requests as a
    # ForceCommand internal-sftp account does, while real SCP still uses SFTP.
    monkeypatch.setattr(sshd.target, '_run', sftp_only)
    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await t.click('#radio_download')
        await _paste(t, '#remote_path_input', '/srv/report.bin')
        await _paste(t, '#local_path_input', '~/download.bin')
        await _transfer_completed(t, 1)
        assert (seed.home / 'download.bin').read_bytes() == PAYLOAD
        assert 'folder detection was unavailable' in t.on_screen('#status_output').render().plain.lower()

        await t.click('#radio_upload')
        await _paste(t, '#local_path_input', str(folder))
        await _paste(t, '#remote_path_input', '/tmp/uploads/')
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        before = len(sshd.target.sessions('sftp-open'))
        await t.click('#scp_folder_cancel')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: not t.on_screen('#transfer_button').disabled, desc='unknown destination cancel')
        assert len(sshd.target.sessions('sftp-open')) == before
        assert remote.read_bytes('/tmp/uploads/site/payload.bin') == b'original'
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        await t.click('#scp_folder_confirm')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: remote.read_bytes('/tmp/uploads/site/payload.bin') == PAYLOAD[::-1], desc='confirmed shellless folder copy')


async def test_typed_dot_folder_requires_consent_for_the_destination_itself(tui, seed, journey, sshd):
    _seed(seed, sshd)
    folder = seed.home / 'site'
    folder.mkdir()
    (folder / 'payload.bin').write_bytes(PAYLOAD)
    remote = sshd.target.remote
    remote.write('/tmp/merge-root/payload.bin', b'original')
    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await _paste(t, '#local_path_input', str(folder) + '/.')
        await _paste(t, '#remote_path_input', '/tmp/merge-root/')
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        assert not sshd.target.sessions('sftp-open')
        await t.click('#scp_folder_cancel')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_until(lambda: not t.on_screen('#transfer_button').disabled, desc='dot-source cancel')
        assert remote.read_bytes('/tmp/merge-root/payload.bin') == b'original'
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        await t.click('#scp_folder_confirm')
        await t.wait_for_screen('SCPTransferScreen')
        await t.wait_for_toast('^Transfer completed$')
        assert remote.read_bytes('/tmp/merge-root/payload.bin') == PAYLOAD
        assert not remote.path('/tmp/merge-root/site').exists()


async def test_folder_copy_onto_an_existing_file_cannot_be_confirmed(tui, seed, journey, sshd):
    _seed(seed, sshd)
    folder = seed.home / 'site'
    folder.mkdir()
    (folder / 'payload.bin').write_bytes(PAYLOAD)
    remote = sshd.target.remote
    remote.write('/tmp/conflict/site', b'keep file')
    async with tui() as t:
        await _open(t, 't', 'SCPTransferScreen')
        await _paste(t, '#local_path_input', str(folder))
        await _paste(t, '#remote_path_input', '/tmp/conflict/')
        await t.click('#transfer_button')
        await t.wait_for_screen('SCPFolderConfirmModal')
        await t.wait_until(lambda: t.find('#scp_folder_target'), desc='file collision details')
        assert 'Existing file: /tmp/conflict/site' in t.on_screen('#scp_folder_target').render().plain
        assert not t.find('#scp_folder_confirm')
        assert not sshd.target.sessions('sftp-open')
        await t.press('escape')
        await t.wait_for_screen('SCPTransferScreen')
        assert remote.read_bytes('/tmp/conflict/site') == b'keep file'
