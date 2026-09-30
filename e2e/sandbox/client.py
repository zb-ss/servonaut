"""The commands that drive a running sandbox: status, run, mcp-call, mcp, desktop, down.

They run in the caller's own shell, unguarded, and never import
``servonaut``: they read the live sandbox's ``state.json`` and start the
checkout's real CLI, MCP server or desktop child with the environment
recorded there, so every Servonaut process is a guarded sandbox child.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from e2e.sandbox import state

SERVONAUT_MODULE = "servonaut.main"
# The owner starts the desktop child within the launcher's own start-up
# timeout (e2e/harness/desktop.py); this adds room for a busy machine.
DESKTOP_WAIT_SECONDS = 60.0
CHILDREN_STOP_SECONDS = 15.0
_POLL_SECONDS = 0.1

# The terminal is drawn on a canvas: the page holds neither its text nor its
# size in cells, so text waits never match and a cell has no element. This
# start snippet sets up ``window.servonautQa`` before it starts the session:
#
# - ``columns``/``rows``: the size the page sends with the session
#   (``/ws?width=..&height=..``, then ``["resize", ...]`` messages);
# - ``text()``/``waitForText(text)``: the visible screen, read from the
#   terminal's own buffer. The frontend keeps its xterm instance to itself,
#   so a one-shot hook catches it while it is built (the constructor assigns
#   ``_addonManager``) and removes itself; ``text()`` is null if a frontend
#   update ever stops that;
# - ``focus()``: keys reach the app only while the terminal has focus.
#
# It then waits for the first output and focuses the terminal.
START_SESSION_JS = """async () => {
  const pause = () => new Promise((resolve) => setTimeout(resolve, 100));
  const qa = window.servonautQa = {
    columns: 0,
    rows: 0,
    terminal: null,
    focus() { document.querySelector('.xterm-helper-textarea').focus(); },
    text() {
      const terminal = qa.terminal;
      if (!terminal) return null;
      const buffer = terminal.buffer.active;
      const lines = [];
      for (let row = 0; row < terminal.rows; row++) {
        const line = buffer.getLine(buffer.viewportY + row);
        lines.push(line ? line.translateToString(true) : '');
      }
      return lines.join('\\n');
    },
    async waitForText(text, timeoutMs = 20000) {
      const deadline = Date.now() + timeoutMs;
      while (!(qa.text() || '').includes(text)) {
        if (Date.now() > deadline) throw new Error(`${text} not on the terminal after ${timeoutMs} ms`);
        await pause();
      }
      return true;
    },
  };
  Object.defineProperty(Object.prototype, '_addonManager', {
    configurable: true,
    set(value) {
      delete Object.prototype._addonManager;
      Object.defineProperty(this, '_addonManager', {
        value, writable: true, enumerable: true, configurable: true,
      });
      qa.terminal = this;
    },
  });
  const note = (columns, rows) => { qa.columns = Number(columns); qa.rows = Number(rows); };
  const NativeWebSocket = window.WebSocket;
  window.WebSocket = class extends NativeWebSocket {
    constructor(url, protocols) {
      super(url, protocols);
      const query = new URL(url).searchParams;
      note(query.get('width'), query.get('height'));
      const send = this.send.bind(this);
      this.send = (data) => {
        try {
          const message = JSON.parse(data);
          if (message[0] === 'resize') note(message[1].width, message[1].height);
        } catch (error) { /* terminal input, not JSON */ }
        return send(data);
      };
    }
  };
  window.startServonaut(TOKEN);
  const deadline = Date.now() + 30000;
  while (!document.body.classList.contains('-first-byte')) {
    if (Date.now() > deadline) break;
    await pause();
  }
  delete Object.prototype._addonManager;
  if (!document.body.classList.contains('-first-byte')) {
    throw new Error('no terminal output after 30 s: see the page console');
  }
  qa.focus();
  return {columns: qa.columns, rows: qa.rows, text: qa.terminal !== null};
}"""
# The middle of terminal cell (COLUMN, ROW), 0-based, in page coordinates:
# what the end-to-end harness clicks (DesktopPage.click_cell).
CELL_CENTER_JS = """() => {
  const [column, row] = [COLUMN, ROW];
  const {columns, rows} = window.servonautQa;
  const box = document.querySelector('.xterm-screen').getBoundingClientRect();
  return {x: box.x + (column + 0.5) * box.width / columns,
          y: box.y + (row + 0.5) * box.height / rows};
}"""
CLICK_CELL_PLAYWRIGHT = """async (page) => {
  const {x, y} = await page.evaluate(%s);
  await page.mouse.click(x, y);
}""" % CELL_CENTER_JS.replace("\n", "\n  ")


def start_session_js(token: str) -> str:
    return START_SESSION_JS.replace("TOKEN", json.dumps(token))


def cell_center_js(column: int, row: int) -> str:
    return CELL_CENTER_JS.replace("[COLUMN, ROW]", f"[{int(column)}, {int(row)}]")


class ClientError(RuntimeError):
    """A command cannot go ahead (the message says why)."""


def _say(message: str) -> None:
    sys.stderr.write(f"qa-sandbox: {message}\n")
    sys.stderr.flush()


def live_state() -> dict:
    try:
        return state.load_live_state()
    except state.SandboxUnavailable as exc:
        raise ClientError(str(exc)) from None


def _wait(predicate: Any, timeout: float) -> bool:
    """Poll *predicate* until it is true; False when *timeout* passed first."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)
    return True


def _servonaut_argv(current: dict, args: Sequence[str]) -> list[str]:
    return [current["python"], "-m", SERVONAUT_MODULE, *args]


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def format_fleet(rows: Iterable[dict]) -> str:
    """A plain-text table of the recorded fleet summary."""
    headers = ("shown", "reference", "provider", "account", "api state", "ssh")
    table = [headers] + [
        (r["shown"], r["reference"], r["provider"], r["account"], r["state"],
         "yes" if r["ssh"] else "no")
        for r in rows
    ]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(headers))]
    return "\n".join(
        "  ".join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip()
        for row in table
    )


def status(*, as_json: bool) -> int:
    try:
        current = live_state()
    except ClientError as exc:
        print(str(exc))
        return 1
    if as_json:
        print(json.dumps(current, indent=2, sort_keys=True))
        return 0
    desktop = current.get("desktop") or {}
    if desktop.get("pid"):
        running = state.is_alive(desktop["pid"], state.process_identity(desktop["pid"]))
        desktop_line = f"{desktop['origin']} (desktop child pid {desktop['pid']}, " + (
            "running)" if running else "exited: run `desktop` again for a new one)"
        )
    elif desktop.get("error"):
        desktop_line = f"failed to start: {desktop['error']}"
    else:
        desktop_line = "not started (python -m e2e.sandbox desktop)"
    lines = [
        f"QA sandbox: running, owner pid {current['owner_pid']}, scenario {current['scenario']}"
        f"{', signed in' if current.get('signed_in') else ''}, since {current['started_at']}",
        f"checkout:   {current['repo_root']}",
        f"root:       {current['root']}",
        f"home:       {current['sandbox']['home']}",
        f"pointer:    {state.pointer_path()}",
        f"desktop:    {desktop_line}",
        "",
        "fleet:",
        format_fleet(current["fleet"]),
        "",
        *(f"- {note}" for note in current.get("notes", [])),
        "",
        "fakes:",
        *(f"  {name:<14} {url}" for name, url in current["urls"].items()),
        "",
        "logs (request logs are rewritten about once a second):",
        *(f"  {name:<27} {path}" for name, path in current["logs"].items()),
    ]
    print("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# run, mcp-call, mcp
# ---------------------------------------------------------------------------


def _strip_program(args: Sequence[str]) -> list[str]:
    args = list(args)
    if args[:1] == ["--"]:
        args = args[1:]
    if args[:1] == ["servonaut"]:
        args = args[1:]
    return args


def run(args: Sequence[str]) -> int:
    """Run ``servonaut <args>`` in the sandbox; stream its output; return its exit code."""
    from e2e.harness.processes import UnguardedChildError, require_armed

    current = live_state()
    process = subprocess.Popen(
        _servonaut_argv(current, _strip_program(args)),
        env=current["env"],
        cwd=current["sandbox"]["base"],
    )
    while True:
        try:
            code = process.wait()
            break
        except KeyboardInterrupt:
            continue  # the child got the same interrupt from the terminal
    try:
        require_armed(Path(current["logs"]["armed"]), pid=process.pid)
    except UnguardedChildError as exc:
        _say(str(exc))
        return 70
    return code


async def _call_tool(current: dict, tool: str, arguments: dict, timeout: float) -> Any:
    from e2e.harness.processes import mcp_session

    logs = Path(current["logs"]["children"])
    stderr_path = logs / f"mcp-call-{time.strftime('%H%M%S')}-{uuid.uuid4().hex[:6]}.stderr.log"
    async with mcp_session(
        _servonaut_argv(current, []),
        env=current["env"],
        cwd=Path(current["sandbox"]["base"]),
        stderr_path=stderr_path,
        armed_log=Path(current["logs"]["armed"]),
    ) as session:
        names = await session.tool_names()
        result = None
        if tool in names:
            result = await session.session.call_tool(
                tool, arguments, read_timeout_seconds=timedelta(seconds=timeout)
            )
    if result is None:
        close = difflib.get_close_matches(tool, names, n=5)
        hint = f"; did you mean {', '.join(close)}?" if close else ""
        raise ClientError(f"the MCP server has no tool {tool!r}{hint}")
    return result, stderr_path


def mcp_call(tool: str, raw_arguments: Optional[str], *, timeout: float) -> int:
    """Call one tool of the real MCP server in the sandbox and print its result."""
    try:
        arguments = json.loads(raw_arguments) if raw_arguments else {}
    except ValueError as exc:
        raise ClientError(f"the tool arguments are not JSON: {exc}") from None
    if not isinstance(arguments, dict):
        raise ClientError("the tool arguments must be a JSON object")
    current = live_state()
    result, stderr_path = asyncio.run(_call_tool(current, tool, arguments, timeout))
    print("\n".join(getattr(item, "text", "") for item in result.content))
    if result.isError:
        _say(f"{tool} reported an error (server log: {stderr_path})")
        return 1
    return 0


def serve_mcp() -> int:
    """Replace this process with the real MCP server (stdio) in the sandbox."""
    current = live_state()
    argv = _servonaut_argv(current, ["--mcp"])
    os.chdir(current["sandbox"]["base"])
    os.execve(argv[0], argv, current["env"])
    return 0  # not reached


# ---------------------------------------------------------------------------
# desktop
# ---------------------------------------------------------------------------


def desktop(*, new: bool, as_json: bool) -> int:
    """Have the owner start (or reuse) the desktop child; print how to open it."""
    current = live_state()
    root = Path(current["root"])
    request = {"id": uuid.uuid4().hex, "new": new}
    state.write_json(root / state.DESKTOP_REQUEST, request)
    os.kill(current["owner_pid"], signal.SIGUSR1)
    answered: dict = {}

    def answer() -> bool:
        latest = state.read_json(root / state.STATE_FILE) or {}
        info = latest.get("desktop") or {}
        if info.get("request") == request["id"]:
            answered.update(info)
            return True
        if not state.owner_alive(current):
            raise ClientError("the sandbox stopped while starting the desktop child")
        return False

    if not _wait(answer, DESKTOP_WAIT_SECONDS):
        raise ClientError(f"no desktop child after {DESKTOP_WAIT_SECONDS:.0f}s; see {root / 'logs'}")
    if answered.get("error"):
        raise ClientError(f"the desktop child did not start: {answered['error']}")
    if as_json:
        print(json.dumps(answered, indent=2, sort_keys=True))
        return 0
    if answered.get("reused"):
        _say("reusing the running desktop child; if a page already used its token, "
             "run `desktop --new` for a fresh one")
    print("\n".join([
        f"URL:    {answered['origin']}",
        f"token:  {answered['token']}",
        f"pid:    {answered['pid']} (desktop child)",
        "",
        "1. Open the URL in a browser page.",
        "2. Start the session (page JavaScript, e.g. browser_evaluate). It waits for the",
        "   first output (the page body gets the class -first-byte) and focuses the",
        "   terminal. The session is single use: a reload ends it, and `desktop` then",
        "   starts a new desktop child.",
        start_session_js(answered["token"]),
        "3. Type and press keys as usual. Keys reach the app only while the terminal has",
        "   focus: after a click outside the terminal, run",
        "     () => window.servonautQa.focus()",
        "   The terminal is drawn on a canvas, so text waits (browser_wait_for) never",
        "   match. Judge states from screenshots, or read the visible screen as text:",
        "     () => window.servonautQa.text()",
        "     () => window.servonautQa.waitForText('app-1')      // rejects after 20 s",
        "4. Click terminal cell (COLUMN, ROW), 0-based (Playwright code, e.g. browser_run_code):",
        CLICK_CELL_PLAYWRIGHT,
        "   or get the cell's page coordinates for another click tool (browser_evaluate):",
        CELL_CENTER_JS,
    ]))
    return 0


# ---------------------------------------------------------------------------
# down
# ---------------------------------------------------------------------------


def _known_pids(record: dict) -> list[int]:
    desktop = record.get("desktop") or {}
    return [pid for pid in (desktop.get("pid"), desktop.get("keeper_pid")) if isinstance(pid, int)]


def _survivors(root: Path, record: dict) -> list[int]:
    if state.can_list_processes():
        return state.sandbox_pids(root)
    # Without /proc only the processes the sandbox recorded can be checked.
    return [pid for pid in _known_pids(record) if _pid_exists(pid)]


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def down(*, timeout: float) -> int:
    """Stop the live sandbox and wait until every one of its processes is gone."""
    from e2e.harness.processes import stop_sandbox_pid

    pointer_file = state.pointer_path()
    pointer = state.read_json(pointer_file)
    if pointer is None:
        print("No QA sandbox is running.")
        return 0
    root = Path(pointer["root"])
    record = state.read_json(root / state.STATE_FILE) or pointer
    was_running = state.owner_alive(pointer)
    if was_running:
        os.kill(pointer["owner_pid"], signal.SIGTERM)
        if not _wait(lambda: not state.owner_alive(pointer), timeout):
            _say(f"the owner (pid {pointer['owner_pid']}) did not stop within {timeout:.0f}s; "
                 "killing it")
            os.kill(pointer["owner_pid"], signal.SIGKILL)
            _wait(lambda: not state.owner_alive(pointer), CHILDREN_STOP_SECONDS)
    # Children stop by themselves once the owner is gone.
    _wait(lambda: not _survivors(root, record), CHILDREN_STOP_SECONDS)
    survivors = _survivors(root, record)
    for pid in survivors:
        _say(f"survived the owner: {pid}; {stop_sandbox_pid(pid, sandbox_root=root)}")
    # An owner that could not clean up leaves its pointer and root behind.
    if state.read_json(pointer_file) == pointer:
        pointer_file.unlink(missing_ok=True)
    marker = state.read_json(root / state.MARKER)
    if marker is not None and marker.get("owner_pid") == pointer["owner_pid"] and not record.get("keep"):
        shutil.rmtree(root, ignore_errors=True)
    if survivors:
        _say(f"{len(survivors)} process(es) outlived the sandbox; see {root / 'logs'}")
        return 1
    if was_running:
        print(f"QA sandbox stopped (owner pid {pointer['owner_pid']}).")
    else:
        print(f"The QA sandbox (owner pid {pointer['owner_pid']}) had already stopped; "
              "removed what it left behind.")
    return 0
