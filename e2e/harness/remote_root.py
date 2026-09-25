"""The filesystem a loopback SSH server presents as its "remote" machine.

Every host started by :mod:`e2e.harness.sshd` owns a *remote root*: a
directory inside the journey's test root that plays the part of ``/`` on the
server. It holds the fixture files a journey reads (``/etc/os-release``,
``/var/log/...``, the login users' homes) and a ``bin`` directory that is the
*only* entry on the remote ``PATH``:

* a fixed list of read-only system tools, each a one-line wrapper that runs
  the host's copy from its system directories (``ls``, ``cat``, ``tail``,
  ``grep`` ...);
* scripted stubs for the tools whose real answers would describe the machine
  running the tests (``docker``, ``journalctl``, ``systemctl``, ``uname``,
  ``hostname``, ``uptime``, ``df``, ``free``) and a ``sudo`` that refuses.

Commands keep their shape but not their reach: :meth:`RemoteRoot.rewrite`
re-roots absolute paths under the usual data directories (``/var``, ``/etc``,
``/home``, ``/tmp`` ...) into the remote root, and :class:`OutputMapper`
maps the remote root back to ``/`` in everything the command prints, so the
application sees ``/var/log/syslog`` both ways. System paths (``/usr``,
``/proc``, ``/dev``) are left alone. This confines what a journey's commands
read and write; it is a hermeticity boundary, not a security sandbox.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Iterable, Mapping, Optional

# Where the real tools are found. A fixed list rather than the invoking
# PATH, so a wrapper in a developer's own bin directory is never picked up.
SYSTEM_TOOL_DIRS = ("/usr/bin", "/bin")

# Read-only tools a remote command may use. Anything else is "command not
# found", as on a minimal server.
LINKED_TOOLS = (
    "bash", "sh", "cat", "ls", "head", "tail", "grep", "egrep", "fgrep", "awk",
    "sed", "cut", "tr", "sort", "uniq", "wc", "find", "stat", "test", "[",
    "echo", "printf", "true", "false", "env", "basename", "dirname", "readlink",
    "realpath", "xargs", "zcat", "gzip", "date", "sleep", "id", "whoami", "du",
    "timeout", "file", "md5sum", "sha256sum",
)

# Top-level directories that belong to the remote machine. An absolute path
# under one of these is re-rooted into the remote root.
REMOTE_TOP_DIRS = ("var", "etc", "home", "root", "srv", "opt", "tmp", "mnt", "data", "run")

# An absolute path starting at a shell word boundary, under a remote top
# directory; or the bare root "/" when quoted or last on the line (the file
# browser lists ``ls -la "/"``).
_REMOTE_PATH = re.compile(
    r"(?:(?<=^)|(?<=[\s\"'=(<>|;&]))"
    r"(?:/(?:" + "|".join(REMOTE_TOP_DIRS) + r")(?=[/\s\"';|&)<>]|$)"
    r"|(?<=\")/(?=\")|(?<=\s)/$)"
)

OS_RELEASE = """\
PRETTY_NAME="E2E Linux 12 (fixture)"
NAME="E2E Linux"
VERSION_ID="12"
VERSION="12 (fixture)"
ID=e2elinux
ID_LIKE=debian
HOME_URL="https://example.com/"
"""

_STUB_HEADER = "#!/bin/sh\n# Scripted stand-in used by the servonaut e2e suite.\n"


def _stub_docker() -> str:
    return _STUB_HEADER + r"""case "$1" in
  ps)
    case "$*" in
      *json*) printf '%s\n' '{"Names":"web-app","Image":"nginx:1.27","Status":"Up 3 hours"}' ;;
      *--format*) printf '%s\n' 'web-app|nginx:1.27|Up 3 hours' ;;
      *) printf '%s\n' 'CONTAINER ID   IMAGE        STATUS       NAMES' \
                       '0a1b2c3d4e5f   nginx:1.27   Up 3 hours   web-app' ;;
    esac ;;
  version|--version) echo "Docker version 27.0.0, build e2e0000" ;;
  logs) printf '%s\n' "web-app started" "web-app ready" ;;
  *) : ;;
esac
exit 0
"""


def _stub_journalctl() -> str:
    return _STUB_HEADER + r"""printf '%s\n' \
  "Jan 01 10:00:00 $(hostname) systemd[1]: Started nginx.service - A high performance web server." \
  "Jan 01 10:00:05 $(hostname) app[812]: worker ready"
exit 0
"""


def _stub_systemctl() -> str:
    return _STUB_HEADER + r"""case "$1" in
  list-unit-files) printf '%s\n' "nginx.service enabled enabled" \
                     "ssh.service enabled enabled" "app-worker.service enabled enabled" ;;
  list-units) printf '%s\n' "nginx.service loaded active running A high performance web server" \
                             "app-worker.service loaded active running App worker" ;;
  is-active) echo active ;;
  is-enabled) echo enabled ;;
  status) printf '%s\n' "* $2 - fixture service" "     Active: active (running)" ;;
  *) : ;;
esac
exit 0
"""


def _stub_hostname(hostname_file: str) -> str:
    return _STUB_HEADER + f"exec cat {shlex.quote(hostname_file)}\n"


def _stub_uname(hostname_file: str) -> str:
    name = f"$(cat {shlex.quote(hostname_file)})"
    return _STUB_HEADER + f"""case "$*" in
  *a*) echo "Linux {name} 6.1.0-e2e #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux" ;;
  *r*) echo "6.1.0-e2e" ;;
  *m*) echo "x86_64" ;;
  *) echo "Linux" ;;
esac
"""


def _stub_print(lines: Iterable[str]) -> str:
    body = "".join(f"printf '%s\\n' {shlex.quote(line)}\n" for line in lines)
    return _STUB_HEADER + body


def _stubs(hostname_file: str) -> dict[str, str]:
    """Stub scripts; the host name comes from the remote ``/etc/hostname``."""
    return {
        "docker": _stub_docker(),
        "journalctl": _stub_journalctl(),
        "systemctl": _stub_systemctl(),
        "uname": _stub_uname(hostname_file),
        "hostname": _stub_hostname(hostname_file),
        "uptime": _stub_print(
            [" 10:00:00 up 3 days,  2:14,  1 user,  load average: 0.10, 0.05, 0.01"]
        ),
        "df": _stub_print(
            [
                "Filesystem      Size  Used Avail Use% Mounted on",
                "/dev/vda1        40G   12G   28G  30% /",
            ]
        ),
        "free": _stub_print(
            [
                "               total        used        free      shared  buff/cache   available",
                "Mem:            3900        1200        1800          10         900        2500",
                "Swap:              0           0           0",
            ]
        ),
        "sudo": _STUB_HEADER + 'echo "sudo: a password is required" >&2\nexit 1\n',
    }


def _default_files(hostname: str) -> dict[str, str]:
    return {
        "etc/os-release": OS_RELEASE,
        "etc/hostname": f"{hostname}\n",
        "var/log/syslog": (
            f"Jan 01 10:00:00 {hostname} systemd[1]: Started Daily apt download activities.\n"
            f"Jan 01 10:00:01 {hostname} CRON[901]: (root) CMD (run-parts /etc/cron.hourly)\n"
        ),
        "var/log/nginx/access.log": (
            '10.0.0.5 - - [01/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "e2e"\n'
            '10.0.0.5 - - [01/Jan/2026:10:00:02 +0000] "GET /health HTTP/1.1" 200 2 "-" "e2e"\n'
        ),
        "var/log/app/worker.log": "worker: job 1 done\nworker: job 2 done\n",
        "var/www/html/index.html": "<h1>fixture site</h1>\n",
    }


class RemoteRoot:
    """One remote machine's filesystem, tools and command mapping."""

    def __init__(self, base: Path, hostname: str, users: Iterable[str] = ()) -> None:
        base.mkdir(parents=True, exist_ok=True)
        self.base = base.resolve()
        self.hostname = hostname
        self.bin = self.base / "bin"
        # The rewrite inserts, and the output mapper removes, this spelling.
        self._root_text = str(self.base)
        self._build(users)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self, users: Iterable[str]) -> None:
        for directory in ("bin", "tmp", "var/log", "srv", "opt", "root"):
            (self.base / directory).mkdir(parents=True, exist_ok=True)
        (self.base / "tmp").chmod(0o1777)
        for relative, content in _default_files(self.hostname).items():
            self.write(f"/{relative}", content)
        for user in users:
            self.home_of(user)
        self._link_tools()
        for name, script in _stubs(str(self.base / "etc" / "hostname")).items():
            path = self.bin / name
            path.unlink(missing_ok=True)
            path.write_text(script, encoding="utf-8")
            path.chmod(0o755)

    def _link_tools(self) -> None:
        # Small exec wrappers rather than symlinks: the suite's guard treats a
        # symlink by its target, so a link into /usr/bin could not be removed.
        for tool in LINKED_TOOLS:
            source = next(
                (Path(d) / tool for d in SYSTEM_TOOL_DIRS if (Path(d) / tool).exists()), None
            )
            if source is None:
                continue
            wrapper = self.bin / tool
            wrapper.write_text(
                f'#!/bin/sh\nexec {shlex.quote(str(source.resolve()))} "$@"\n', encoding="utf-8"
            )
            wrapper.chmod(0o755)

    def home_of(self, user: str) -> Path:
        """The user's home directory (created on first use), like a login."""
        home = self.base / ("root" if user == "root" else f"home/{user}")
        if not home.exists():
            home.mkdir(parents=True)
            # Keeps the host's shell start-up files from printing login hints.
            (home / ".hushlogin").write_text("", encoding="utf-8")
        return home

    # ------------------------------------------------------------------
    # Files, addressed by their remote path
    # ------------------------------------------------------------------

    def path(self, remote_path: str) -> Path:
        """The local path behind an absolute *remote_path*."""
        if not remote_path.startswith("/"):
            raise ValueError(f"remote paths are absolute: {remote_path!r}")
        local = (self.base / remote_path.lstrip("/")).resolve()
        if local != self.base and not str(local).startswith(self._root_text + os.sep):
            raise ValueError(f"{remote_path!r} leaves the remote root")
        return local

    def write(self, remote_path: str, content: "str | bytes", mode: int = 0o644) -> Path:
        local = self.path(remote_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            local.write_bytes(content)
        else:
            local.write_text(content, encoding="utf-8")
        local.chmod(mode)
        return local

    def append(self, remote_path: str, text: str) -> None:
        with self.path(remote_path).open("a", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()

    def read_bytes(self, remote_path: str) -> bytes:
        return self.path(remote_path).read_bytes()

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def rewrite(self, command: str) -> str:
        """Re-root the remote absolute paths in a shell command."""
        return _REMOTE_PATH.sub(lambda match: self._root_text + match.group(0), command)

    def environment(self, user: str) -> dict[str, str]:
        """The complete environment of a command run for *user*."""
        home = self.home_of(user)
        return {
            "HOME": str(home),
            "USER": user,
            "LOGNAME": user,
            "SHELL": "/bin/bash",
            "PATH": str(self.bin),
            "PWD": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": str(self.base / "tmp"),
        }

    def output_mapper(self) -> "OutputMapper":
        return OutputMapper(self._root_text)

    def shell(self) -> str:
        """The login shell used to run commands."""
        return "/bin/bash" if Path("/bin/bash").exists() else "/bin/sh"


class OutputMapper:
    """Map the remote root back to ``/`` in a stream of command output.

    Output is handled a line at a time so a path split across two reads is
    still recognised; :meth:`flush` returns what is left when the stream
    ends.
    """

    def __init__(self, root_text: str) -> None:
        self._root = root_text.encode()
        self._pending = b""

    def feed(self, data: bytes) -> bytes:
        self._pending += data
        cut = self._pending.rfind(b"\n") + 1
        if cut == 0:
            return b""
        ready, self._pending = self._pending[:cut], self._pending[cut:]
        return self._map(ready)

    def flush(self) -> bytes:
        ready, self._pending = self._pending, b""
        return self._map(ready)

    def _map(self, data: bytes) -> bytes:
        return data.replace(self._root + b"/", b"/").replace(self._root, b"/")


def describe(roots: Mapping[str, "RemoteRoot"], only: Optional[str] = None) -> str:
    """A short listing of the remote roots, for failure artifacts."""
    lines = []
    for name, root in roots.items():
        if only and name != only:
            continue
        for path in sorted(root.base.rglob("*")):
            if path.is_file() and root.bin not in path.parents:
                lines.append(f"{name}:/{path.relative_to(root.base)}")
    return "\n".join(lines) + "\n"
