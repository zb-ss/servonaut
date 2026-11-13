"""A remote path reaches the remote end as data, whichever scp client is installed.

An scp before OpenSSH 9.0 hands the remote path to the remote shell, so a name
such as ``x;cmd;.log`` runs ``cmd``. With ``-s`` (OpenSSH 8.7 and later) the
path travels over SFTP. Quoting works for neither protocol, so the service
passes ``-s`` when the client has it and backslash-escapes the path when not.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from servonaut.services.scp_service import SCPService
from servonaut.utils import scp_client

OUTSIDE_NAMES = [
    "x;touch marker;.log",
    "$(touch marker).log",
    "a b`touch marker`.log",
    "it's\"; touch marker;'.log",
    "q*?[x].log",
    "back\\slash.log",
    "r[1].log",
    "a*b.log",
    "q?.log",
]

# A file with a similar name that a pattern would also match.
DECOYS = {"r[1].log": "r1.log", "a*b.log": "aXb.log", "q?.log": "qZ.log", "back\\slash.log": "backslash.log"}


@pytest.fixture
def modern_client(monkeypatch):
    monkeypatch.setattr(scp_client, "_answers", {"scp": True})


@pytest.fixture
def legacy_client(monkeypatch):
    monkeypatch.setattr(scp_client, "_answers", {"scp": False})


def _upload(path: str) -> list[str]:
    return SCPService().build_upload_command("/tmp/up", path, "9.9.9.9", "deploy")


def _download(path: str) -> list[str]:
    return SCPService().build_download_command(path, "/tmp/down", "9.9.9.9", "deploy")


# ---------------------------------------------------------------------------
# argv
# ---------------------------------------------------------------------------

def test_a_client_with_the_sftp_flag_gets_it_and_the_raw_path(modern_client) -> None:
    for command, remote in ((_upload("/srv/x;y.log"), -1), (_download("/srv/x;y.log"), -2)):
        assert "-s" in command[: command.index("--")]
        assert command[remote] == "deploy@9.9.9.9:/srv/x;y.log"


def test_a_client_without_it_gets_an_escaped_path_and_no_flag(legacy_client) -> None:
    for command in (_upload("/srv/x;y z.log"), _download("/srv/x;y z.log")):
        assert "-s" not in command
        assert "deploy@9.9.9.9:/srv/x\;y\\ z.log" in command
    assert _upload("~/my dir/a.log")[-1] == "deploy@9.9.9.9:~/my\\ dir/a.log"


def test_sftp_reads_a_download_source_as_a_pattern_so_its_special_characters_are_escaped(modern_client) -> None:
    assert _download("/srv/a\\b")[-2] == "deploy@9.9.9.9:/srv/a\\\\b"
    assert _download("/srv/a*b?[1].log")[-2] == "deploy@9.9.9.9:/srv/a\\*b\\?\\[1].log"
    assert _download("/srv/{a,b}")[-2] == "deploy@9.9.9.9:/srv/{a,b}"
    assert _upload("/srv/a\\b*[1]")[-1] == "deploy@9.9.9.9:/srv/a\\b*[1]"


def test_plain_paths_are_unchanged_in_both_modes(modern_client, legacy_client) -> None:
    assert _upload("/var/log/app-1/a_b.log")[-1] == "deploy@9.9.9.9:/var/log/app-1/a_b.log"


@pytest.mark.parametrize(
    ("path", "escaped"),
    [
        ("x;touch marker;.log", "x\;touch\\ marker\;.log"),
        ("$(id).log", "\\$\\(id\\).log"),
        ("a`b`", "a\\`b\\`"),
        ("it's", "it\\'s"),
        ('say"hi"', 'say\\"hi\\"'),
        ("q*?[x]", "q\\*\\?\\[x\\]"),
        ("back\\slash", "back\\\\slash"),
        ("~/a b", "~/a\\ b"),
        ("~root/x", "\\~root/x"),
        ("é", "\\é"),
    ],
)
def test_escaping_table(path, escaped) -> None:
    assert scp_client.legacy_remote_path(path) == escaped


@pytest.mark.parametrize("path", ["a\nb", "a\rb", "a\x1bb", "a\x00b", "a\x7fb", "a\x9bb"])
def test_a_control_character_is_refused_with_a_clear_message(legacy_client, path) -> None:
    with pytest.raises(ValueError, match="control character or a line break"):
        _upload(path)


def test_a_control_character_is_fine_for_a_client_that_uses_sftp(modern_client) -> None:
    assert _upload("a\nb")[-1] == "deploy@9.9.9.9:a\nb"


# ---------------------------------------------------------------------------
# The question put to the client
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        ("usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path]", True),
        ("usage: scp [-346ABCpqRrsTv] [-c cipher]", True),
        ("usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config]", False),
        ("usage: scp [-346ABCOpqRrTv] [-c cipher]", False),
        ("", False),
        ("some other program", False),
    ],
)
def test_the_usage_line_tells_whether_the_flag_exists(usage, expected) -> None:
    assert scp_client.parse_sftp_flag(usage) is expected


def test_the_client_is_asked_once(monkeypatch) -> None:
    monkeypatch.setattr(scp_client, "_answers", {})
    monkeypatch.setattr(scp_client, "_probes", {})
    asked = []

    def probe(executable):
        asked.append(executable)
        return True

    monkeypatch.setattr(scp_client, "_probe", probe)
    assert scp_client.supports_sftp_flag("scp") is True
    assert scp_client.supports_sftp_flag("scp") is True
    SCPService()
    assert asked == ["scp"]


def test_the_question_is_asked_off_the_calling_thread(monkeypatch) -> None:
    import threading

    monkeypatch.setattr(scp_client, "_answers", {})
    monkeypatch.setattr(scp_client, "_probes", {})
    threads = []
    monkeypatch.setattr(scp_client, "_probe", lambda executable: threads.append(threading.current_thread()) or False)
    SCPService()
    scp_client.supports_sftp_flag("scp")
    assert threads and threads[0] is not threading.current_thread()


def test_a_client_that_cannot_be_asked_counts_as_not_having_the_flag(monkeypatch) -> None:
    def broken(*_args, **_kwargs):
        raise FileNotFoundError("scp")

    monkeypatch.setattr(subprocess, "run", broken)
    assert scp_client._probe("scp") is False


# ---------------------------------------------------------------------------
# The real client
# ---------------------------------------------------------------------------

FAKE_TRANSPORT = """#!/bin/sh
log="$REMOTE_ROOT/../transport.log"
sub=0
while [ $# -gt 0 ]; do
  case "$1" in
    -s) sub=1; shift ;;
    -o|-p|-l|-i|-F|-J|-c|-m|-b|-e|-E|-L|-R|-D|-W|-w|-O|-Q|-S|-B|-I) shift 2 ;;
    -*) shift ;;
    *) break ;;
  esac
done
host="$1"; shift
printf 'sub=%s cmd=[%s]\\n' "$sub" "$*" >> "$log"
cd "$REMOTE_ROOT" || exit 1
if [ "$sub" = 1 ]; then exec /usr/lib/openssh/sftp-server; fi
exec /bin/sh -c "$*"
"""

needs_client = pytest.mark.skipif(
    shutil.which("scp") is None or not os.path.exists("/usr/lib/openssh/sftp-server"),
    reason="needs an OpenSSH scp client and sftp-server",
)


def _run_scp(tmp_path: Path, command: list[str], legacy: bool) -> subprocess.CompletedProcess:
    transport = tmp_path / "transport.sh"
    transport.write_text(FAKE_TRANSPORT)
    transport.chmod(0o755)
    argv = [command[0], "-S", str(transport), *(["-O"] if legacy else []), *command[1:]]
    return subprocess.run(
        argv, env={**os.environ, "REMOTE_ROOT": str(tmp_path / "remote")},
        capture_output=True, text=True, timeout=60, check=False,
    )


@needs_client
@pytest.mark.real_ssh_process
@pytest.mark.parametrize("name", OUTSIDE_NAMES)
@pytest.mark.parametrize("client", ["legacy", "modern"])
def test_download_gets_the_right_file_and_runs_nothing(tmp_path, monkeypatch, client, name) -> None:
    monkeypatch.setattr(scp_client, "_answers", {"scp": client == "modern"})
    (tmp_path / "remote").mkdir()
    (tmp_path / "remote" / name).write_text("real content\n")
    if name in DECOYS:
        (tmp_path / "remote" / DECOYS[name]).write_text("decoy\n")
    command = SCPService().build_download_command(name, str(tmp_path / "out"), "h", "u")
    # Drop the host-key and keepalive options; the stand-in transport is not ssh.
    done = _run_scp(tmp_path, command, legacy=client == "legacy")
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "out").is_file(), "the target must be one file, not a directory of matches"
    assert (tmp_path / "out").read_text() == "real content\n"
    assert not (tmp_path / "remote" / "marker").exists()


@needs_client
@pytest.mark.real_ssh_process
@pytest.mark.parametrize("name", OUTSIDE_NAMES[:3])
def test_legacy_upload_runs_nothing(tmp_path, monkeypatch, name) -> None:
    monkeypatch.setattr(scp_client, "_answers", {"scp": False})
    (tmp_path / "remote").mkdir()
    (tmp_path / "up").write_text("uploaded\n")
    command = SCPService().build_upload_command(str(tmp_path / "up"), name, "h", "u")
    done = _run_scp(tmp_path, command, legacy=True)
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "remote" / name).read_text() == "uploaded\n"
    assert not (tmp_path / "remote" / "marker").exists()


def test_the_client_is_asked_once_for_a_build_and_for_the_process(monkeypatch) -> None:
    asked = []
    monkeypatch.setattr(scp_client, "_answers", {})
    monkeypatch.setattr(scp_client, "_probes", {})
    monkeypatch.setattr(scp_client, "_probe", lambda executable: asked.append(executable) or True)
    service = SCPService()
    seen = []
    real = scp_client.supports_sftp_flag
    monkeypatch.setattr(scp_client, "supports_sftp_flag", lambda executable="scp": seen.append(1) or real(executable))
    service.build_download_command("/srv/a", "/tmp/a", "9.9.9.9", "u")
    assert len(seen) == 1
    service.build_upload_command("/tmp/a", "/srv/a", "9.9.9.9", "u")
    assert asked == ["scp"]


def test_the_probe_runs_without_a_console_window(monkeypatch) -> None:
    seen = {}

    def run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 1, "", "usage: scp [-346ABCOpqRrsTv]")

    monkeypatch.setattr(subprocess, "run", run)
    assert scp_client._probe("scp") is True
    from servonaut.utils.ssh_utils import background_process_kwargs

    assert all(seen.get(key) == value for key, value in background_process_kwargs().items())
