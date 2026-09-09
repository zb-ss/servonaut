"""Tests for SSH utility functions."""

import os
import asyncio
import subprocess
import sys

import pytest

from servonaut.utils.ssh_utils import (
    expand_key_path,
    validate_key_path,
    get_key_permissions,
    parse_ssh_output,
    run_ssh_subprocess,
)


class TestExpandKeyPath:

    def test_expand_tilde(self):
        result = expand_key_path('~/my-key.pem')
        assert result == os.path.expanduser('~/my-key.pem')
        assert '~' not in result

    def test_absolute_path(self):
        assert expand_key_path('/absolute/path.pem') == '/absolute/path.pem'

    def test_env_var(self, monkeypatch):
        monkeypatch.setenv('MY_KEY_DIR', '/custom/keys')
        assert expand_key_path('$MY_KEY_DIR/key.pem') == '/custom/keys/key.pem'


class TestValidateKeyPath:

    def test_existing_file(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        assert validate_key_path(str(key_file)) is True

    def test_nonexistent_file(self):
        assert validate_key_path('/nonexistent/path.pem') is False

    def test_directory_not_file(self, tmp_path):
        assert validate_key_path(str(tmp_path)) is False


class TestGetKeyPermissions:

    def test_permissions_600(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        os.chmod(str(key_file), 0o600)
        assert get_key_permissions(str(key_file)) == '600'

    def test_permissions_400(self, tmp_path):
        key_file = tmp_path / 'test.pem'
        key_file.touch()
        os.chmod(str(key_file), 0o400)
        assert get_key_permissions(str(key_file)) == '400'


class TestParseSshOutput:

    def test_basic(self):
        assert parse_ssh_output('line1\nline2\nline3\n') == ['line1', 'line2', 'line3']

    def test_strips_whitespace(self):
        assert parse_ssh_output('  line1  \n  line2  \n') == ['line1', 'line2']

    def test_skips_empty_lines(self):
        assert parse_ssh_output('line1\n\n\nline2\n') == ['line1', 'line2']

    def test_empty_input(self):
        assert parse_ssh_output('') == []


@pytest.mark.asyncio
async def test_nonzero_exit_can_be_checked_without_changing_legacy_callers() -> None:
    command = [sys.executable, "-c", "import sys; print('partial'); sys.stderr.write('failed'); sys.exit(7)"]
    assert await run_ssh_subprocess(command) == (b"partial\n", b"failed")
    with pytest.raises(subprocess.CalledProcessError) as error:
        await run_ssh_subprocess(command, check=True)
    assert error.value.returncode == 7
    assert error.value.output == b"partial\n"
    assert error.value.stderr == b"failed"


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_timeout_and_cancellation_reap_real_process(
    monkeypatch: pytest.MonkeyPatch, cancel: bool,
) -> None:
    spawn = asyncio.create_subprocess_exec
    started = asyncio.Event()
    processes = []

    async def capture_process(*args, **kwargs):
        process = await spawn(*args, **kwargs)
        processes.append(process)
        started.set()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_process)
    task = asyncio.create_task(run_ssh_subprocess(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        timeout=30 if cancel else 0.1, check=True,
    ))
    await asyncio.wait_for(started.wait(), timeout=5)
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else asyncio.TimeoutError):
        await task
    assert processes[0].returncode is not None
    with pytest.raises(ProcessLookupError):
        os.kill(processes[0].pid, 0)
