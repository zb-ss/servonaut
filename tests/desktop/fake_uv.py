"""Stand-in for the bundled ``uv`` executable in managed voice runtime tests.

The tests start this program through a small wrapper script that sets
``FAKE_UV_CONTROL`` to a control directory, because the runtime manager hands
its children a scrubbed environment. The control directory holds:

- ``config.json``: ``{"src": <servonaut source dir>, "paths": [<import dirs>]}``
- ``behavior.json`` (optional): per-command misbehaviour, see ``_misbehave``
- ``engines/``: stub engine modules made importable by the requirements step

Every invocation appends ``{"command", "argv", "env"}`` to ``calls.jsonl`` and
touches ``started-<command>``. No network access happens.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import venv
from pathlib import Path

CONTROL = Path(os.environ["FAKE_UV_CONTROL"])


def main(argv: list[str]) -> int:
    command = _command(argv)
    _record(command, argv)
    behavior = _load("behavior.json")
    action = behavior.get(command)
    if action is not None:
        return _misbehave(action)
    handler = {
        "python-install": _python_install,
        "venv": _venv,
        "pip-requirements": _pip_requirements,
        "pip-wheel": _pip_wheel,
    }[command]
    return handler(argv, behavior)


def _command(argv: list[str]) -> str:
    if argv[:2] == ["python", "install"]:
        return "python-install"
    if argv[:1] == ["venv"]:
        return "venv"
    if argv[:2] == ["pip", "install"]:
        return "pip-requirements" if "-r" in argv else "pip-wheel"
    raise SystemExit(f"fake uv: unexpected arguments {argv}")


def _record(command: str, argv: list[str]) -> None:
    env = {key: value for key, value in os.environ.items() if key != "FAKE_UV_CONTROL"}
    with (CONTROL / "calls.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"command": command, "argv": argv, "env": env}) + "\n")
    (CONTROL / f"started-{command}").write_text(str(os.getpid()), encoding="utf-8")


def _load(name: str) -> dict:
    path = CONTROL / name
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _misbehave(action: str) -> int:
    """Simulate a failing, hanging or silently stalled uv command.

    ``fail``        exit 2 with an error message.
    ``hang``        print progress forever (never stalls, only times out).
    ``hang-silent`` sleep forever without output or file changes.
    Both hangs first start a grandchild so tests can prove the tree is killed.
    """
    if action == "fail":
        print("error: simulated uv failure", file=sys.stderr)
        return 2
    grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    (CONTROL / "grandchild.pid").write_text(str(grandchild.pid), encoding="utf-8")
    (CONTROL / "uv.pid").write_text(str(os.getpid()), encoding="utf-8")
    while True:
        if action == "hang":
            print("still working", file=sys.stderr, flush=True)
        time.sleep(0.2)


def _python_install(argv: list[str], behavior: dict) -> int:
    install_dir = Path(os.environ["UV_PYTHON_INSTALL_DIR"])
    target = install_dir / f"cpython-{argv[2]}-fake"
    target.mkdir(parents=True, exist_ok=True)
    (target / "installed").write_text(argv[2], encoding="utf-8")
    print(f"Installed Python {argv[2]}", file=sys.stderr)
    return 0


def _venv(argv: list[str], behavior: dict) -> int:
    venv.EnvBuilder(with_pip=False, symlinks=os.name != "nt").create(argv[-1])
    return 0


def _pip_requirements(argv: list[str], behavior: dict) -> int:
    for flag in ("--require-hashes", "--no-deps"):
        assert flag in argv, flag
    assert argv[argv.index("--only-binary") + 1] == ":all:"
    if behavior.get("tamper-staged-wheel"):
        for wheel in Path(argv[argv.index("-r") + 1]).parent.glob("*.whl"):
            with wheel.open("ab") as handle:
                handle.write(b"tampered")
    _write_pth(argv, "00-fake-voice-engines.pth", [str(CONTROL / "engines")])
    return 0


def _pip_wheel(argv: list[str], behavior: dict) -> int:
    assert "--no-deps" in argv
    if behavior.get("empty-wheel"):
        return 0
    config = _load("config.json")
    _write_pth(argv, "10-fake-servonaut.pth", [config["src"], *config["paths"]])
    return 0


def _write_pth(argv: list[str], name: str, lines: list[str]) -> None:
    python = argv[argv.index("--python") + 1]
    purelib = subprocess.run(
        [python, "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    Path(purelib, name).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
