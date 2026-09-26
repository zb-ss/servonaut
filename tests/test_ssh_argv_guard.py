"""Every ssh/scp command line is built where the host-key policy applies.

A new place that starts an ``ssh``/``scp`` command, or spells a host-key
option itself, would skip the policy (and the ``off`` compatibility rules),
so this scan fails until the new site is routed through
``servonaut.services.ssh_host_keys`` and listed below.

What it recognises (statically, from the source):

* a list or tuple whose first item is ``ssh``/``scp``/``sftp``, also as an
  absolute path such as ``/usr/bin/ssh`` or ``ssh.exe``;
* the same behind a wrapper (``sshpass``, ``timeout``, ``env``, ``nice``,
  ``nohup``, ``sudo``, ``stdbuf``), and ``rsync -e ssh``;
* a process call (``subprocess.run``/``Popen``/..., ``asyncio``'s
  ``create_subprocess_exec``/``_shell``, ``os.system``/``popen``/``exec*``)
  whose first argument is such a program, or a shell string or f-string
  starting with one.

What it cannot see: a program name taken from a variable or configuration
(``shutil.which``, user settings), command text assembled at run time from
pieces, and SSH libraries used in-process.
"""
from __future__ import annotations

import ast
import posixpath
from pathlib import Path
from typing import Dict, Iterator, Optional, Set, Tuple

SRC = Path(__file__).resolve().parents[1] / "src" / "servonaut"
POLICY_MODULE = "services/ssh_host_keys.py"

# (module, enclosing function) of every place that starts an ssh/scp command.
ALLOWED_SITES: Set[Tuple[str, str]] = {
    ("services/ssh_service.py", "SSHService.build_ssh_command"),
    ("services/scp_service.py", "SCPService._build_base_args"),
    ("services/connection_service.py", "ConnectionService._bastion_proxy_command"),
    ("screens/server_actions.py", "ServerActionsScreen._run_ssh_probe"),
    ("cli/servers.py", "_run_ssh_probe"),
}
SSH_PROGRAMS = {"ssh", "scp", "sftp"}
WRAPPERS = {"sshpass", "timeout", "env", "nice", "nohup", "sudo", "stdbuf"}
PROCESS_CALLS = {
    "run", "Popen", "call", "check_call", "check_output", "getoutput",
    "getstatusoutput", "create_subprocess_exec", "create_subprocess_shell",
    "system", "popen", "execv", "execvp", "execvpe", "execl", "execlp",
    "spawnv", "spawnvp", "spawnl", "spawnlp",
}
HOST_KEY_OPTIONS = (
    "StrictHostKeyChecking", "UserKnownHostsFile", "GlobalKnownHostsFile",
    "HostKeyAlias", "UpdateHostKeys", "KnownHostsCommand",
)


def _program(word: str) -> Optional[str]:
    """The program *word* names (``/usr/bin/ssh``, ``ssh.exe``) if it matters here."""
    name = posixpath.basename(word.replace("\\", "/")).lower()
    name = name[:-4] if name.endswith(".exe") else name
    return name if name in SSH_PROGRAMS | WRAPPERS | {"rsync"} else None


def _starts_with_ssh_program(text: str) -> bool:
    """True for command text such as ``"ssh -o ..."`` or ``"sshpass -p x ssh"``."""
    words = text.split()
    if not words:
        return False
    first = _program(words[0])
    if first in SSH_PROGRAMS:
        return True
    if first in WRAPPERS:
        return any(_program(word) in SSH_PROGRAMS for word in words[1:4])
    if first == "rsync":
        return any(word.startswith(("-e", "--rsh")) for word in words) and "ssh" in text
    return False


def _constant_text(node: ast.AST) -> Optional[str]:
    """The literal text of a string constant, or of an f-string's leading part."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values:
        return _constant_text(node.values[0])
    return None


def _starts_ssh_argv(node: ast.AST) -> bool:
    """A list/tuple that runs ssh/scp, directly or through a wrapper.

    An all-literal list of plain words (a search keyword list, say) cannot
    reach a host and is not an argv; a bare ``['ssh']`` is one being built.
    """
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return False
    texts = [_constant_text(element) for element in node.elts]
    first = _program(texts[0]) if texts[0] is not None else None
    if first in WRAPPERS or first == "rsync":
        return _starts_with_ssh_program(" ".join(t for t in texts if t is not None))
    if first not in SSH_PROGRAMS:
        return False
    return len(texts) == 1 or any(
        not isinstance(element, ast.Constant) or text is None or text.startswith("-")
        for element, text in zip(node.elts[1:], texts[1:])
    )


def _spawns_ssh(node: ast.AST) -> bool:
    """A process call whose program (or shell text) is ssh/scp."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    function = node.func
    name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)
    if name not in PROCESS_CALLS:
        return False
    text = _constant_text(node.args[0])
    return text is not None and _starts_with_ssh_program(text)


def _modules() -> Iterator[Tuple[str, ast.AST]]:
    for path in sorted(SRC.rglob("*.py")):
        yield path.relative_to(SRC).as_posix(), ast.parse(path.read_text(), str(path))


def _functions(tree: ast.AST) -> Iterator[Tuple[str, ast.AST]]:
    """Yield (qualified name, node) for every function, innermost last."""
    def walk(node: ast.AST, prefix: str) -> Iterator[Tuple[str, ast.AST]]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    yield name, child
                yield from walk(child, f"{name}.")
            else:
                yield from walk(child, prefix)
    yield from walk(tree, "")


def _enclosing(tree: ast.AST) -> Dict[int, str]:
    """Map node ids to the innermost function containing them."""
    owner: Dict[int, str] = {}
    for name, function in _functions(tree):
        for node in ast.walk(function):
            owner[id(node)] = name  # inner functions come later and win
    return owner


def _docstrings(tree: ast.AST) -> Set[int]:
    """Ids of docstring nodes, which may describe options freely."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                found.add(id(body[0].value))
    return found


def _ssh_sites(tree: ast.AST) -> Set[Optional[str]]:
    owner = _enclosing(tree)
    return {
        owner.get(id(node)) for node in ast.walk(tree)
        if _starts_ssh_argv(node) or _spawns_ssh(node)
    }


def test_ssh_and_scp_commands_start_only_where_the_policy_applies():
    found = {
        (module, site) for module, tree in _modules() for site in _ssh_sites(tree)
    }
    assert found == ALLOWED_SITES


def test_every_allowed_site_applies_the_policy():
    trees = dict(_modules())
    for module, function_name in ALLOWED_SITES:
        function = dict(_functions(trees[module]))[function_name]
        calls = {
            node.func.attr for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        assert "ssh_options" in calls, f"{module}::{function_name} skips the host-key policy"


def test_host_key_options_are_spelled_only_by_the_policy():
    offenders = []
    for module, tree in _modules():
        if module == POLICY_MODULE:
            continue
        docstrings = _docstrings(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant) and isinstance(node.value, str)
                and id(node) not in docstrings
                and any(f"{option}=" in node.value for option in HOST_KEY_OPTIONS)
            ):
                offenders.append(f"{module}:{node.lineno}")
    assert offenders == []


def _sites_in(source: str) -> Set[Optional[str]]:
    return _ssh_sites(ast.parse(source))


def test_the_guard_notices_new_ways_to_start_ssh():
    snippets = {
        "raw argv": "def f(host):\n    return ['ssh', '-o', 'BatchMode=yes', host]\n",
        "absolute path": "def f(host):\n    return ['/usr/bin/ssh', host]\n",
        "windows exe": "def f(host):\n    return ('ssh.exe', host)\n",
        "scp": "def f(src, dst):\n    return ['scp', src, dst]\n",
        "exec call": (
            "async def f(host):\n"
            "    await asyncio.create_subprocess_exec('ssh', host)\n"
        ),
        "shell string": "def f():\n    subprocess.run('ssh -o BatchMode=yes web-1', shell=True)\n",
        "f-string": "def f(host):\n    os.system(f'scp /tmp/a {host}:/tmp/a')\n",
        "sshpass": "def f(host):\n    return ['sshpass', '-p', 'x', 'ssh', host]\n",
        "timeout": "def f(host):\n    return ['timeout', '5', 'ssh', host]\n",
        "rsync": "def f(src, dst):\n    return ['rsync', '-e', 'ssh -p 2222', src, dst]\n",
    }
    for label, source in snippets.items():
        assert _sites_in(source) == {"f"}, label


def test_the_guard_ignores_plain_text():
    source = (
        "KEYWORDS = ['ssh', 'keys', 'pem']\n"
        "def f():\n"
        "    print('ssh keys are listed below')\n"
        "    return ['timeout', '5', 'curl', 'https://example.com']\n"
    )
    assert _sites_in(source) == set()
