"""Every ssh/scp command line is built where the host-key policy applies.

A new place that starts an ``ssh``/``scp`` argv, or spells a host-key
option itself, would skip the policy (and the ``off`` compatibility rules),
so this scan fails until the new site is routed through
``servonaut.services.ssh_host_keys`` and listed below.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Iterator, Optional, Set, Tuple

SRC = Path(__file__).resolve().parents[1] / "src" / "servonaut"
POLICY_MODULE = "services/ssh_host_keys.py"

# (module, enclosing function) of every argv that starts with ssh or scp.
ALLOWED_ARGV_SITES: Set[Tuple[str, str]] = {
    ("services/ssh_service.py", "SSHService.build_ssh_command"),
    ("services/scp_service.py", "SCPService._build_base_args"),
    ("services/connection_service.py", "ConnectionService._bastion_proxy_command"),
    ("screens/server_actions.py", "ServerActionsScreen._run_ssh_probe"),
    ("cli/servers.py", "_run_ssh_probe"),
}
SSH_PROGRAMS = {"ssh", "scp", "sftp"}
HOST_KEY_OPTIONS = (
    "StrictHostKeyChecking", "UserKnownHostsFile", "GlobalKnownHostsFile",
    "HostKeyAlias", "UpdateHostKeys", "KnownHostsCommand",
)


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


def _starts_ssh_argv(node: ast.AST) -> bool:
    """A list/tuple starting with ssh or scp: alone, or with an option or a value.

    An all-literal list of plain words (a search keyword list, say) cannot
    reach a host and is not an argv.
    """
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return False
    first = node.elts[0]
    if not (isinstance(first, ast.Constant) and first.value in SSH_PROGRAMS):
        return False
    rest = node.elts[1:]
    return not rest or any(  # a bare ['ssh'] is an argv being assembled
        not isinstance(element, ast.Constant)
        or (isinstance(element.value, str) and element.value.startswith("-"))
        for element in rest
    )


def _docstrings(tree: ast.AST) -> Set[int]:
    """Ids of docstring nodes, which may describe options freely."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                found.add(id(body[0].value))
    return found


def _argv_sites() -> Set[Tuple[str, Optional[str]]]:
    sites = set()
    for module, tree in _modules():
        owner = _enclosing(tree)
        for node in ast.walk(tree):
            if _starts_ssh_argv(node):
                sites.add((module, owner.get(id(node))))
    return sites


def test_ssh_and_scp_argv_are_built_only_where_the_policy_applies():
    assert _argv_sites() == ALLOWED_ARGV_SITES


def test_every_allowed_site_applies_the_policy():
    trees = dict(_modules())
    for module, function_name in ALLOWED_ARGV_SITES:
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
            ):
                text = node.value
                if any(f"{option}=" in text for option in HOST_KEY_OPTIONS):
                    offenders.append(f"{module}:{node.lineno}")
    assert offenders == []


def test_the_guard_notices_a_new_raw_argv():
    tree = ast.parse("def connect(host):\n    return ['ssh', '-o', 'BatchMode=yes', host]\n")
    owner = _enclosing(tree)
    found = {owner[id(n)] for n in ast.walk(tree) if _starts_ssh_argv(n)}
    assert found == {"connect"}
