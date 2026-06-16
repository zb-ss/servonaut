"""Home-relative path normalisation for portable config files.

User-entered SSH key paths (``default_key``, ``custom_servers[].ssh_key`` …)
are stored as whatever string the user typed or a file-picker handed back —
typically a machine-specific absolute path like ``/home/<user>/.ssh/id_rsa``.
That makes ``config.json`` non-portable: a different username, a different OS,
or a teammate's machine all resolve that path to something that doesn't exist.

The fix is symmetric:

* On **save**, :func:`tildify` collapses any absolute path that lives under the
  current user's home directory back to a ``~/…`` literal (with forward
  slashes, so a Windows-authored config stays readable on macOS/Linux).
* On **read**, every consumption site already calls ``os.path.expanduser`` /
  ``Path.expanduser``, which expands ``~`` per-OS — ``$HOME`` on POSIX,
  ``%USERPROFILE%`` on Windows. Nothing to change there.

Paths *outside* the home directory (``/etc/ssh/keys/foo``, ``D:\\keys\\foo``)
are genuinely machine-specific and are left untouched. Distributing the key
*files* themselves across machines/teams is a separate concern handled by the
secrets layer, not by path rewriting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


# Prefixes that already denote a portable / indirected value and must never be
# rewritten: ``~`` (already home-relative), ``$VAR`` (env-var indirection), and
# ``file:`` (secret-store reference resolved elsewhere).
_NON_FS_PREFIXES = ("~", "$", "file:")


def tildify(path: str) -> str:
    """Collapse a home-prefixed absolute path to a ``~/…`` literal.

    Returns *path* unchanged when it is empty, already portable (starts with
    ``~``/``$``/``file:``), or points outside the current user's home
    directory. Otherwise returns the home-relative form using forward slashes.

    Examples (with ``$HOME`` = ``/home/<user>``)::

        tildify("/home/<user>/.ssh/id_rsa")  -> "~/.ssh/id_rsa"
        tildify("~/.ssh/id_rsa")            -> "~/.ssh/id_rsa"   # unchanged
        tildify("/etc/ssh/keys/foo")        -> "/etc/ssh/keys/foo"  # outside home
        tildify("$HOME/.ssh/id_rsa")        -> "$HOME/.ssh/id_rsa"  # unchanged
        tildify("")                         -> ""
    """
    if not path or path.startswith(_NON_FS_PREFIXES):
        return path
    try:
        home = Path.home()
        # Resolve only ``~`` (already excluded above) — do NOT call resolve(),
        # which would follow symlinks and dereference relative segments,
        # changing the stored value in surprising ways.
        candidate = Path(path)
        relative = candidate.relative_to(home)
    except (ValueError, OSError):
        # ValueError: not under home. OSError: home is unresolvable. Either
        # way the original string is the safe thing to keep.
        return path
    # ``as_posix`` guarantees forward slashes so a Windows-authored config
    # ("~/.ssh/id_rsa", not "~\\.ssh\\id_rsa") round-trips on POSIX too.
    rel = relative.as_posix()
    return "~" if rel == "." else f"~/{rel}"


def normalize_config_paths(data: Dict[str, Any]) -> Dict[str, Any]:
    """Tildify every user-entered path field in a serialised config dict.

    Mutates and returns *data* (already the product of ``dataclasses.asdict``).
    Only fields that hold a **local filesystem path the user supplies** are
    touched. App-managed ``*_path`` fields already default to ``~/…`` literals
    and Hetzner/OVH *remote* key identifiers (``default_hetzner_ssh_key``) are
    deliberately excluded — they are not local paths.
    """
    if not isinstance(data, dict):
        return data

    # Top-level scalar key path.
    if isinstance(data.get("default_key"), str):
        data["default_key"] = tildify(data["default_key"])

    # Per-instance key map: {instance_id: key_path}.
    instance_keys = data.get("instance_keys")
    if isinstance(instance_keys, dict):
        data["instance_keys"] = {
            k: tildify(v) if isinstance(v, str) else v
            for k, v in instance_keys.items()
        }

    # Connection profiles: bastion key path.
    for profile in data.get("connection_profiles", []) or []:
        if isinstance(profile, dict) and isinstance(profile.get("bastion_key"), str):
            profile["bastion_key"] = tildify(profile["bastion_key"])

    # Custom servers: ssh_key path.
    for server in data.get("custom_servers", []) or []:
        if isinstance(server, dict) and isinstance(server.get("ssh_key"), str):
            server["ssh_key"] = tildify(server["ssh_key"])

    # Provider-level local key paths. ``default_hetzner_ssh_key`` is a
    # Hetzner-side identifier (NOT a local path) and is intentionally skipped.
    hetzner = data.get("hetzner")
    if isinstance(hetzner, dict) and isinstance(hetzner.get("default_local_ssh_key"), str):
        hetzner["default_local_ssh_key"] = tildify(hetzner["default_local_ssh_key"])

    ovh = data.get("ovh")
    if isinstance(ovh, dict) and isinstance(ovh.get("default_ssh_key"), str):
        ovh["default_ssh_key"] = tildify(ovh["default_ssh_key"])

    return data
