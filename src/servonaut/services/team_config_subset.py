"""Build a shareable subset of the local AppConfig for team-config push.

The team-config feature persists a JSON blob on the server. The CLI does NOT
share the entire :class:`AppConfig` — it strips three categories of field
before sending:

* **Credential-bearing**: AI provider API keys, OAuth tokens, cloud-provider
  credentials (GCP service account paths, OVH consumer keys, Hetzner tokens).
* **Operator-personal**: terminal preference, command-history path, demo-mode
  flag, dismissed banners, cache TTLs.
* **Local-filesystem paths**: ``ssh_key`` on custom servers, ``bastion_key``
  on connection profiles. These are reset to ``""`` and the recipient
  re-binds them locally; we surface the count of stripped paths in the push
  warning so the operator knows what's missing on the other side.

The shareable subset is intentionally narrow — connection profiles, scan
rules, the custom servers the operator picks (sanitised), and connection
rules. IP-ban configs are
EXCLUDED because they reference AWS-account-specific resource IDs (IP-set
UUIDs, security-group IDs) that won't exist in another teammate's account.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Collection, Mapping, Sequence, Tuple

if TYPE_CHECKING:
    from servonaut.config.schema import AppConfig


# Marker the sanitiser stamps on the payload so apply-side knows the shape
# came from this version of the contract. Bump when the wire format changes.
SHAREABLE_SUBSET_VERSION = 1


def build_shareable_subset(
    config: "AppConfig", *, custom_servers: Collection[str]
) -> Tuple[dict, dict]:
    """Return ``(payload, summary)`` from a local :class:`AppConfig`.

    Only the custom servers named in ``custom_servers`` go into the payload.
    The caller always says which ones, so no caller shares every server by
    accident; names not in the config are ignored. Connection profiles,
    connection rules and scan rules are sent whole.

    The payload is what gets POSTed to ``/api/v1/teams/{slug}/configs``.
    The summary is a dict the UI can render before push so the operator can
    review what will be shared (counts cover only what is sent):

    .. code-block:: python

        summary = {
            "connection_profiles": 4,
            "connection_rules": 2,
            "scan_rules": 7,
            "custom_servers": 3,
            "stripped_paths": 5,  # bastion_key + custom_server.ssh_key removed
        }
    """
    profiles = [_sanitise_profile(asdict(p)) for p in config.connection_profiles]
    chosen = set(custom_servers)
    servers = [
        _sanitise_custom_server(asdict(s)) for s in config.custom_servers if s.name in chosen
    ]

    stripped = sum(p.pop("_stripped", 0) for p in profiles)
    stripped += sum(s.pop("_stripped", 0) for s in servers)

    payload = {
        "subset_version": SHAREABLE_SUBSET_VERSION,
        "connection_profiles": profiles,
        "connection_rules": [asdict(r) for r in config.connection_rules],
        "scan_rules": [asdict(r) for r in config.scan_rules],
        "custom_servers": servers,
    }
    summary = {
        "connection_profiles": len(profiles),
        "connection_rules": len(payload["connection_rules"]),
        "scan_rules": len(payload["scan_rules"]),
        "custom_servers": len(servers),
        "stripped_paths": stripped,
    }
    return payload, summary


def _sanitise_profile(d: dict) -> dict:
    """Strip ``bastion_key`` (local path). Count stripped paths under ``_stripped``."""
    stripped = 0
    if d.get("bastion_key"):
        d["bastion_key"] = ""
        stripped += 1
    d["_stripped"] = stripped
    return d


def _sanitise_custom_server(d: dict) -> dict:
    """Strip ``ssh_key`` (local path). Count under ``_stripped``."""
    stripped = 0
    if d.get("ssh_key"):
        d["ssh_key"] = ""
        stripped += 1
    d["_stripped"] = stripped
    return d


def diff_against_local(
    local: "AppConfig", remote_payload: dict, *, shared_servers: Sequence[Mapping[str, Any]] = (),
) -> dict:
    """Summarise what would change if ``remote_payload`` were applied over ``local``.

    Returned shape (suitable for an Apply-confirmation modal):

    .. code-block:: python

        {
            "connection_profiles": {"local": 3, "remote": 4, "after": 4},
            "connection_rules":    {"local": 1, "remote": 2, "after": 2},
            "scan_rules":          {"local": 7, "remote": 7, "after": 7},
            "custom_servers":      {"local": 0, "remote": 5, "after": 5},
            "stripped_paths_in_remote": 3,
            "removed": {"connection_profiles": ["old-bastion"], ...},
            "skipped_custom_servers": ["web-1"],
        }

    ``removed`` names the local entries of each section that the team's
    section has no entry of the same name for: they are gone after the pull.
    ``skipped_custom_servers`` names the pulled custom servers that one of
    the team's *shared_servers* also is: the pull does not add them.

    Apply semantics are REPLACE-WHOLE-SECTION — the team's section overwrites
    the local one. Selective-per-item import is deferred to v2 (see the plan
    note for design).
    """
    from servonaut.services.team_config_apply import team_custom_servers

    sections = ("connection_profiles", "connection_rules", "scan_rules", "custom_servers")
    kept_servers, skipped = team_custom_servers(remote_payload, shared_servers)
    diff: dict = {"removed": {}, "skipped_custom_servers": skipped}
    for name in sections:
        local_entries = getattr(local, name, []) or []
        remote_entries = remote_payload.get(name, []) or []
        after = kept_servers if name == "custom_servers" else remote_entries
        diff[name] = {
            "local": len(local_entries),
            "remote": len(remote_entries),
            "after": len(after),  # replace-whole-section
        }
        kept_names = {entry.get("name") for entry in after if isinstance(entry, dict)}
        diff["removed"][name] = [
            entry.name for entry in local_entries if getattr(entry, "name", None) not in kept_names
        ]
    # Re-count stripped paths from the payload so apply-side can mention them
    # ("3 SSH key paths were stripped — re-bind them in Settings after Apply").
    stripped = 0
    for p in remote_payload.get("connection_profiles", []) or []:
        if not (p.get("bastion_key") or "").strip():
            # A blank bastion_key in the payload means the publisher had one
            # locally that got stripped, OR they never had one. We can't
            # distinguish without an explicit marker. Conservative: don't
            # falsely accuse the payload of stripping. Operators see the
            # accurate count from the PUSH-side summary anyway.
            pass
    for s in remote_payload.get("custom_servers", []) or []:
        if not (s.get("ssh_key") or "").strip():
            pass
    diff["stripped_paths_in_remote"] = stripped
    return diff
