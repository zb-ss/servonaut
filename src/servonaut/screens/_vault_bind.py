"""Shared helpers for applying Vault SSH key bindings across screens."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional


async def apply_vault_binding(
    app: Any,
    service: Any,
    instance: dict[str, Any],
    values: Mapping[str, Any],
    *,
    own: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Persist a confirmed ``VaultBindingModal`` result and clear stale leases.

    Raises ``ValueError`` or a vault service exception (including ``HostKeysNeeded``)
    when binding fails or required target details are incomplete.
    """
    server = str(instance.get("id") or "")
    if not server:
        raise ValueError("This server has no usable identifier.")
    host_keys = [key.strip() for key in str(values.get("host_keys") or "").split(",") if key.strip()]
    if values.get("team"):
        result = await service.bind(
            vault_id=values["vault_id"],
            server=server,
            item_id=values["item_id"],
            team=values["team"],
            login=values.get("login"),
            pin_host_key=True,
            host_keys=tuple(host_keys),
            own_rows=[own] if own is not None else [],
        )
    else:
        if not host_keys:
            raise ValueError("Personal-server binding requires verified OpenSSH host keys.")
        from servonaut.services.vault.personal_targets import instance_provider

        custom = instance.get("is_custom") is True
        provider = instance_provider(instance)
        destination, port = service.ssh_destination(instance)
        hostname = str(destination or "")
        login = values.get("login") or instance.get("username")
        if not hostname:
            raise ValueError(
                "This server has no address to connect to, so no vault key can be bound to it."
            )
        if not isinstance(port, int) or isinstance(port, bool) or not isinstance(login, str) or not login:
            raise ValueError("The personal server needs a numeric port and login user.")
        result = await service.bind_personal(
            vault_id=values["vault_id"],
            item_id=values["item_id"],
            provider=provider,
            instance_id=str(instance.get("name") or "") if custom else server,
            hostname=hostname,
            port=port,
            login=login,
            host_keys=host_keys,
        )
        bound = getattr(app, "_personal_vault_bound_ids", None)
        if not isinstance(bound, set):
            bound = set()
            try:
                app._personal_vault_bound_ids = bound
            except Exception:
                pass
        if server:
            bound.add(server)
    leases = getattr(app, "vault_lease_cache", None)
    if leases is not None:
        leases.forget(instance)
        if own is not None:
            leases.forget(own)
    return dict(result) if isinstance(result, Mapping) else {}


def remember_team_vault_binding(
    app: Any,
    target: Mapping[str, Any],
    result: object,
) -> Optional[dict[str, Any]]:
    """Update cached shared-server rows when a team vault key binding succeeds."""
    if not isinstance(result, Mapping):
        return None
    binding = result.get("credential_binding", result)
    if (
        not isinstance(binding, Mapping)
        or binding.get("source") != "servonaut_vault"
        or binding.get("valid") is not True
        or not binding.get("signature")
    ):
        return None
    from servonaut.screens._demo_resolve import replace_instances, team_rows

    saved = dict(binding)
    rows = team_rows(app)
    target_id = (target.get("team_slug"), target.get("id"))
    for row in rows:
        if (row.get("team_slug"), row.get("id")) != target_id:
            continue
        row["credential_binding"] = dict(saved)
        if saved.get("login_user"):
            row["login_user"] = saved["login_user"]
    replace_instances(app, "shared", rows)
    return saved


def format_vault_bind_error(exc: Exception) -> str:
    """Return a concise, safe user-facing reason for a binding error."""
    from servonaut.services.vault.errors import HostKeysNeeded, vault_failure_reason

    if isinstance(exc, HostKeysNeeded):
        return (
            "this machine does not trust a host key for the server yet: use Fetch host key "
            "(or connect to it once) and check its fingerprint, or paste verified host keys"
        )
    if isinstance(exc, ValueError):
        return str(exc)
    return vault_failure_reason(exc)


async def resolve_bw_ssh_key_path(
    app: Any,
    item_id: str,
) -> Optional[str]:
    """Fetch a Bitwarden SSH private key into a persistent key file, or notify & return None."""
    import asyncio
    import logging

    from servonaut.services.bw_resolver import (
        BwCliMissingError,
        BwItemNotFoundError,
        BwItemShapeError,
        BwResolver,
        BwSessionMissingError,
    )
    from servonaut.utils.ephemeral_key import persistent_bw_ssh_key

    bw_session = getattr(app, "bw_session_service", None)
    bw_resolver = BwResolver(
        session_getter=bw_session.session if bw_session is not None else None
    )
    try:
        key_body = await asyncio.to_thread(bw_resolver.resolve_ssh_key, item_id)
    except BwCliMissingError:
        app.notify(
            "Bitwarden CLI (bw) not found. Install it and ensure it is on your PATH.",
            severity="error",
            markup=False,
        )
        return None
    except BwSessionMissingError:
        app.notify(
            "Bitwarden vault is locked. Run 'bw unlock' and export BW_SESSION, then retry.",
            severity="error",
            markup=False,
        )
        return None
    except BwItemNotFoundError:
        app.notify(
            "Bitwarden item not found. Verify the item UUID or re-register via Settings.",
            severity="error",
            markup=False,
        )
        return None
    except BwItemShapeError:
        app.notify(
            "Bitwarden item shape unexpected — ensure it is a native SSH item (BW 2023.10+).",
            severity="error",
            markup=False,
        )
        return None
    except Exception as exc:  # noqa: BLE001
        logging.getLogger(__name__).error("BW key resolution failed: %s", exc, exc_info=True)
        app.notify(
            "Bitwarden key resolution failed. See logs for details.",
            severity="error",
            markup=False,
        )
        return None
    return persistent_bw_ssh_key(key_body)

