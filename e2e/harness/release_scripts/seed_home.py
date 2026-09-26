"""Write a home the way an installed Servonaut release writes it.

Run with the Python of an install, not imported by the suite::

    <venv>/bin/python seed_home.py <spec.json>

The spec (built by the journey from the neutral inventory) says what the user
has: settings (top-level and per section, such as ``ai_provider``), custom
servers, connection profiles, the instance cache, scan results and command
history. Only the installed release's own classes write
the files, so the home holds exactly what that release saves, in its format.
Fields a release does not know are skipped and reported. Prints a JSON
summary on stdout.

Standard library and the installed ``servonaut`` only. It sits in a directory
of its own because Python puts the script's directory first on ``sys.path``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import fields
from typing import Any


def _known(cls: type, values: dict[str, Any], skipped: list[str], label: str) -> dict[str, Any]:
    names = {f.name for f in fields(cls)}
    for name in sorted(set(values) - names):
        skipped.append(f"{label}.{name}")
    return {name: value for name, value in values.items() if name in names}


def _build_config(spec: dict[str, Any], skipped: list[str]) -> Any:
    from servonaut.config import schema

    config = schema.AppConfig()
    settings = _known(schema.AppConfig, spec.get("settings", {}), skipped, "settings")
    for name, value in settings.items():
        setattr(config, name, value)
    config.custom_servers = [
        schema.CustomServer(**_known(schema.CustomServer, server, skipped, "custom_server"))
        for server in spec.get("custom_servers", [])
    ]
    config.connection_profiles = [
        schema.ConnectionProfile(**_known(schema.ConnectionProfile, profile, skipped, "profile"))
        for profile in spec.get("connection_profiles", [])
    ]
    for section, values in spec.get("sections", {}).items():
        target = getattr(config, section, None)
        if target is None:
            skipped.append(section)
            continue
        for name, value in values.items():
            if hasattr(target, name):
                setattr(target, name, value)
            else:
                skipped.append(f"{section}.{name}")
    return config


def main(spec_path: str) -> int:
    with open(spec_path, encoding="utf-8") as handle:
        spec = json.load(handle)

    from importlib.metadata import version

    from servonaut.config.manager import ConfigManager
    from servonaut.config.schema import CONFIG_VERSION
    from servonaut.services.cache_service import CacheService
    from servonaut.services.command_history import CommandHistoryService
    from servonaut.services.keyword_store import KeywordStore

    skipped: list[str] = []
    config = _build_config(spec, skipped)
    ConfigManager().save(config)

    CacheService(ttl_seconds=config.cache_ttl_seconds).save(spec.get("fleet", []))
    keywords = KeywordStore(config.keyword_store_path)
    for server_id, results in spec.get("scan_results", {}).items():
        keywords.save_results(server_id, results)
    history = CommandHistoryService(config.command_history_path)
    for server_id, command in spec.get("history", []):
        history.add_to_history(server_id, command)
    for name, command in spec.get("saved_commands", []):
        history.save_command(name, command)

    print(
        json.dumps(
            {
                "version": version("servonaut"),
                "config_version": CONFIG_VERSION,
                "skipped": skipped,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
