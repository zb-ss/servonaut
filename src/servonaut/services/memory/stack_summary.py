"""Stack-summary projection over stored server-memory modules.

Feeds the proactive-monitoring recon phase (scan step 0): a compact,
deterministic JSON object describing what is ON the box, so the server
can select and parameterize detectors without shipping the full memory
payload every scan. Pure functions over the module dicts returned by
``MemoryService.get_all_modules`` — no store access, no IO.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Database engines projected from the databases module, in report order.
_DB_ENGINES = ("mysql", "mariadb", "postgres", "redis", "mongodb")

#: Cap on the projected enabled-units list — recon needs the shape of the
#: stack, not a full inventory (the full list stays in the services module).
_MAX_SERVICES = 40


def _observed(modules: Dict[str, Any], name: str) -> Dict[str, Any]:
    mod = modules.get(name) or {}
    obs = mod.get("observed")
    return obs if isinstance(obs, dict) else {}


def build_stack_summary(
    modules: Dict[str, Any],
    *,
    provider: str = "custom",
) -> Dict[str, Any]:
    """Project stored memory modules into the recon stack summary.

    Shape (proactive-monitoring recon contract):
    ``{os, cloud_provider, docker: {present, container_count},
    databases: [{engine, version}], web: {server, vhosts_count,
    access_log_paths}, services: [units], log_paths: [paths]}``
    """
    os_obs = _observed(modules, "os")
    containers = _observed(modules, "containers")
    databases_obs = _observed(modules, "databases")
    web_obs = _observed(modules, "web_stack")
    logs_obs = _observed(modules, "logs")
    services_obs = _observed(modules, "services")

    docker_containers = containers.get("docker_containers") or []
    if not isinstance(docker_containers, list):
        docker_containers = []

    databases: List[Dict[str, str]] = []
    for engine in _DB_ENGINES:
        version = databases_obs.get(f"{engine}_version")
        if version:
            databases.append({"engine": engine, "version": str(version)})

    web_server: Optional[str] = None
    if web_obs.get("nginx"):
        web_server = "nginx"
    elif web_obs.get("apache"):
        web_server = "apache"

    vhosts = 0
    for key in ("nginx_sites_enabled", "apache_sites_enabled"):
        sites = web_obs.get(key)
        if isinstance(sites, list):
            vhosts += len(sites)

    log_paths = logs_obs.get("probed_paths") or []
    if not isinstance(log_paths, list):
        log_paths = []
    access_log_paths = [
        str(p) for p in log_paths if "access" in str(p).lower()
    ]

    units = services_obs.get("enabled_units") or []
    if not isinstance(units, list):
        units = []

    return {
        "os": os_obs.get("pretty_name") or os_obs.get("id"),
        "cloud_provider": provider,
        "docker": {
            "present": bool(
                containers.get("docker_running") or docker_containers
            ),
            "container_count": len(docker_containers),
        },
        "databases": databases,
        "web": {
            "server": web_server,
            "vhosts_count": vhosts,
            "access_log_paths": access_log_paths,
        },
        "services": [str(u) for u in units[:_MAX_SERVICES]],
        # Additive beyond the asked shape: the full probed log paths let
        # recon parameterize journal/auth/web log detectors directly.
        "log_paths": [str(p) for p in log_paths],
        "modules_present": sorted(modules.keys()),
    }
