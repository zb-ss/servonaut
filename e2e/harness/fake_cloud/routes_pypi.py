"""Package-index route: the PyPI JSON document the update check reads."""

from __future__ import annotations

from aiohttp import web

from e2e.harness.fake_cloud.state import ScenarioStore

PYPI_JSON_PATH = "/pypi/servonaut/json"


def add_routes(app: web.Application, store: ScenarioStore) -> None:
    """Register the package-index routes on *app*."""

    async def project_json(request: web.Request) -> web.Response:
        version = store.snapshot().pypi_version
        return web.json_response(
            {"info": {"name": "servonaut", "version": version}, "releases": {}}
        )

    app.router.add_get(PYPI_JSON_PATH, project_json)
