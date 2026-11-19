"""Package-index routes: the PyPI JSON document and a simple index.

The JSON document is what the update check reads. The simple index (PEP 503)
lets a real pip or pipx install and upgrade Servonaut from wheels a journey
provides: a scenario lists them in ``pypi_files``. Every other project is
unknown, so pip fails on a dependency it cannot find already installed
instead of looking anywhere else.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
from pathlib import Path

from aiohttp import web

from e2e.harness.fake_cloud.state import ScenarioStore

PYPI_JSON_PATH = "/pypi/servonaut/json"
SIMPLE_INDEX_PATH = "/simple/"
FILES_PATH = "/packages/"


def _normalise(name: str) -> str:
    """PEP 503 project-name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add_routes(app: web.Application, store: ScenarioStore) -> None:
    """Register the package-index routes on *app*."""

    def offered() -> list[Path]:
        return [Path(entry) for entry in store.snapshot().pypi_files]

    async def project_json(request: web.Request) -> web.Response:
        scenario = store.snapshot()
        releases: dict[str, list[dict]] = {}
        for path in offered():
            parts = path.name.split("-")
            if parts[0] != "servonaut" or len(parts) < 5:
                continue
            releases.setdefault(parts[1], []).append({
                "filename": path.name,
                "url": f"{request.scheme}://{request.host}{FILES_PATH}{path.name}",
                "size": path.stat().st_size,
                "digests": {"sha256": _sha256(path)},
                "yanked": path.name in scenario.pypi_yanked_files,
            })
        return web.json_response(
            {"info": {"name": "servonaut", "version": scenario.pypi_version}, "releases": releases}
        )

    async def simple_project(request: web.Request) -> web.Response:
        project = _normalise(request.match_info["project"])
        files = [f for f in offered() if _normalise(f.name.split("-", 1)[0]) == project]
        if not files:
            raise web.HTTPNotFound()
        links = "".join(
            f'<a href="{FILES_PATH}{html.escape(f.name)}#sha256={_sha256(f)}">'
            f"{html.escape(f.name)}</a><br>\n"
            for f in files
        )
        page = f"<!DOCTYPE html>\n<html><body>\n{links}</body></html>\n"
        return web.Response(text=page, content_type="text/html")

    async def package_file(request: web.Request) -> web.StreamResponse:
        name = request.match_info["filename"]
        for path in offered():
            if path.name == name:
                delay = store.snapshot().pypi_download_delay
                if delay:
                    await asyncio.sleep(delay)
                return web.FileResponse(path)
        raise web.HTTPNotFound()

    app.router.add_get(PYPI_JSON_PATH, project_json)
    app.router.add_get(SIMPLE_INDEX_PATH + "{project}/", simple_project)
    app.router.add_get(FILES_PATH + "{filename}", package_file)
