"""Journeys: upload a file to S3 and download one in the Object Storage screen.

The user opens AWS Object Storage from the sidebar, sees the buckets, opens
one, uploads a local file under a new folder, then walks into another folder
and downloads an object to ~/Downloads. The bytes must survive both trips.
"""

from __future__ import annotations

import pytest
from rich.text import Text
from textual.widgets import DataTable

from e2e.harness import fleet
from e2e.harness.controls import click_row

pytestmark = [pytest.mark.e2e_pr, pytest.mark.asyncio]

BUCKET = "e2e-assets"
README = b"Seeded by the e2e suite.\n"
REPORT = b"quarterly numbers: 1, 2, 3\n"


def _names(t) -> list[str]:
    """The Name / Key column as shown."""
    table = t.on_screen("#s3_table", DataTable)
    return [Text.from_markup(str(table.get_row(key)[1])).plain for key in table.rows]


async def _click_name(t, name: str) -> None:
    await click_row(t, t.on_screen("#s3_table", DataTable), _names(t).index(name))


def _seed(seed, moto) -> None:
    moto.seed_bucket(BUCKET, {"docs/readme.txt": README})
    moto.seed_bucket("e2e-logs")
    seed.config()
    seed.cache(fleet.cache_rows(), fresh=True)


async def _open_bucket(t) -> None:
    await t.nav("nav_aws_s3")
    await t.wait_for_screen("ObjectStorageScreen")
    await t.wait_until(lambda: _names(t) == [BUCKET, "e2e-logs"], desc="bucket list")
    # A click on a bucket opens it.
    await _click_name(t, BUCKET)
    await t.wait_until(lambda: _names(t) == ["docs/"], desc="bucket contents")


async def test_upload_puts_a_local_file_in_the_bucket(tui, seed, moto):
    _seed(seed, moto)
    outbox = seed.home / "outbox"
    outbox.mkdir()
    (outbox / "report.txt").write_bytes(REPORT)

    async with tui() as t:
        await _open_bucket(t)
        await t.click("#btn_s3_upload")
        await t.wait_until(lambda: t.on_screen("#s3_upload_form").display, desc="upload form")
        await t.fill("#s3_input_upload_path", "~/outbox/report.txt")
        await t.fill("#s3_input_upload_key", "reports/report.txt")
        await t.click("#btn_s3_do_upload")
        await t.wait_for_toast("^Uploaded to 'reports/report.txt'$", severity="information")
        await t.wait_until(lambda: _names(t) == ["docs/", "reports/"], desc="new folder listed")

    assert moto.object_bytes(BUCKET, "reports/report.txt") == REPORT


async def test_download_writes_the_object_to_downloads(tui, seed, moto):
    _seed(seed, moto)
    (seed.home / "Downloads").mkdir()

    async with tui() as t:
        await _open_bucket(t)
        # Into docs/, pick the object, download it.
        await _click_name(t, "docs/")
        await t.wait_until(lambda: _names(t) == ["readme.txt"], desc="folder contents")
        await _click_name(t, "readme.txt")
        await t.click("#btn_s3_download")
        await t.wait_until(lambda: t.on_screen("#s3_download_form").display, desc="download form")
        # The destination starts as ~/Downloads/; the user adds a file name.
        field = t.on_screen("#s3_input_download_path")
        assert field.value == "~/Downloads/"
        await t.click(field)
        await t.press("end")
        await t.type("readme.txt")
        await t.wait_until(lambda: field.value == "~/Downloads/readme.txt", desc="path typed")
        await t.click("#btn_s3_do_download")
        await t.wait_for_toast(
            "^Downloaded to '~/Downloads/readme.txt'$", severity="information"
        )

    assert (seed.home / "Downloads" / "readme.txt").read_bytes() == README
