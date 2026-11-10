"""Cancelling one provider's listing, and what a listing reports while it runs."""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.accounts import AccountRef
from servonaut.screens._fleet_load import FleetLoad, Phase, render_load
from servonaut.services.accounts.fleet import AccountBinding, AccountFleet
from servonaut.services.aws_service import AWSService
from servonaut.services.cache_service import CacheService
from servonaut.services.load_progress import LoadProgress
from servonaut.widgets.fleet_skeleton import FOOTNOTE, SHORT_FOOTNOTE, skeleton_lines

CACHED = [{"id": "i-0123456789abcdef0", "name": "web-1", "region": "us-east-1"}]


async def _until(condition: Callable[[], bool]) -> None:
    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), timeout=10)


def _boto3(*regions: str) -> MagicMock:
    boto3 = MagicMock()
    boto3.client.return_value.describe_regions.return_value = {
        "Regions": [{"RegionName": name} for name in regions],
    }
    return boto3


def _service(cache_rows=CACHED) -> tuple[AWSService, MagicMock]:
    cache = MagicMock(spec=CacheService)
    cache.load.return_value = None
    cache.load_any.return_value = cache_rows
    return AWSService(cache), cache


class _Regions:
    """A fake region listing whose first region waits until the test lets it go."""

    def __init__(self) -> None:
        self.hold = threading.Event()
        self.started = threading.Semaphore(0)
        self.listed: list[tuple[str, str]] = []

    def __call__(self, region: str) -> list:
        self.listed.append((threading.current_thread().name, region))
        if region == "us-east-1":
            self.started.release()
            self.hold.wait(timeout=10)
        return [{"id": f"i-{region}", "name": region}]

    async def first_region_open(self, count: int = 1) -> None:
        for _ in range(count):
            await _until(lambda: self.started.acquire(blocking=False))


REGIONS = ("us-east-1", "eu-west-1", "ap-south-1")


@pytest.mark.asyncio
async def test_a_cancelled_aws_listing_leaves_the_cache_alone_and_stops_listing() -> None:
    service, cache = _service()
    regions = _Regions()
    pool = ThreadPoolExecutor(max_workers=2)
    asyncio.get_running_loop().set_default_executor(pool)
    with patch("servonaut.services.aws_service.boto3", _boto3(*REGIONS)), \
            patch.object(service, "_fetch_region", regions):
        task = asyncio.create_task(service.fetch_instances_cached(force_refresh=True))
        await regions.first_region_open()
        assert service.listing_region == "us-east-1"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert service.listing_region == ""  # nothing is being listed any more
        regions.hold.set()
        pool.shutdown(wait=True)

    assert [region for _thread, region in regions.listed] == ["us-east-1"]
    cache.save.assert_not_called()


@pytest.mark.asyncio
async def test_cancelling_one_listing_does_not_cut_another_listing_short() -> None:
    service, cache = _service(cache_rows=[{"id": f"i-{r}"} for r in REGIONS])
    regions = _Regions()
    pool = ThreadPoolExecutor(max_workers=4)
    asyncio.get_running_loop().set_default_executor(pool)
    with patch("servonaut.services.aws_service.boto3", _boto3(*REGIONS)), \
            patch.object(service, "_fetch_region", regions):
        cancelled = asyncio.create_task(service.fetch_instances_cached(force_refresh=True))
        survivor = asyncio.create_task(service.fetch_instances_cached(force_refresh=True))
        await regions.first_region_open(2)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        regions.hold.set()
        rows = await survivor
        pool.shutdown(wait=True)

    assert [row["id"] for row in rows] == [f"i-{r}" for r in REGIONS]
    cache.save.assert_called_once()
    assert [row["id"] for row in cache.save.call_args.args[0]] == [f"i-{r}" for r in REGIONS]


@pytest.mark.asyncio
async def test_a_new_listing_does_not_revive_the_cancelled_one() -> None:
    service, cache = _service()
    regions = _Regions()
    pool = ThreadPoolExecutor(max_workers=4)
    asyncio.get_running_loop().set_default_executor(pool)
    with patch("servonaut.services.aws_service.boto3", _boto3(*REGIONS)), \
            patch.object(service, "_fetch_region", regions):
        old = asyncio.create_task(service.fetch_instances_cached(force_refresh=True))
        await regions.first_region_open()
        old.cancel()
        with pytest.raises(asyncio.CancelledError):
            await old
        new = asyncio.create_task(service.fetch_instances_cached(force_refresh=True))
        await regions.first_region_open()
        regions.hold.set()
        rows = await new
        pool.shutdown(wait=True)

    assert len(rows) == 3
    threads = {thread for thread, _region in regions.listed}
    per_thread = {t: [r for th, r in regions.listed if th == t] for t in threads}
    assert sorted(len(v) for v in per_thread.values()) == [1, 3]  # the old one stopped
    cache.save.assert_called_once()


def _account(label: str, gate: asyncio.Event, region: str) -> AccountBinding:
    service = SimpleNamespace(
        listing_region=region, last_fetch_error=None, last_fetch_partial=False,
    )

    async def fetch(force_refresh: bool = False) -> list:
        del force_refresh
        await gate.wait()
        service.listing_region = ""
        return [{"id": label, "name": label}]

    service.fetch_instances_cached = fetch
    return AccountBinding(AccountRef("aws", label, label == "main"), service)


@pytest.mark.asyncio
async def test_a_fleet_reports_the_account_and_region_being_listed() -> None:
    gates = {"main": asyncio.Event(), "spare": asyncio.Event()}
    fleet = AccountFleet("aws", [
        _account("main", gates["main"], "us-east-1"),
        _account("spare", gates["spare"], "eu-west-1"),
    ])
    task = asyncio.create_task(fleet.fetch_instances_cached(force_refresh=True))
    await _until(lambda: not fleet._answered and fleet.load_progress.region == "us-east-1")
    assert fleet.load_progress == LoadProgress(1, 2, "us-east-1")

    gates["main"].set()
    await _until(lambda: fleet.load_progress.account == 2)
    assert fleet.load_progress == LoadProgress(2, 2, "eu-west-1")

    gates["spare"].set()
    await task
    assert fleet.load_progress.account == fleet.load_progress.accounts == 2


@pytest.mark.asyncio
async def test_cancelling_a_fleet_cancels_every_account_and_raises() -> None:
    gates = {"main": asyncio.Event(), "spare": asyncio.Event()}
    fleet = AccountFleet("aws", [
        _account("main", gates["main"], "a"), _account("spare", gates["spare"], "b"),
    ])
    task = asyncio.create_task(fleet.fetch_instances_cached(force_refresh=True))
    await _until(lambda: fleet.load_progress.region == "a")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert fleet.last_fetch_error is None  # a cancel is not a failure


def _tracker(*keys: str) -> FleetLoad:
    load = FleetLoad()
    for key in keys:
        load.start(key, accounts=2 if key == "aws" else 1, has_rows=False)
    return load


def test_the_loading_lines_say_how_to_stop() -> None:
    assert "esc stop" in render_load(_tracker("aws")).plain.splitlines()[0]
    refresh = FleetLoad()
    refresh.start("aws", has_rows=True)
    assert render_load(refresh).plain.endswith("esc stop")
    refresh.finish("aws", count=1)
    assert render_load(refresh) is None  # nothing left to stop, nothing to say


def test_progress_changes_what_a_loading_line_says() -> None:
    load = _tracker("aws")
    assert "◐ AWS · 2 accounts" in render_load(load).plain
    assert load.note_progress("aws", LoadProgress(1, 2, "us-east-1")) is True
    assert "◐ AWS · account 1 of 2 · us-east-1" in render_load(load).plain
    assert load.note_progress("aws", LoadProgress(1, 2, "us-east-1")) is False  # nothing new


def test_a_single_account_names_only_its_region() -> None:
    load = FleetLoad()
    load.start("aws", accounts=1, has_rows=False)
    load.note_progress("aws", LoadProgress(1, 1, "eu-west-1"))
    assert "◐ AWS · eu-west-1" in render_load(load).plain


def test_the_spinner_frame_changes_the_glyph() -> None:
    load = _tracker("hetzner")
    first = render_load(load).plain.splitlines()[1][0]
    load.frame += 1
    assert render_load(load).plain.splitlines()[1][0] != first


def test_a_cancelled_provider_ends_the_cycle_and_keeps_a_note() -> None:
    load = _tracker("aws", "ovh")
    load.finish("ovh", count=2)
    load.cancel("aws", count=0)
    assert not load.active and not load.problems  # the user's choice is no failure
    assert render_load(load).plain == "○ AWS · cancelled"


def test_a_cancelled_provider_with_cached_rows_is_stale() -> None:
    load = FleetLoad()
    load.start("aws", has_rows=True)
    load.cancel("aws", count=3)
    assert render_load(load).plain == "⚠ AWS · stale: cancelled, showing 3 servers from the cache"


def test_cancelling_a_provider_that_answered_changes_nothing() -> None:
    load = _tracker("aws", "ovh")
    load.finish("ovh", count=2)
    load.cancel("ovh", count=2)
    assert load.providers["ovh"].phase is Phase.DONE


def test_the_refresh_pill_turns_and_counts_a_cancelled_provider_as_stale() -> None:
    load = FleetLoad()
    load.start("aws", has_rows=True, cached_age="6 min ago")
    load.start("ovh", has_rows=True, cached_age="6 min ago")
    load.cancel("aws", count=3)
    assert render_load(load).plain.startswith("◐ Refreshing · AWS stale · OVH …")
    load.frame = 1
    assert render_load(load).plain.startswith("◓ Refreshing")


def test_the_skeleton_draws_a_few_rows_then_the_footnote() -> None:
    lines = skeleton_lines(90, 30)
    assert len(lines) == 7  # six placeholder rows and the footnote
    assert lines[-1].plain == FOOTNOTE
    assert len(skeleton_lines(90, 4)) == 4  # a short area is filled to its height
    assert all(set(line.plain) <= {"▬", " "} for line in lines[:-1])


def test_the_skeleton_never_draws_wider_than_its_area() -> None:
    assert all(len(line.plain) <= 20 for line in skeleton_lines(20, 5, footnote=""))


def test_a_skeleton_too_short_for_the_footnote_shows_rows_only() -> None:
    assert skeleton_lines(30, 2) and all("Esc" not in line.plain for line in skeleton_lines(30, 2))


def test_a_narrow_skeleton_uses_the_short_footnote_on_one_line() -> None:
    lines = skeleton_lines(60, 3)
    assert len(lines) == 3 and lines[-1].plain == SHORT_FOOTNOTE
