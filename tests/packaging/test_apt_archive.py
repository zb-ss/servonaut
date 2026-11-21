"""Secretless APT publication and release-source contract tests."""

from __future__ import annotations

import importlib
import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.packaging.apt.fixtures import NOW, ROOT, SETTINGS, FixtureStore, plain_fixture_indexes, sample
from apt_archive import (
    INVENTORY, ArchiveError, Change, Input, Inventory, Publisher, Signer, audit, build_indexes,
    inrelease, sha256,
)

entrypoint = importlib.import_module("apt-publish")


@pytest.fixture
def archive(tmp_path):
    store = FixtureStore()
    releases = []
    now = [NOW]

    def select(inventory):
        packages = sorted(releases, key=lambda item: entrypoint.version_order(item.package.tag), reverse=True)
        eligible = [item for item in packages if not inventory.blocked(item.package)]
        stable = [item for item in eligible if "~" not in item.package.version][:SETTINGS.finals]
        candidate = [item for item in eligible if "~" in item.package.version][:SETTINGS.candidates]
        return {"stable": stable, "candidate": stable + candidate}

    publisher = Publisher(
        store, store, SETTINGS, tmp_path, select, plain_fixture_indexes,
        lambda plain: plain, lambda signed: signed, lambda: now[0],
        knows_release=lambda change: any(
            (item.package.tag, item.package.sha256) == (change.tag, change.digest) for item in releases
        ),
    )
    return store, releases, now, publisher


def indexes(store):
    return [key for key in store.objects if "/by-hash/" in key]


def test_puts_both_suites_last_and_retains_immutable_hashes(tmp_path, archive):
    store, releases, _, publisher = archive
    stable = sample(tmp_path, "v2.0.0")
    rc = sample(tmp_path, "v2.1.0rc4")
    releases.extend((stable, rc))
    publisher.publish()
    keys = [key for action, key in store.events if action == "put" and key != INVENTORY]
    first_hash = next(index for index, key in enumerate(keys) if "/by-hash/" in key)
    first_name = next(index for index, key in enumerate(keys) if key.endswith("/Packages"))
    assert set(keys[:first_hash]) == {stable.package.key, rc.package.key}
    assert all("/by-hash/" in key for key in keys[first_hash:first_name])
    assert keys[-2:] == [inrelease("stable"), inrelease("candidate")]
    original = {key: store.read(key) for key in indexes(store)}
    releases.append(sample(tmp_path, "v2.1.0"))
    publisher.publish()
    assert all(store.read(key) == body for key, body in original.items())
    assert store.read(rc.package.key) == rc.path.read_bytes()


def test_conflicting_pool_bytes_fail_before_publishing(tmp_path, archive):
    store, releases, _, publisher = archive
    selected = sample(tmp_path, "v2.0.0")
    releases.append(selected)
    store.put(selected.package.key, b"unexpected bytes", etag=None)
    with pytest.raises(ArchiveError, match="Immutable archive object differs"):
        publisher.publish()
    assert store.get(inrelease("stable")) is None
    assert store.get(inrelease("candidate")) is None


def test_uses_newest_inventory_after_a_conditional_conflict(tmp_path, archive):
    store, releases, _, publisher = archive
    stable = sample(tmp_path, "v2.0.0")
    releases.append(stable)
    publisher.publish()
    selections = []
    original = publisher.select

    def select(inventory):
        selections.append(list(releases))
        return original(inventory)

    publisher.select = select

    def concurrent_change(key, body):
        if key != INVENTORY:
            return
        store.before_put = None
        update = Inventory(store.read(INVENTORY))
        update.raw["started"] += 1
        store.put(INVENTORY, update.encode(), etag=store.get(INVENTORY).etag)
        releases.append(sample(tmp_path, "v2.1.0"))

    store.before_put = concurrent_change
    publisher.publish()
    assert len(selections) == 2 and len(selections[1]) > len(selections[0])
    assert len(Inventory(store.read(INVENTORY)).raw["desired"]["stable"]) == 2


def test_withdrawal_conflict_cannot_republish_the_stale_choice(tmp_path, archive):
    store, releases, _, publisher = archive
    stable = sample(tmp_path, "v2.0.0")
    next_release = sample(tmp_path, "v2.1.0")
    releases.append(stable)
    publisher.publish()
    releases.append(next_release)

    def withdraw_before_reservation(key, body):
        if key != INVENTORY:
            return
        store.before_put = None
        publisher.publish(Change("withdraw", next_release.package.tag, next_release.package.sha256))

    store.before_put = withdraw_before_reservation
    publisher.publish()
    assert store.denied(next_release.package.key)
    assert Inventory(store.read(INVENTORY)).raw["desired"]["stable"] == [stable.package.key]
    assert not any(action == "put" and key == next_release.package.key for action, key in store.events)


def test_retried_pointer_replace_prepares_a_fresh_snapshot(tmp_path, archive):
    store, releases, _, publisher = archive
    releases.append(sample(tmp_path, "v2.0.0"))
    publisher.publish()
    old = store.get(inrelease("stable")).etag
    refreshed = []

    def change_pointer(key, body):
        if key != inrelease("stable"):
            return
        store.before_put = None
        store.put(key, body.replace(b"X-Servonaut-Snapshot: ", b"X-Servonaut-Snapshot: fixture-"), etag=old)
        refreshed.append(store.get(key).etag)

    store.before_put = change_pointer
    publisher.publish()
    assert len(refreshed) == 1
    assert store.get(inrelease("stable")).etag != refreshed[0]
    audit(store, Inventory(store.read(INVENTORY)), publisher.verify, settings=SETTINGS, now=NOW)


def test_failure_between_suites_preserves_old_by_hash_for_retry(tmp_path, archive):
    store, releases, now, publisher = archive
    first = sample(tmp_path, "v2.0.0")
    releases.append(first)
    publisher.publish()
    old_candidate = store.read(inrelease("candidate"))
    old_refs = {key: store.read(key) for key in indexes(store)}
    releases.append(sample(tmp_path, "v2.1.0"))

    def lose_write(key, body):
        if key == inrelease("candidate"):
            raise OSError("fixture lost the candidate pointer write")

    store.before_put = lose_write
    with pytest.raises(OSError):
        publisher.publish()
    assert store.read(inrelease("candidate")) == old_candidate
    assert all(store.read(key) == body for key, body in old_refs.items())
    state = Inventory(store.read(INVENTORY))
    audit(store, state, publisher.verify, settings=SETTINGS, now=NOW)
    now[0] += SETTINGS.split_grace
    with pytest.raises(ArchiveError, match="differ from the current"):
        audit(store, state, publisher.verify, settings=SETTINGS, now=now[0])
    store.before_put = None
    publisher.publish()
    assert store.read(inrelease("candidate")) != old_candidate
    assert all(store.read(key) == body for key, body in old_refs.items())


def test_retention_outlives_the_last_signed_snapshot(tmp_path, archive):
    store, releases, now, publisher = archive
    old = sample(tmp_path, "v2.0.0")
    releases.append(old)
    publisher.publish()
    old_hashes = set(indexes(store))

    now[0] += timedelta(days=1)
    releases.extend([sample(tmp_path, "v2.1.0"), sample(tmp_path, "v2.2.0")])
    publisher.publish()
    assert old.package.key not in Inventory(store.read(INVENTORY)).raw["desired"]["stable"]

    now[0] += timedelta(days=7)
    publisher.publish()
    assert old_hashes <= set(indexes(store))
    assert not store.denied(old.package.key)

    now[0] += timedelta(days=3)
    publisher.publish()
    assert old_hashes.isdisjoint(indexes(store))
    assert not store.denied(old.package.key)

    now[0] += timedelta(days=25)
    publisher.publish()
    assert store.denied(old.package.key)
    assert old.package.key in Inventory(store.read(INVENTORY)).packages


def test_withdrawal_blocks_payload_first_even_if_upstream_fails(tmp_path, archive):
    store, releases, _, publisher = archive
    rollback = sample(tmp_path, "v2.0.0")
    revoked = sample(tmp_path, "v2.1.0")
    releases.extend((rollback, revoked))
    publisher.publish()
    last = store.read(inrelease("stable"))
    select = publisher.select

    def unavailable(_inventory):
        raise ArchiveError("fixture release API unavailable")

    publisher.select = unavailable
    with pytest.raises(ArchiveError, match="release API unavailable"):
        publisher.publish(Change("withdraw", revoked.package.tag, revoked.package.sha256))
    assert store.denied(revoked.package.key)
    assert not store.denied(rollback.package.key)
    assert store.read(inrelease("stable")) == last
    assert Inventory(store.read(INVENTORY)).blocked(revoked.package)
    publisher.select = select
    publisher.publish()
    assert store.denied(revoked.package.key)
    assert store.read(inrelease("stable")) != last


def test_pause_signs_empty_suites_blocks_prior_pool_and_requires_explicit_resume(tmp_path, archive):
    store, releases, _, publisher = archive
    package = sample(tmp_path, "v2.0.0")
    releases.append(package)
    publisher.publish()
    old_pointers = {suite: store.read(inrelease(suite)) for suite in ("stable", "candidate")}
    select = publisher.select
    publisher.select = lambda inventory: pytest.fail("A paused archive must not select release inputs")
    publisher.publish(Change("pause"))
    state = Inventory(store.read(INVENTORY))
    assert state.raw["paused"] and state.raw["desired"] == {"stable": [], "candidate": []}
    assert store.denied(package.package.key)
    assert all(store.read(inrelease(suite)) != body for suite, body in old_pointers.items())
    publisher.publish()
    assert store.denied(package.package.key)
    publisher.select = select
    publisher.publish(Change("resume"))
    assert store.read(package.package.key) == package.path.read_bytes()


def test_missing_inventory_does_not_renew_existing_archive(tmp_path, archive):
    store, releases, _, publisher = archive
    releases.append(sample(tmp_path, "v2.0.0"))
    publisher.publish()
    last = store.read(inrelease("stable"))
    store.delete(INVENTORY)
    with pytest.raises(ArchiveError, match="inventory missing"):
        publisher.publish()
    assert store.read(inrelease("stable")) == last


def release_row(tag: str, body: bytes, *, draft=False, prerelease=None, package=True) -> dict:
    name, sums = entrypoint.VerifiedReleases.expected_assets(tag)
    return {
        "tag_name": tag, "draft": draft, "published_at": "2030-01-01T00:00:00Z",
        "prerelease": "rc" in tag if prerelease is None else prerelease,
        "assets": [{"name": sums, "size": len(body)}] + ([
            {"name": name, "size": len(body), "digest": f"sha256:{sha256(body)}"},
        ] if package else []),
    }


@pytest.fixture
def source(tmp_path, monkeypatch):
    public = FixtureStore()
    records = []
    github = {}
    attested = []

    def add(tag, **kwargs):
        body = tag.encode()
        row = release_row(tag, body, **kwargs)
        records.append(row)
        name, sums = entrypoint.VerifiedReleases.expected_assets(tag)
        checksum = f"{sha256(body)}  {name}\n".encode()
        public.put(f"{tag}/{sums}", checksum, etag=None)
        github[entrypoint.mirror.github_url("example/project", tag, sums)] = checksum
        public.put(f"{tag}/{name}", body, etag=None)
        return row

    def tool(argv, **kwargs):
        if argv[:2] == ["gh", "api"]:
            assert "--paginate" in argv and "--slurp" in argv
            return json.dumps([records]).encode()
        attested.append(argv)
        return b""

    monkeypatch.setattr(entrypoint, "run", tool)
    monkeypatch.setattr(entrypoint, "validate_debian_fields", lambda *a: None)
    monkeypatch.setattr(entrypoint.mirror, "fetch", lambda url, **kw: (200, {}, [github[url]]))
    notices = []
    releases = entrypoint.VerifiedReleases(
        "example/project", public, tmp_path, SETTINGS, pool=public, checksum_budget=65536,
        notice=lambda message, alert: notices.append((message, alert)),
        unqualified_delay=timedelta(hours=24), clock=lambda: NOW,
    )
    releases.notices = notices
    return releases, add, attested


def test_eligible_releases_select_newest_finals_and_release_candidates(source):
    releases, add, attested = source
    for tag in ("v2.1.0rc2", "v2.0.0", "v2.1.0rc10", "v2.0.1", "v2.0.2"):
        add(tag)
    add("v3.0.0", draft=True)
    add("v4.0.0", prerelease=True)
    add("v5.0.0", package=False)
    add("v6.0.0rc1", prerelease=False)
    output = releases.select(Inventory())
    assert [item.package.tag for item in output["stable"]] == ["v2.0.2", "v2.0.1"]
    assert [item.package.tag for item in output["candidate"]] == [
        "v2.0.2", "v2.0.1", "v2.1.0rc10", "v2.1.0rc2",
    ]
    assert all("--signer-workflow" in args for args in attested)
    assert {args[-1] for args in attested} == {
        f"refs/tags/{item.package.tag}" for item in output["candidate"]
    }


@pytest.mark.parametrize("mismatch", [
    "attestation", "asset_digest", "public_bytes", "checksum", "mirror_checksum", "debian_fields",
])
def test_unverified_package_is_not_selected(source, monkeypatch, mismatch):
    releases, add, _ = source
    row = add("v2.0.0")
    deb, sums = releases.expected_assets("v2.0.0")
    if mismatch == "asset_digest":
        row["assets"][1]["digest"] = "sha256:" + "0" * 64
    elif mismatch == "public_bytes":
        key = f"v2.0.0/{deb}"
        releases.published.put(key, b"other bytes", etag=releases.published.get(key).etag)
    elif mismatch == "debian_fields":
        def bad_fields(*args):
            raise ArchiveError("Debian control fields do not match")

        monkeypatch.setattr(entrypoint, "validate_debian_fields", bad_fields)
    elif mismatch == "mirror_checksum":
        key = f"v2.0.0/{sums}"
        releases.published.put(key, b"other checksum", etag=releases.published.get(key).etag)
    elif mismatch == "checksum":
        monkeypatch.setattr(entrypoint.mirror, "fetch", lambda url, **kw: (200, {}, [b"mismatch"]))
    else:
        original = entrypoint.run

        def tool(argv, **kwargs):
            if argv[:2] == ["gh", "attestation"]:
                raise ArchiveError("Attestation belongs to a different ref")
            return original(argv, **kwargs)

        monkeypatch.setattr(entrypoint, "run", tool)
    assert releases.select(Inventory()) == {"stable": [], "candidate": []}
    assert releases.notices == [("Skipped package qualification for v2.0.0", None)]


@pytest.mark.parametrize(("field", "value"), [
    ("Package", "another-package"), ("Version", "2.1.0rc1"), ("Architecture", "arm64"),
])
def test_debian_fields_are_checked_before_indexing(tmp_path, monkeypatch, field, value):
    import apt_archive
    package = sample(tmp_path, "v2.1.0rc1")
    fields = {"Package": "servonaut", "Version": "2.1.0~rc1", "Architecture": "amd64"}
    fields[field] = value
    monkeypatch.setattr(apt_archive, "deb_fields", lambda path, timeout: fields)
    with pytest.raises(ArchiveError, match="Debian control fields"):
        build_indexes([package], tmp_path, SETTINGS.timeout)


def test_a_dry_run_constructs_no_s3_client(tmp_path, monkeypatch, source, capsys):
    releases, add, _ = source
    add("v2.0.0")
    monkeypatch.setattr(entrypoint, "VerifiedReleases", lambda *a, **kw: releases)
    monkeypatch.setattr(entrypoint, "public_inventory", lambda public: Inventory())
    monkeypatch.setattr(entrypoint, "build_indexes", plain_fixture_indexes)

    def fail():
        pytest.fail("dry run attempted to open a writer")

    monkeypatch.setattr(entrypoint.mirror, "bucket_client", fail)
    args = entrypoint.parser().parse_args([
        "--repo", "example/project", "--base", "https://mirror.example.com", "--prefix", "apt",
        "--dry-run", "--finals", "2", "--candidates", "2", "--valid-hours", "48",
        "--pool-days", "30", "--index-days", "7", "--alert-hours", "24",
        "--split-minutes", "30", "--attempts", "3", "--timeout", "30", "--max-bytes", "100000",
        "--checksum-max-bytes", "65536", "--key-alert-days", "90",
        "--rehearsal-retention-hours", "24", "--unqualified-alert-hours", "24",
    ])
    entrypoint.execute(args, tmp_path)
    assert "stable: v2.0.0" in capsys.readouterr().out


def test_workflow_preserves_verified_readback_and_a_read_only_audit():
    workflow = (ROOT / ".github/workflows/release-mirror.yml").read_text()
    assert workflow.index("gh attestation verify") < workflow.index("id: apt-input")
    assert workflow.index("release-mirror.py check-public") < workflow.index("id: apt-input")
    publisher = workflow.split("  apt-publish:", 1)[1].split("  apt-audit:", 1)[0]
    audit_job = workflow.split("  apt-audit:", 1)[1]
    assert "needs.mirror.outputs.apt-deb-verified == 'true'" in publisher
    assert "concurrency:\n      group: release-mirror-apt-writer\n      queue: max" in publisher
    assert "environment: release-mirror" in publisher
    assert "--dry-run --prefix apt" in publisher and "--rehearsal --prefix" in publisher
    assert "secrets." not in audit_job and "apt-publish.py --action audit" in audit_job

    rehearsal = publisher.split("name: Sign and publish a separate rehearsal archive", 1)[1]
    rehearsal, production = rehearsal.split("name: Sign and publish the APT archive", 1)
    dry = publisher.split("name: Validate the APT publication plan without writing", 1)[1]
    assert "secrets." not in dry.split("\n      - name:", 1)[0]
    assert "APT_REPO_SIGNING_SUBKEY" not in rehearsal
    assert "vars.APT_RELEASE_MIRROR == 'on'" in production
    assert "secrets.APT_REPO_SIGNING_SUBKEY" in production


def test_unqualified_candidates_do_not_prevent_renewal_over_two_days(tmp_path, source, monkeypatch):
    releases, add, _ = source
    store = FixtureStore()
    releases.pool = store
    now = [NOW]
    for tag in ("v2.0.0", "v2.0.1"):
        add(tag)
    publisher = Publisher(
        store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
        lambda plain: plain, lambda signed: signed, lambda: now[0],
    )
    publisher.publish()
    initial = store.read(inrelease("stable"))
    missing, rejected = "v2.1.0rc1", "v2.1.0rc2"
    add(missing)
    add(rejected)
    _, checksum = releases.expected_assets(missing)
    releases.published.delete(f"{missing}/{checksum}")
    original = entrypoint.run

    def tool(argv, **kwargs):
        if argv[:2] == ["gh", "attestation"] and argv[-1] == f"refs/tags/{rejected}":
            raise ArchiveError("Candidate attestation rejected")
        return original(argv, **kwargs)

    monkeypatch.setattr(entrypoint, "run", tool)
    for _ in range(9):
        now[0] += timedelta(hours=6)
        publisher.publish()
        state = Inventory(store.read(INVENTORY))
        audit(store, state, publisher.verify, settings=SETTINGS, now=now[0])
        assert state.raw["desired"]["stable"] == state.raw["desired"]["candidate"]
        assert len(state.raw["desired"]["stable"]) == 2
    assert store.read(inrelease("stable")) != initial
    assert {(msg, alert) for msg, alert in releases.notices} == {
        (f"Skipped package qualification for {missing}", None),
        (f"Skipped package qualification for {rejected}", None),
    }


@pytest.mark.parametrize("withdrawn", [False, True])
def test_replacement_bytes_raise_alert_and_never_replace_admitted_bytes(tmp_path, source, withdrawn):
    releases, add, _ = source
    store = FixtureStore()
    releases.pool = store
    tag = "v2.0.1"
    add("v2.0.0")
    row = add(tag)
    publisher = Publisher(
        store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
        lambda plain: plain, lambda signed: signed, lambda: NOW,
    )
    publisher.publish()
    old = next(item for item in Inventory(store.read(INVENTORY)).packages.values() if item.tag == tag)
    if withdrawn:
        publisher.publish(Change("withdraw", tag, old.sha256))
    row["assets"][1]["digest"] = "sha256:" + "a" * 64
    name, _ = releases.expected_assets(tag)
    key = f"{tag}/{name}"
    releases.published.put(key, b"unauthorized replacement", etag=releases.published.get(key).etag)
    first = store.read(inrelease("stable"))
    publisher.publish()
    assert store.read(inrelease("stable")) != first
    assert releases.notices == [(f"Refused replacement bytes for admitted release {tag}", "upstream")]
    if withdrawn:
        assert store.denied(old.key)
    else:
        assert store.read(old.key) == tag.encode()


def test_unknown_withdrawal_records_nothing(tmp_path, archive):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    publisher.publish()
    existing = store.get(INVENTORY)
    for tag, digest in ((item.package.tag, "0" * 64), ("v8.0.0", item.package.sha256)):
        with pytest.raises(ArchiveError, match="No known APT package"):
            publisher.publish(Change("withdraw", tag, digest))
        assert store.get(INVENTORY) == existing
        assert store.read(item.package.key) == item.path.read_bytes()


def test_published_asset_exact_digest_can_be_withdrawn_before_mirroring(source):
    releases, add, _ = source
    tag = "v2.0.0"
    row = add(tag)
    name, _ = releases.expected_assets(tag)
    releases.published.delete(f"{tag}/{name}")
    inventory = Inventory()
    pkg_digest = row["assets"][1]["digest"].split(":")[1]
    assert releases.knows_withdrawal(Change("withdraw", tag, pkg_digest))
    assert not releases.knows_withdrawal(Change("withdraw", tag, "0" * 64))
    inventory.change(Change("withdraw", tag, pkg_digest), releases.knows_withdrawal)
    assert releases.select(inventory) == {"stable": [], "candidate": []}
    assert releases.notices == []


def test_checksum_download_stops_reading_after_budget(source):
    releases, _, _ = source

    def checksum_chunks():
        yield b"x" * (releases.checksum_budget + 1)
        pytest.fail("checksum download consumed more chunks after hitting the budget")

    with pytest.MonkeyPatch.context() as patches:
        patches.setattr(entrypoint.mirror, "fetch", lambda *a, **kw: (200, {}, checksum_chunks()))
        with pytest.raises(ArchiveError, match="size budget"):
            releases.github_checksum("v2.0.0", "SHA256SUMS")


def test_inventory_fence_stops_later_writes_after_policy_changes(tmp_path, archive, monkeypatch):
    store, releases, _, publisher = archive
    stable = sample(tmp_path, "v2.0.0")
    candidate = sample(tmp_path, "v2.1.0rc1")
    releases.extend((stable, candidate))
    publisher.settings = replace(SETTINGS, attempts=1)
    original = store.read

    def move_policy(key):
        body = original(key)
        if key == stable.package.key:
            current = store.get(INVENTORY)
            policy = Inventory(current.body)
            policy.change(Change("withdraw", candidate.package.tag, candidate.package.sha256))
            store.put(INVENTORY, policy.encode(), etag=current.etag)
        return body

    monkeypatch.setattr(store, "read", move_policy)
    with pytest.raises(ArchiveError, match="Concurrent archive change"):
        publisher.publish()
    assert store.get(candidate.package.key) is None
    assert store.get(inrelease("stable")) is None


def test_public_pool_readback_is_required_before_replacing_pointers(tmp_path, archive, monkeypatch):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    original = store.read
    reads = 0

    def wrong_once(key):
        nonlocal reads
        if key == item.package.key:
            reads += 1
            if reads == 1:
                return b"wrong"
        return original(key)

    monkeypatch.setattr(store, "read", wrong_once)
    with pytest.raises(ArchiveError, match="Package bytes"):
        publisher.publish()
    assert store.get(inrelease("stable")) is None


def test_post_publish_audit_reads_canonical_bytes(tmp_path, archive, monkeypatch):
    store, releases, _, publisher = archive
    releases.append(sample(tmp_path, "v2.0.0"))
    original = store.read
    monkeypatch.setattr(
        store, "read", lambda key: b"stale" if key == "dists/stable/main/binary-amd64/Packages" else original(key),
    )
    with pytest.raises(ArchiveError, match="Canonical stable index"):
        publisher.publish()


def test_audit_refuses_candidate_in_stable_even_with_a_valid_signature(tmp_path, archive):
    _, _, _, publisher = archive
    rc = sample(tmp_path, "v2.0.0rc1")
    publisher.select = lambda inventory: {"stable": [rc], "candidate": [rc]}
    with pytest.raises(ArchiveError, match="Stable suite advertises a release candidate"):
        publisher.publish()


def test_audit_refuses_blocked_index_and_old_or_short_key_windows(tmp_path, archive):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    publisher.publish()
    inventory = Inventory(store.read(INVENTORY))
    with pytest.raises(ArchiveError, match="outside its renewal window"):
        audit(store, inventory, publisher.verify, settings=SETTINGS, now=NOW + timedelta(hours=24))
    with pytest.raises(ArchiveError, match="Signing subkey expires before"):
        audit(store, inventory, publisher.verify, settings=SETTINGS, now=NOW,
              key_expires=NOW + timedelta(hours=36))
    inventory.change(Change("withdraw", item.package.tag, item.package.sha256))
    with pytest.raises(ArchiveError, match="Index includes an unverified or blocked package"):
        audit(store, inventory, publisher.verify, settings=SETTINGS, now=NOW)


def test_retained_deadlines_include_validity_and_reader_grace(tmp_path, archive):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    publisher.publish()
    retained = Inventory(store.read(INVENTORY)).raw["retained"]
    assert retained[item.package.key] == int((NOW + SETTINGS.valid_for + SETTINGS.pool_grace).timestamp())
    assert all(retained[key] == int((NOW + SETTINGS.valid_for + SETTINGS.index_grace).timestamp())
               for key in indexes(store))


def test_cleanup_scopes_to_completed_or_old_rehearsals():
    from types import SimpleNamespace

    old = NOW - timedelta(days=15)
    recent = NOW - timedelta(days=1)
    deleted = []
    listing = [
        ("apt/pool/package.deb", old),
        ("apt-rehearsal/30-1/index", old),
        ("apt-rehearsal/31-1/index", old),
        ("apt-rehearsal/31-1/package", recent),
        ("apt-rehearsal/31-1-other/index", old),
        ("apt-rehearsal/32-1/index", recent),
    ]
    pages = [{"Contents": [{"Key": key, "LastModified": time} for key, time in listing]}]
    store = SimpleNamespace(
        get_paginator=lambda operation: SimpleNamespace(paginate=lambda **kw: pages),
        delete_object=lambda **kw: deleted.append(kw["Key"]),
    )
    entrypoint.clear_rehearsals(store, "fixture", older_than=NOW - timedelta(days=7))
    assert deleted == ["apt-rehearsal/30-1/index"]
    entrypoint.clear_rehearsals(store, "fixture", prefix="apt-rehearsal/31-1")
    assert deleted[1:] == ["apt-rehearsal/31-1/index", "apt-rehearsal/31-1/package"]
    with pytest.raises(ArchiveError, match="Invalid rehearsal"):
        entrypoint.clear_rehearsals(store, "fixture", prefix="apt")


@pytest.mark.parametrize(("signature", "valid"), [
    ("good", True), ("missing-good", False), ("other-subkey", False), ("other-good-key", False),
    ("EXPKEYSIG", False), ("EXPSIG", False), ("REVKEYSIG", False),
    ("KEYEXPIRED", False), ("KEYREVOKED", False),
])
def test_verify_checks_both_bound_status_records_and_expiry(tmp_path, monkeypatch, signature, valid):
    import apt_archive

    expected, other = "A" * 40, "B" * 40
    good = other[-16:] if signature == "other-good-key" else expected[-16:]
    valid_fingerprint = other if signature == "other-subkey" else expected
    rows = [f"[GNUPG:] VALIDSIG {valid_fingerprint}"]
    if signature != "missing-good":
        rows.append(f"[GNUPG:] GOODSIG {good} Fixture")
    if signature.isupper():
        rows.append(f"[GNUPG:] {signature} 0")

    def tool(argv, **kwargs):
        Path(argv[argv.index("--output") + 1]).write_bytes(b"Release")
        return "\n".join(rows).encode()

    monkeypatch.setattr(apt_archive, "run", tool)
    signer = Signer(tmp_path, tmp_path / "fixture.gpg", expected, SETTINGS.timeout)
    if valid:
        assert signer.verify(b"InRelease") == b"Release"
    else:
        with pytest.raises(ArchiveError, match="signing"):
            signer.verify(b"InRelease")


def test_sign_uses_only_the_exact_subkey_and_sha256(tmp_path, monkeypatch):
    import apt_archive

    fingerprint = "A" * 40
    signer = Signer(tmp_path, tmp_path / "fixture.gpg", fingerprint, SETTINGS.timeout)
    monkeypatch.setattr(signer, "verify", lambda data: b"Release")

    def tool(argv, *, input_bytes, timeout):
        assert argv[argv.index("--local-user") + 1] == fingerprint + "!"
        assert argv[argv.index("--digest-algo") + 1] == "SHA256"
        assert input_bytes == b"fixture\n"
        return b"InRelease"

    monkeypatch.setattr(apt_archive, "run", tool)
    assert signer.sign(b"Release", b"fixture") == b"InRelease"


def test_import_refuses_a_private_primary_even_with_matching_subkey(tmp_path, monkeypatch):
    fingerprint = "A" * 40
    sec = [""] * 16
    sec[0], sec[14] = "sec", "+"
    ssb = [""] * 16
    ssb[0], ssb[11], ssb[14] = "ssb", "s", "+"
    fpr = [""] * 16
    fpr[0], fpr[9] = "fpr", fingerprint
    output = "\n".join(":".join(row) for row in (sec, ssb, fpr)).encode()
    monkeypatch.setattr(entrypoint, "run", lambda *a, **kw: output)
    with pytest.raises(ArchiveError, match="stub primary"):
        entrypoint.import_signing_subkey(tmp_path, b"fixture", fingerprint, SETTINGS.timeout)


def test_key_rotation_lead_signals_the_workflow_without_failing(tmp_path, monkeypatch, capsys):
    output = tmp_path / "workflow-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    entrypoint.warn_key_rotation(NOW + timedelta(days=91), NOW, 90)
    assert not output.exists()
    entrypoint.warn_key_rotation(NOW + timedelta(days=90), NOW, 90)
    assert output.read_text() == "rotation=true\n"
    assert "rotation window" in capsys.readouterr().out


@pytest.mark.parametrize(("prefix", "rehearsal"), [("apt", True), ("apt-rehearsal/1-1", False)])
def test_prefix_must_match_rehearsal_or_production_mode(tmp_path, prefix, rehearsal):
    from types import SimpleNamespace

    args = SimpleNamespace(prefix=prefix, rehearsal=rehearsal, action="publish")
    with pytest.raises(ArchiveError, match="prefix"):
        entrypoint.execute(args, tmp_path)


def test_rehearsal_refuses_production_signing_inputs(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY", "fixture-setting")
    def generate(*args, **kwargs):
        pytest.fail("Fixture key generated with production signing input still present")

    monkeypatch.setattr(entrypoint, "fixture_signing", generate)
    with pytest.raises(ArchiveError, match="only fixture signing"):
        entrypoint.signing(SimpleNamespace(rehearsal=True), tmp_path, None, None)


def test_conflict_retry_keeps_signing_input_and_original_error(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from apt_archive import Conflict, KEYRING

    fingerprint = "A" * 40
    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY", "fixture-secret")
    monkeypatch.setenv("APT_REPO_SIGNING_PASSPHRASE", "fixture-phrase")
    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY_FINGERPRINT", fingerprint)
    imported = []
    monkeypatch.setattr(
        entrypoint, "import_signing_subkey", lambda home, body, fpr, timeout: imported.append((body, fpr)),
    )
    monkeypatch.setattr(entrypoint, "run", lambda *a, **kw: b"fixture-public-keyring")
    monkeypatch.setattr(Signer, "sign", lambda *a: b"signature")
    monkeypatch.setattr(Signer, "expires_at", lambda *a: datetime.now(timezone.utc) + timedelta(days=365))
    store = FixtureStore()

    def conflict(key, body):
        if key == KEYRING:
            store.before_put = None
            raise Conflict("fixture keyring conflict")

    store.before_put = conflict
    args = SimpleNamespace(rehearsal=False, timeout=30, valid_hours=48, key_alert_days=90)
    with pytest.raises(Conflict, match="fixture keyring conflict"):
        entrypoint.signing(args, tmp_path, store, store)
    assert entrypoint.signing(args, tmp_path, store, store)[1] == b"fixture-phrase"
    assert imported == [(b"fixture-secret", fingerprint)] * 2


def test_selection_with_a_blocked_identity_fails_before_any_write(tmp_path, archive):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    publisher.publish()
    publisher.publish(Change("withdraw", item.package.tag, item.package.sha256))
    stable = store.get(inrelease("stable"))
    publisher.select = lambda inventory: {"stable": [item], "candidate": [item]}
    with pytest.raises(ArchiveError, match="Selected package conflicts with archive policy"):
        publisher.publish()
    assert store.get(inrelease("stable")) == stable
    assert store.denied(item.package.key)


def test_preparation_keeps_the_original_pointer_etag(tmp_path, archive):
    store, releases, _, publisher = archive
    releases.append(sample(tmp_path, "v2.0.0"))
    publisher.publish()
    old = store.get(inrelease("stable"))
    publisher.settings = replace(SETTINGS, attempts=1)

    def replace_pointer(key, body):
        if key == "dists/stable/main/binary-amd64/Packages":
            store.before_put = None
            store.put(inrelease("stable"), b"external publication", etag=old.etag)

    store.before_put = replace_pointer
    with pytest.raises(ArchiveError, match="Concurrent archive change"):
        publisher.publish()
    assert store.read(inrelease("stable")) == b"external publication"


def test_retention_reservation_extends_prior_active_references(tmp_path, archive):
    store, releases, now, publisher = archive
    old = sample(tmp_path, "v2.0.0")
    releases.append(old)
    publisher.publish()
    before = Inventory(store.read(INVENTORY)).raw["retained"][old.package.key]
    releases.clear()
    releases.append(sample(tmp_path, "v2.0.1"))
    now[0] += timedelta(hours=36)
    publisher.publish()
    retained = Inventory(store.read(INVENTORY)).raw["retained"]
    assert retained[old.package.key] == before + 36 * 60 * 60


def test_gc_preserves_current_objects_even_with_a_stale_retention_deadline(tmp_path, archive, monkeypatch):
    store, releases, _, publisher = archive
    item = sample(tmp_path, "v2.0.0")
    releases.append(item)
    reserve = Inventory.reserve

    def stale_deadline(inventory, *args):
        reserve(inventory, *args)
        inventory.raw["retained"][item.package.key] = int((NOW - timedelta(days=1)).timestamp())

    monkeypatch.setattr(Inventory, "reserve", stale_deadline)
    publisher.publish()
    assert store.read(item.package.key) == item.path.read_bytes()


def test_admitted_package_survives_missing_assets_with_upstream_alert(tmp_path, source, monkeypatch):
    releases, add, attested = source
    tag = "v2.0.1"
    row = add(tag)
    store = FixtureStore()
    releases.pool = store
    publisher = Publisher(store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
                          lambda plain: plain, lambda signed: signed, lambda: NOW)
    publisher.publish()
    before = store.read(inrelease("stable"))
    row["assets"].clear()
    attested.clear()
    publisher.publish()
    assert store.read(inrelease("stable")) != before
    assert [call[-1] for call in attested] == [f"refs/tags/{tag}"]
    assert releases.notices == [(f"Upstream package evidence is unavailable for {tag}", "upstream")]

    def denied(argv, **kwargs):
        if argv[:2] == ["gh", "attestation"]:
            raise ArchiveError("Pool bytes have no current tag attestation")
        return json.dumps([[row]]).encode()

    monkeypatch.setattr(entrypoint, "run", denied)
    assert store.read(inrelease("stable")) != before
    current = store.read(inrelease("stable"))
    with pytest.raises(ArchiveError, match="no current tag attestation"):
        publisher.publish()
    assert store.read(inrelease("stable")) == current


@pytest.mark.parametrize("withdrawing", [True, False])
@pytest.mark.parametrize("replacement", [True, False])
def test_pool_recovery_refuses_blocked_or_unindexed_packages(tmp_path, source, withdrawing, replacement):
    releases, add, _ = source
    tag = "v2.0.1"
    row = add(tag)
    store = FixtureStore()
    releases.pool = store
    publisher = Publisher(store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
                          lambda plain: plain, lambda signed: signed, lambda: NOW)
    publisher.publish()
    state = Inventory(store.read(INVENTORY))
    old, = state.packages.values()
    if withdrawing:
        # A run interrupted after saving policy can still have an old desired index.
        state.change(Change("withdraw", tag, old.sha256))
    else:
        state.raw["desired"] = {"stable": [], "candidate": []}
    if replacement:
        row["assets"][1]["digest"] = "sha256:" + "a" * 64
    else:
        row["assets"].clear()
    assert releases.select(state) == {"stable": [], "candidate": []}


def test_unqualified_alert_persists_first_observed_time_and_clears_on_admission(tmp_path, source):
    releases, add, _ = source
    tag = "v2.0.1"
    row = add(tag)
    assets = row["assets"].copy()
    row["assets"].clear()
    store = FixtureStore()
    clock = [NOW]
    releases.clock = lambda: clock[0]
    publisher = Publisher(store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
                          lambda plain: plain, lambda signed: signed, lambda: clock[0])
    publisher.publish()
    assert Inventory(store.read(INVENTORY)).raw["unqualified_since"] == {tag: int(NOW.timestamp())}
    assert releases.notices[-1][1] is None
    clock[0] += timedelta(hours=23)
    publisher.publish()
    assert releases.notices[-1][1] is None
    clock[0] += timedelta(hours=1)
    publisher.publish()
    assert releases.notices[-1] == (f"Skipped package qualification for {tag}", "unqualified")
    row["assets"] = assets
    publisher.publish()
    assert Inventory(store.read(INVENTORY)).raw["unqualified_since"] == {}


def test_missing_release_row_keeps_exact_admitted_pool_bytes(tmp_path, source, monkeypatch):
    releases, add, _ = source
    tag = "v2.0.1"
    add(tag)
    store = FixtureStore()
    releases.pool = store
    publisher = Publisher(store, store, SETTINGS, tmp_path, releases.select, plain_fixture_indexes,
                          lambda plain: plain, lambda signed: signed, lambda: NOW)
    publisher.publish()
    monkeypatch.setattr(releases, "releases", lambda: [])
    publisher.publish()
    state = Inventory(store.read(INVENTORY))
    item, = state.packages.values()
    assert store.read(item.key) == tag.encode() and state.raw["desired"]["stable"] == [item.key]
    assert releases.notices[-1][1] == "upstream"


def cli_args(*extra):
    return entrypoint.parser().parse_args([
        "--repo", "example/project", "--base", "https://mirror.example.com", "--prefix", "apt",
        "--finals", "2", "--candidates", "2", "--valid-hours", "48", "--pool-days", "30",
        "--index-days", "7", "--alert-hours", "24", "--split-minutes", "30", "--attempts", "3",
        "--timeout", "30", "--max-bytes", "100000", "--checksum-max-bytes", "65536",
        "--key-alert-days", "90", "--rehearsal-retention-hours", "24", "--unqualified-alert-hours", "24",
        *extra,
    ])


def test_unknown_withdrawal_dry_run_fails_before_selection(tmp_path, monkeypatch, source):
    releases, _, _ = source
    monkeypatch.setattr(entrypoint, "VerifiedReleases", lambda *a, **kw: releases)
    monkeypatch.setattr(entrypoint, "public_inventory", lambda public: Inventory())
    monkeypatch.setattr(releases, "select", lambda inventory: pytest.fail("Unknown withdrawal selected"))
    args = cli_args("--dry-run", "--action", "withdraw", "--tag", "v2.0.0", "--digest", "0" * 64)
    with pytest.raises(ArchiveError, match="No known APT package"):
        entrypoint.execute(args, tmp_path)


def test_key_expiry_checks_primary_and_distinguishes_a_missing_subkey(tmp_path, monkeypatch):
    import apt_archive

    primary = [""] * 15
    primary[0], primary[6] = "pub", str(int(NOW.timestamp()))
    subkey = [""] * 15
    subkey[0], subkey[6], subkey[11] = "sub", str(int((NOW + timedelta(days=1)).timestamp())), "s"
    fpr = [""] * 15
    fpr[0], fpr[9] = "fpr", "A" * 40
    rows = "\n".join(":".join(row) for row in (primary, subkey, fpr)).encode()
    monkeypatch.setattr(apt_archive, "run", lambda *args, **kwargs: rows)
    assert Signer(tmp_path, tmp_path / "fixture.gpg", "A" * 40, 30).expires_at() == NOW
    with pytest.raises(ArchiveError, match="keyring does not contain"):
        Signer(tmp_path, tmp_path / "fixture.gpg", "B" * 40, 30).expires_at()


def test_publisher_refuses_a_subkey_that_expires_before_next_snapshot(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY", "fixture secret")
    monkeypatch.setenv("APT_REPO_SIGNING_PASSPHRASE", "fixture passphrase")
    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY_FINGERPRINT", "A" * 40)
    monkeypatch.setattr(entrypoint, "import_signing_subkey", lambda *args: None)
    monkeypatch.setattr(entrypoint, "run", lambda *a, **kw: b"fixture keyring")
    monkeypatch.setattr(Signer, "expires_at", lambda self: datetime.now(timezone.utc) + timedelta(hours=24))
    monkeypatch.setattr(Signer, "sign", lambda *args: pytest.fail("Short-lived key should not sign"))
    store = FixtureStore()
    args = SimpleNamespace(rehearsal=False, timeout=30, valid_hours=48, key_alert_days=90)
    with pytest.raises(ArchiveError, match="expires before the next archive snapshot"):
        entrypoint.signing(args, tmp_path, store, store)
    assert store.events == []


def test_audit_cli_uses_pinned_fingerprint_and_passes_key_expiry(tmp_path, monkeypatch):
    from apt_archive import KEYRING

    store = FixtureStore()
    store.put(KEYRING, b"fixture keyring", etag=None)
    store.put(INVENTORY, Inventory().encode(), etag=None)
    monkeypatch.setenv("APT_REPO_SIGNING_SUBKEY_FINGERPRINT", "A" * 40)
    monkeypatch.setattr(entrypoint, "HttpArchive", lambda *args: store)

    def key_expiry(signer):
        assert signer.fingerprint == "A" * 40
        return NOW

    monkeypatch.setattr(Signer, "expires_at", key_expiry)
    recorded = []
    monkeypatch.setattr(entrypoint, "audit", lambda *a, **kw: recorded.append(kw["key_expires"]))
    entrypoint.execute(cli_args("--action", "audit"), tmp_path)
    assert recorded == [NOW]


def test_rehearsal_sweep_passes_configured_retention_cutoff(tmp_path, monkeypatch):
    class FixtureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    recorded = []
    monkeypatch.setattr(entrypoint, "datetime", FixtureClock)
    monkeypatch.setattr(entrypoint.mirror, "bucket_client", lambda: (object(), "fixture-bucket"))
    monkeypatch.setattr(entrypoint, "clear_rehearsals", lambda *args, **kwargs: recorded.append(kwargs))
    entrypoint.execute(cli_args("--action", "sweep-rehearsals", "--rehearsal-retention-hours", "37"), tmp_path)
    assert recorded == [{"older_than": NOW - timedelta(hours=37)}]


@pytest.mark.parametrize(("is_open", "previous", "active", "hours", "expected"), [
    (True, True, True, 6, ""), (True, True, True, 24, "comment"),
    (False, True, True, 150, ""), (False, True, False, 1, "comment"),
    (False, False, True, 1, "create"), (True, False, True, 1, "comment"),
    (True, True, False, 1, "comment"), (True, False, False, 999, ""),
])
def test_issue_alert_dispatch_throttles_persistent_state(is_open, previous, active, hours, expected):
    reporter = importlib.import_module("apt-report-alerts")
    state = reporter.IssueState(12, is_open, previous, NOW)
    assert reporter.decision(state, active, NOW + timedelta(hours=hours), timedelta(hours=24)) == expected


def test_alert_history_is_appended_and_uses_a_distinct_stable_marker(tmp_path, monkeypatch):
    reporter = importlib.import_module("apt-report-alerts")
    gh = reporter.GitHub("example/project", 30, timedelta(hours=24))
    actions = []
    label_commands = []

    def command(*args):
        if args[:2] == ("label", "create"):
            label_commands.append(args)
            return ""
        if args[:2] == ("issue", "create"):
            assert args[6:8] == ("--label", "apt-archive-alert")
        actions.append((args[:2], Path(args[-1]).read_text()))
        return ""

    monkeypatch.setattr(gh, "run", command)
    current = reporter.IssueState(12, True, True, NOW)
    gh.update("upstream", False, current, "https://example.com/run/1", NOW)
    gh.update("rotation", True, None, "https://example.com/run/2", NOW)
    assert label_commands == [(
        "label", "create", "apt-archive-alert", "--repo", "example/project", "--force",
        "--description", "Automated APT archive alerts", "--color", "d93f0b",
    )]
    assert actions == [
        (("issue", "comment"), "<!-- apt-archive:upstream:clear -->\nCondition cleared.\n\nRun: https://example.com/run/1\n"),
        (("issue", "create"), "<!-- apt-archive:rotation:active -->\nCondition active.\n\nRun: https://example.com/run/2\n"),
    ]


def test_issue_reporter_requires_marker_and_bot_author(monkeypatch):
    reporter = importlib.import_module("apt-report-alerts")
    gh = reporter.GitHub("example/project", 30, timedelta(hours=24))
    issue = {
        "number": 12, "title": reporter.KINDS["audit"], "body": reporter.marker("audit", True),
        "state": "closed", "created_at": NOW.isoformat(), "user": {"login": reporter.BOT},
    }
    comments = [
        {"body": reporter.marker("audit", False), "created_at": (NOW + timedelta(hours=1)).isoformat(),
         "user": {"login": reporter.BOT}},
        {"body": reporter.marker("audit", True), "created_at": (NOW + timedelta(hours=2)).isoformat(),
         "user": {"login": "fixture-contributor"}},
    ]
    monkeypatch.setattr(gh, "run", lambda *args: json.dumps([comments]))
    impostor = {**issue, "number": 13, "user": {"login": "fixture-contributor"}}
    unmarked = {**issue, "number": 14, "body": "An unrelated note"}
    state = gh.state("audit", [issue, impostor, unmarked])
    assert state == reporter.IssueState(12, False, False, NOW + timedelta(hours=1))


def test_alert_lookup_fetches_only_labelled_issues_and_keeps_closed_records(monkeypatch):
    reporter = importlib.import_module("apt-report-alerts")
    gh = reporter.GitHub("example/project", 30, timedelta(hours=24))
    issue = {"number": 12, "state": "closed"}

    def command(*args):
        assert args == (
            "api", "--paginate", "--slurp",
            "repos/example/project/issues?state=all&labels=apt-archive-alert&per_page=100",
        )
        return json.dumps([[{"number": 11, "pull_request": {}}], [issue]])

    monkeypatch.setattr(gh, "run", command)
    assert gh.issues() == [issue]


def test_alert_reminder_interval_is_taken_from_workflow_environment(monkeypatch):
    reporter = importlib.import_module("apt-report-alerts")
    monkeypatch.setenv("APT_ALERT_REMINDER_HOURS", "9")
    monkeypatch.setenv("GH_REPO", "example/project")
    monkeypatch.setenv("APT_TIMEOUT", "30")
    monkeypatch.setattr(reporter, "observed", lambda env: {})
    actual = []
    monkeypatch.setattr(reporter, "GitHub", lambda *args: actual.append(args))
    assert reporter.main() == 0
    assert actual == [("example/project", 30, timedelta(hours=9))]
    state = reporter.IssueState(12, True, True, NOW)
    assert reporter.decision(state, True, NOW + timedelta(hours=8), actual[0][-1]) == ""
    assert reporter.decision(state, True, NOW + timedelta(hours=9), actual[0][-1]) == "comment"


def test_issue_reporting_does_not_clear_unobserved_conditions():
    reporter = importlib.import_module("apt-report-alerts")
    assert reporter.observed({"AUDIT_RESULT": "skipped", "PUBLISH_RESULT": "success"}) == {}
    assert reporter.observed({
        "AUDIT_RESULT": "failure", "PUBLISH_RESULT": "failure", "CHECK_SCHEDULED_PUBLISH": "true",
        "PUBLISH_ROTATION": "true", "UPSTREAM": "true", "UNQUALIFIED": "true",
    }) == {kind: True for kind in reporter.KINDS}
    assert reporter.observed({
        "AUDIT_RESULT": "success", "PUBLISH_RESULT": "success", "PRODUCTION_RESULT": "success",
        "CHECK_SCHEDULED_PUBLISH": "true",
    }) == {kind: False for kind in reporter.KINDS}
