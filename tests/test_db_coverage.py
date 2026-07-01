"""Tests for DB-vault coverage + search primitives — Layer B4."""
from __future__ import annotations

from servonaut.config.schema import AppConfig, DBProfile
from servonaut.services.db_coverage import (
    compute_db_coverage,
    coverage_summary,
    filter_coverage,
    filter_names,
)


def _config(profiles):
    cfg = AppConfig()
    cfg.db_profiles = profiles
    return cfg


def _instances(*names):
    return [{"id": n, "name": n} for n in names]


class TestComputeCoverage:
    def test_classifies_covered_gap_and_missing_secret(self):
        cfg = _config([
            DBProfile(instance="web-1", password_secret="db/web-1"),  # covered
            DBProfile(instance="web-2", password_secret="db/web-2"),  # secret gone
            # web-3 has no profile at all → gap
        ])
        # Store has web-1's secret but NOT web-2's (deleted out-of-band).
        rows = compute_db_coverage(
            _instances("web-1", "web-2", "web-3"), cfg, ["db/web-1"],
        )
        by = {r.instance_id: r for r in rows}
        assert by["web-1"].covered is True
        assert by["web-1"].status == "covered"
        assert by["web-2"].has_profile is True
        assert by["web-2"].secret_present is False
        assert by["web-2"].status == "secret missing"
        assert by["web-3"].has_profile is False
        assert by["web-3"].status == "no profile"

    def test_summary_counts(self):
        cfg = _config([DBProfile(instance="a", password_secret="db/a")])
        rows = compute_db_coverage(_instances("a", "b"), cfg, ["db/a"])
        assert coverage_summary(rows) == {"covered": 1, "gap": 1, "total": 2}

    def test_matches_by_name_and_id(self):
        # Profile keyed on the instance NAME resolves via db_profile_for.
        cfg = _config([DBProfile(instance="prod-web", password_secret="db/prod-web")])
        rows = compute_db_coverage(
            [{"id": "i-999", "name": "prod-web"}], cfg, ["db/prod-web"],
        )
        assert rows[0].covered is True


class TestFilters:
    def test_filter_names(self):
        names = ["db/web-1", "db/web-2", "ssh/key-a"]
        assert filter_names(names, "web") == ["db/web-1", "db/web-2"]
        assert filter_names(names, "") == names
        assert filter_names(names, "SSH") == ["ssh/key-a"]

    def test_filter_coverage_by_server_and_secret(self):
        cfg = _config([DBProfile(instance="web-1", password_secret="db/web-1")])
        rows = compute_db_coverage(_instances("web-1", "api-2"), cfg, ["db/web-1"])
        assert [r.instance_id for r in filter_coverage(rows, "web")] == ["web-1"]
        assert [r.instance_id for r in filter_coverage(rows, "api")] == ["api-2"]
        assert len(filter_coverage(rows, "")) == 2
        # Secret-name match.
        assert [r.instance_id for r in filter_coverage(rows, "db/web")] == ["web-1"]
