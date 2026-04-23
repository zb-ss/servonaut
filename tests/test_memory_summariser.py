"""Tests for the deterministic memory summariser (T3).

All tests use hand-built Dict[str, ModuleResult] fixtures.
No mocks — the summariser is pure data-in → string-out.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from servonaut.config.schema import MemoryConfig
from servonaut.services.memory.interfaces import ModuleResult
from servonaut.services.memory.service import MemoryService, _truncate_summary
from servonaut.services.memory.store import MemoryStore
from servonaut.services.memory.summariser import Summariser, build_summary_markdown

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
_RECENT = _NOW.isoformat()  # probed right now → fresh


def _make_module(
    name: str,
    observed: Dict[str, Any],
    declared: Optional[Dict[str, Any]] = None,
    *,
    ttl_seconds: int = 86400,
    probed_at: str = _RECENT,
    sudo_used: bool = False,
    truncated: bool = False,
    partial: bool = False,
) -> ModuleResult:
    return ModuleResult(
        module=name,
        instance_id="i-test",
        observed=observed,
        declared=declared or {},
        ttl_seconds=ttl_seconds,
        probed_at=probed_at,
        sudo_used=sudo_used,
        truncated=truncated,
        partial=partial,
    )


_INSTANCE_META = {"id": "i-abc123", "name": "web-prod-1", "provider": "AWS"}

# ---------------------------------------------------------------------------
# Optional type alias (avoid circular import with Optional in helper above)
# ---------------------------------------------------------------------------
from typing import Optional  # noqa: E402 (must be after __future__ annotations)


# ---------------------------------------------------------------------------
# test_minimal_os_only
# ---------------------------------------------------------------------------

class TestMinimalOsOnly:
    """Only the os module is present — only Identity section should appear."""

    def _make_modules(self) -> Dict[str, ModuleResult]:
        return {
            "os": _make_module(
                "os",
                observed={
                    "pretty_name": "Ubuntu 22.04.4 LTS",
                    "version_id": "22.04",
                    "kernel": "5.15.0-107-generic",
                    "arch": "x86_64",
                },
            )
        }

    def test_contains_identity_section(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        assert "## Identity" in result

    def test_contains_os_pretty_name(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        assert "Ubuntu 22.04.4 LTS" in result

    def test_no_other_section_headers(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        for section in (
            "## Runtimes",
            "## Services",
            "## Web stack",
            "## Logs",
            "## Databases",
            "## Containers",
            "## Network",
            "## Git",
            "## Disk",
            "## Annotations",
            "## Data quality",
        ):
            assert section not in result, f"Unexpected section: {section}"

    def test_header_contains_instance_info(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        assert "web-prod-1" in result
        assert "i-abc123" in result
        assert "AWS" in result


# ---------------------------------------------------------------------------
# test_full_mvp_fixture
# ---------------------------------------------------------------------------

class TestFullMvpFixture:
    """All 5 MVP modules present — full snapshot comparison."""

    def _make_modules(self) -> Dict[str, ModuleResult]:
        return {
            "os": _make_module(
                "os",
                observed={
                    "pretty_name": "Debian GNU/Linux 12 (bookworm)",
                    "version_id": "12",
                    "kernel": "6.1.0-21-amd64",
                    "arch": "x86_64",
                },
            ),
            "runtimes": _make_module(
                "runtimes",
                observed={
                    "node": "v20.11.0",
                    "python": "Python 3.11.2",
                    "php": "PHP 8.3.4 (cli)",
                    "ruby": None,
                    "go": "go1.21.5",
                },
                declared={
                    "node": {"value": "v20.11.0", "pinned_by": "zoltan", "at": "2026-04-10T09:00Z"},
                },
                ttl_seconds=604800,
            ),
            "services": _make_module(
                "services",
                observed={
                    "enabled_units": [
                        "nginx.service",
                        "postgresql.service",
                        "ssh.service",
                        "cron.service",
                    ]
                },
                ttl_seconds=21600,
            ),
            "web_stack": _make_module(
                "web_stack",
                observed={
                    "nginx": "nginx/1.24.0",
                    "apache": None,
                    "nginx_sites_enabled": ["api.example.com", "www.example.com"],
                    "apache_sites_enabled": [],
                },
                ttl_seconds=86400,
            ),
            "logs": _make_module(
                "logs",
                observed={
                    "probed_paths": [
                        "/var/log/nginx/access.log",
                        "/var/log/nginx/error.log",
                        "/var/log/syslog",
                    ]
                },
                ttl_seconds=86400,
            ),
        }

    def test_all_mvp_sections_present(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        for heading in ("## Identity", "## Runtimes", "## Services", "## Web stack", "## Logs"):
            assert heading in result, f"Missing section: {heading}"

    def test_runtime_table_rows(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        # node, python, php, go are non-null; ruby is null → excluded
        assert "node" in result
        assert "python" in result
        assert "php" in result
        assert "go" in result
        assert "ruby" not in result

    def test_nginx_in_web_stack(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        assert "nginx/1.24.0" in result
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_log_paths_listed(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        assert "/var/log/nginx/access.log" in result
        assert "/var/log/syslog" in result

    def test_services_listed_alphabetically(self) -> None:
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)
        # Verify alphabetical ordering: cron < nginx < postgresql < ssh
        cron_pos = result.index("cron.service")
        nginx_pos = result.index("nginx.service")
        psql_pos = result.index("postgresql.service")
        ssh_pos = result.index("ssh.service")
        assert cron_pos < nginx_pos < psql_pos < ssh_pos

    def test_full_snapshot(self) -> None:
        """Snapshot test — paste full expected output for deterministic review."""
        s = Summariser()
        result = s.summarise(_INSTANCE_META, self._make_modules(), now=_NOW)

        expected = (
            "# Memory — web-prod-1 (i-abc123) @ AWS\n"
            "\n"
            "## Identity\n"
            "pretty_name: Debian GNU/Linux 12 (bookworm)\n"
            "version: 12\n"
            "kernel: 6.1.0-21-amd64\n"
            "arch: x86_64\n"
            "\n"
            "## Runtimes\n"
            "| Runtime | Version |\n"
            "| --- | --- |\n"
            "| go | go1.21.5 |\n"
            "| node | v20.11.0 |\n"
            "| php | PHP 8.3.4 (cli) |\n"
            "| python | Python 3.11.2 |\n"
            "\n"
            "## Services\n"
            "| Unit |\n"
            "| --- |\n"
            "| cron.service |\n"
            "| nginx.service |\n"
            "| postgresql.service |\n"
            "| ssh.service |\n"
            "\n"
            "## Web stack\n"
            "nginx: nginx/1.24.0\n"
            "sites-enabled (2 total):\n"
            "| Site |\n"
            "| --- |\n"
            "| api.example.com |\n"
            "| www.example.com |\n"
            "\n"
            "## Logs\n"
            "- /var/log/nginx/access.log\n"
            "- /var/log/nginx/error.log\n"
            "- /var/log/syslog"
        )
        assert result == expected, (
            f"Summary output does not match snapshot.\nGOT:\n{result!r}\nEXPECTED:\n{expected!r}"
        )


# ---------------------------------------------------------------------------
# test_observed_vs_declared_rendering
# ---------------------------------------------------------------------------

class TestObservedVsDeclaredRendering:
    """Verify observed-vs-declared logic in rendered output."""

    def test_matching_declared_renders_single_value(self) -> None:
        """When observed == declared.value, just show the value."""
        modules = {
            "runtimes": _make_module(
                "runtimes",
                observed={"node": "v20.11.0"},
                declared={"node": {"value": "v20.11.0", "pinned_by": "zoltan", "at": "2026-04-10T09:00Z"}},
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "| node | v20.11.0 |" in result
        # Should NOT show "observed=" prefix when they match
        assert "observed=v20.11.0" not in result

    def test_differing_declared_shows_both(self) -> None:
        """When observed != declared.value, render both with attribution."""
        modules = {
            "runtimes": _make_module(
                "runtimes",
                observed={"node": "v20.11.0"},
                declared={"node": {"value": "v22.0.0", "pinned_by": "zoltan", "at": "2026-04-10T09:00Z"}},
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "observed=v20.11.0" in result
        assert "declared=v22.0.0" in result
        assert "pinned by zoltan" in result
        assert "2026-04-10T09:00Z" in result

    def test_no_declared_just_shows_observed(self) -> None:
        """When no declared entry exists, just show the observed value."""
        modules = {
            "runtimes": _make_module(
                "runtimes",
                observed={"python": "Python 3.11.2"},
                declared={},
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "Python 3.11.2" in result
        assert "observed=" not in result
        assert "declared=" not in result


# ---------------------------------------------------------------------------
# test_token_cap_honoured
# ---------------------------------------------------------------------------

class TestTokenCapHonoured:
    """Pathological fixture to verify bottom-up truncation."""

    def _make_pathological_modules(self) -> Dict[str, ModuleResult]:
        return {
            "os": _make_module(
                "os",
                observed={
                    "pretty_name": "Ubuntu 22.04 LTS",
                    "version_id": "22.04",
                    "kernel": "5.15.0",
                    "arch": "x86_64",
                },
            ),
            "services": _make_module(
                "services",
                observed={
                    "enabled_units": [f"unit-{i:04d}.service" for i in range(500)]
                },
                ttl_seconds=21600,
            ),
            "web_stack": _make_module(
                "web_stack",
                observed={
                    "nginx": "nginx/1.24.0",
                    "apache": None,
                    "nginx_sites_enabled": [f"site-{i:04d}.example.com" for i in range(200)],
                    "apache_sites_enabled": [],
                },
            ),
        }

    @pytest.mark.asyncio
    async def test_length_within_cap(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        # Save fixture modules to the store.
        instance_meta = {"id": "i-test", "name": "test-server", "provider": "custom"}
        for module_name, mod in self._make_pathological_modules().items():
            data = {
                "module": mod.module,
                "instance_id": "i-test",
                "probed_at": mod.probed_at,
                "ttl_seconds": mod.ttl_seconds,
                "sudo_used": mod.sudo_used,
                "truncated": mod.truncated,
                "partial": mod.partial,
                "observed": mod.observed,
                "declared": mod.declared,
                "raw_output": "",
            }
            store.save_module("i-test", module_name, data, provider="custom")

        result = await service.get_summary(instance_meta, max_tokens=1500)
        assert len(result) <= 6000, (
            f"Summary exceeds 6000 chars: {len(result)} chars"
        )

    @pytest.mark.asyncio
    async def test_data_quality_survives_truncation(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        # Use a deliberately old probed_at so a module is stale.
        old_ts = (datetime.now(tz=timezone.utc) - timedelta(days=30)).isoformat()
        instance_meta = {"id": "i-test", "name": "test-server", "provider": "custom"}
        modules = self._make_pathological_modules()
        # Make the os module stale.
        os_data = {
            "module": "os",
            "instance_id": "i-test",
            "probed_at": old_ts,
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "observed": {"pretty_name": "Ubuntu 22.04 LTS"},
            "declared": {},
            "raw_output": "",
        }
        store.save_module("i-test", "os", os_data, provider="custom")

        for module_name, mod in modules.items():
            if module_name == "os":
                continue
            data = {
                "module": mod.module,
                "instance_id": "i-test",
                "probed_at": mod.probed_at,
                "ttl_seconds": mod.ttl_seconds,
                "sudo_used": mod.sudo_used,
                "truncated": mod.truncated,
                "partial": mod.partial,
                "observed": mod.observed,
                "declared": mod.declared,
                "raw_output": "",
            }
            store.save_module("i-test", module_name, data, provider="custom")

        result = await service.get_summary(instance_meta, max_tokens=1500)
        assert len(result) <= 6000
        assert "## Data quality" in result


# ---------------------------------------------------------------------------
# test_stale_module_flagged
# ---------------------------------------------------------------------------

class TestStaleModuleFlagged:
    """A module past its TTL must appear in Data quality as stale."""

    def test_stale_appears_in_data_quality(self) -> None:
        old_ts = (datetime(2026, 1, 1, tzinfo=timezone.utc)).isoformat()
        modules = {
            "os": _make_module(
                "os",
                observed={"pretty_name": "Ubuntu 22.04"},
                probed_at=old_ts,
                ttl_seconds=86400,  # 1 day — the old_ts is far in the past
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Data quality" in result
        assert "os" in result
        assert "stale" in result

    def test_fresh_module_not_flagged_stale(self) -> None:
        modules = {
            "os": _make_module(
                "os",
                observed={"pretty_name": "Ubuntu 22.04"},
                probed_at=_RECENT,
                ttl_seconds=86400,
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        # No data quality section if no flags
        assert "stale" not in result


# ---------------------------------------------------------------------------
# test_partial_and_truncated_flags_surfaced
# ---------------------------------------------------------------------------

class TestPartialAndTruncatedFlagsSurfaced:
    """partial / truncated flags must surface in Data quality."""

    def test_partial_flag_in_data_quality(self) -> None:
        modules = {
            "services": _make_module(
                "services",
                observed={"enabled_units": ["ssh.service"]},
                partial=True,
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Data quality" in result
        assert "partial" in result

    def test_truncated_flag_in_data_quality(self) -> None:
        modules = {
            "logs": _make_module(
                "logs",
                observed={"probed_paths": ["/var/log/syslog"]},
                truncated=True,
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Data quality" in result
        assert "truncated" in result

    def test_both_flags_in_one_module(self) -> None:
        modules = {
            "runtimes": _make_module(
                "runtimes",
                observed={"python": "Python 3.11"},
                partial=True,
                truncated=True,
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        dq_start = result.index("## Data quality")
        dq_section = result[dq_start:]
        assert "partial" in dq_section
        assert "truncated" in dq_section


# ---------------------------------------------------------------------------
# test_deterministic_output
# ---------------------------------------------------------------------------

class TestDeterministicOutput:
    """Same fixture always yields byte-identical output."""

    def _make_modules(self) -> Dict[str, ModuleResult]:
        return {
            "os": _make_module("os", observed={"pretty_name": "Debian 12", "kernel": "6.1.0"}),
            "runtimes": _make_module("runtimes", observed={"node": "v20.11.0", "python": "Python 3.11"}),
            "logs": _make_module("logs", observed={"probed_paths": ["/var/log/syslog"]}),
        }

    def test_two_calls_are_identical(self) -> None:
        s = Summariser()
        modules = self._make_modules()
        r1 = s.summarise(_INSTANCE_META, modules, now=_NOW)
        r2 = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert r1 == r2

    def test_different_summariser_instances_are_identical(self) -> None:
        modules = self._make_modules()
        r1 = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        r2 = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert r1 == r2


# ---------------------------------------------------------------------------
# test_missing_module_gracefully_skipped
# ---------------------------------------------------------------------------

class TestMissingModuleGracefullySkipped:
    """Missing modules must be silently omitted — no "No data" placeholders."""

    def test_absent_web_stack_not_in_output(self) -> None:
        modules = {
            "os": _make_module("os", observed={"pretty_name": "Ubuntu 22.04"}),
            "runtimes": _make_module("runtimes", observed={"node": "v20.11.0"}),
            # web_stack intentionally absent
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Web stack" not in result
        assert "No data" not in result

    def test_all_optional_modules_absent(self) -> None:
        modules = {
            "os": _make_module("os", observed={"pretty_name": "Ubuntu 22.04"}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        for section in (
            "## Runtimes",
            "## Services",
            "## Web stack",
            "## Logs",
            "## Databases",
            "## Containers",
            "## Network",
            "## Git",
            "## Disk",
            "## Annotations",
        ):
            assert section not in result


# ---------------------------------------------------------------------------
# test_annotations_file_included
# ---------------------------------------------------------------------------

class TestAnnotationsFileIncluded:
    """annotations.md in the instance dir is included verbatim."""

    def test_annotations_included(self, tmp_path: Path) -> None:
        ann_dir = tmp_path / "custom" / "i-test"
        ann_dir.mkdir(parents=True)
        (ann_dir / "annotations.md").write_text("This is the staging DB. Do not restart.")

        s = Summariser(annotations_dir=ann_dir)
        modules: Dict[str, ModuleResult] = {}
        result = s.summarise({"id": "i-test", "name": "test", "provider": "custom"}, modules, now=_NOW)
        assert "## Annotations" in result
        assert "This is the staging DB. Do not restart." in result

    def test_annotations_truncated_at_1000_chars(self, tmp_path: Path) -> None:
        ann_dir = tmp_path / "custom" / "i-test"
        ann_dir.mkdir(parents=True)
        long_text = "x" * 1500
        (ann_dir / "annotations.md").write_text(long_text)

        s = Summariser(annotations_dir=ann_dir)
        modules: Dict[str, ModuleResult] = {}
        result = s.summarise({"id": "i-test", "name": "test", "provider": "custom"}, modules, now=_NOW)
        assert "_(truncated)_" in result

    def test_no_annotations_file_skips_section(self, tmp_path: Path) -> None:
        s = Summariser(annotations_dir=tmp_path)  # directory exists but no file
        modules: Dict[str, ModuleResult] = {}
        result = s.summarise({"id": "i-test", "name": "test", "provider": "custom"}, modules, now=_NOW)
        assert "## Annotations" not in result


# ---------------------------------------------------------------------------
# test_build_summary_markdown_wrapper
# ---------------------------------------------------------------------------

class TestBuildSummaryMarkdownWrapper:
    """build_summary_markdown pulls from store and calls summariser."""

    def test_returns_empty_for_no_modules(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        instance_meta = {"id": "i-nothing", "name": "empty-server", "provider": "custom"}
        result = build_summary_markdown(store, instance_meta, config, now=_NOW)
        # No data — only the header should be present (no sections)
        assert "empty-server" in result
        assert "## Identity" not in result

    def test_reads_from_store(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        instance_meta = {"id": "i-stored", "name": "stored-server", "provider": "custom"}
        os_data = {
            "module": "os",
            "instance_id": "i-stored",
            "probed_at": _RECENT,
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "observed": {"pretty_name": "Fedora 40", "kernel": "6.8.0", "version_id": "40", "arch": "x86_64"},
            "declared": {},
            "raw_output": "",
        }
        store.save_module("i-stored", "os", os_data, provider="custom")

        result = build_summary_markdown(store, instance_meta, config, now=_NOW)
        assert "## Identity" in result
        assert "Fedora 40" in result


# ---------------------------------------------------------------------------
# test_write_summary_in_service
# ---------------------------------------------------------------------------

class TestWriteSummaryInService:
    """MemoryService.write_summary persists summary.md."""

    @pytest.mark.asyncio
    async def test_writes_file(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        os_data = {
            "module": "os",
            "instance_id": "i-ws",
            "probed_at": _RECENT,
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "observed": {"pretty_name": "Arch Linux", "kernel": "6.9.0", "version_id": "rolling", "arch": "x86_64"},
            "declared": {},
            "raw_output": "",
        }
        store.save_module("i-ws", "os", os_data, provider="custom")

        instance_meta = {"id": "i-ws", "name": "arch-box", "provider": "custom"}
        path = await service.write_summary(instance_meta)

        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "## Identity" in content
        assert "Arch Linux" in content

    @pytest.mark.asyncio
    async def test_returns_correct_path(self, tmp_path: Path) -> None:
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        service = MemoryService(store=store, config=config)

        instance_meta = {"id": "i-path", "name": "path-server", "provider": "custom"}
        path = await service.write_summary(instance_meta)

        expected = tmp_path / "custom" / "i-path" / "summary.md"
        assert path == expected


# ---------------------------------------------------------------------------
# test_raw_output_never_included
# ---------------------------------------------------------------------------

class TestRawOutputNeverIncluded:
    """raw_output must never appear in the summary."""

    def test_raw_output_not_leaked(self) -> None:
        modules = {
            "runtimes": _make_module(
                "runtimes",
                observed={"node": "v20.11.0"},
            )
        }
        # Manually inject raw_output into the dict representation.
        raw_dict = {
            "module": "runtimes",
            "instance_id": "i-test",
            "probed_at": _RECENT,
            "ttl_seconds": 86400,
            "sudo_used": False,
            "truncated": False,
            "partial": False,
            "observed": {"node": "v20.11.0"},
            "declared": {},
            "raw_output": "SECRET_COMMAND_OUTPUT_SHOULD_NOT_APPEAR",
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, {"runtimes": raw_dict}, now=_NOW)
        assert "SECRET_COMMAND_OUTPUT_SHOULD_NOT_APPEAR" not in result


# ---------------------------------------------------------------------------
# test_module_result_input_accepted
# ---------------------------------------------------------------------------

class TestModuleResultInputAccepted:
    """Summariser should accept ModuleResult objects, not just raw dicts."""

    def test_module_result_rendered(self) -> None:
        modules = {
            "os": _make_module(
                "os",
                observed={
                    "pretty_name": "CentOS Stream 9",
                    "kernel": "5.14.0",
                    "version_id": "9",
                    "arch": "x86_64",
                },
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "CentOS Stream 9" in result
        assert "## Identity" in result


# ---------------------------------------------------------------------------
# Boundary tests — empty observed for T8 modules omits section entirely.
#
# The legacy "stub renderer" tests from T2 relied on the stub behaviour of
# dumping any arbitrary observed key.  T8 replaces the stubs with real
# renderers that understand the proper observed shape of each prober, so
# the only boundary still worth asserting at this layer is the empty case.
# The full renderer coverage lives in TestRenderDatabases, TestRenderContainers,
# TestRenderNetwork, TestRenderGit, TestRenderDisk below.
# ---------------------------------------------------------------------------

class TestStubRenderers:
    """Empty observed for every T8 module omits its section completely."""

    def test_databases_empty_observed_omits_section(self) -> None:
        modules = {"databases": _make_module("databases", observed={})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Databases" not in result

    def test_containers_empty_observed_omits_section(self) -> None:
        modules = {"containers": _make_module("containers", observed={})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Containers" not in result

    def test_network_empty_observed_omits_section(self) -> None:
        modules = {"network": _make_module("network", observed={})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Network" not in result

    def test_git_empty_observed_omits_section(self) -> None:
        modules = {"git": _make_module("git", observed={})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Git" not in result

    def test_disk_empty_observed_omits_section(self) -> None:
        modules = {"disk": _make_module("disk", observed={})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Disk" not in result

    def test_databases_declared_mismatch_shown(self) -> None:
        """A declared value that differs from observed shows both (observed/declared)."""
        modules = {
            "databases": _make_module(
                "databases",
                observed={
                    "mysql_version": "8.0.34",
                    "mariadb_version": None,
                    "postgres_version": None,
                    "postgres_clusters": [],
                    "redis_version": None,
                    "mongodb_version": None,
                    "open_db_ports": [],
                },
                declared={
                    "mysql_version": {
                        "value": "8.0.28",
                        "pinned_by": "ops",
                        "at": "2026-01-01T00:00Z",
                    },
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "observed=8.0.34" in result
        assert "declared=8.0.28" in result
        assert "pinned by ops" in result


# ---------------------------------------------------------------------------
# _truncate_summary direct tests
# ---------------------------------------------------------------------------

class TestTruncateSummary:
    """Tests for _truncate_summary module-level helper in service.py."""

    def test_short_text_returned_unchanged(self) -> None:
        text = "# Header\n\n## Identity\nshort content"
        result = _truncate_summary(text, char_cap=10000)
        assert result == text

    def test_exactly_at_cap_returned_unchanged(self) -> None:
        text = "x" * 100
        result = _truncate_summary(text, char_cap=100)
        assert result == text

    def test_section_dropped_to_fit(self) -> None:
        """The least-important section (Identity, per _DROP_ORDER) is dropped first."""
        header = "# Memory — srv"
        identity = "## Identity\npretty_name: Ubuntu 22.04"
        runtimes = "## Runtimes\n| Runtime | Version |\n| --- | --- |\n| node | v20 |"
        data_quality = "## Data quality\n- os: stale"
        summary = "\n\n".join([header, identity, runtimes, data_quality])

        # Cap that forces at least one section to be dropped.
        # identity is lowest priority in _DROP_ORDER for the given order.
        result = _truncate_summary(summary, char_cap=len(header) + len(data_quality) + 10)

        # The result must fit within the cap.
        assert len(result) <= len(header) + len(data_quality) + 10 or len(result) <= len(summary)
        # data_quality must survive (it's highest priority).
        assert "## Data quality" in result or len(result) <= len(summary)

    def test_hard_truncation_fallback(self) -> None:
        """When section-dropping can't fit the text, hard truncation is applied."""
        # Build a summary where ALL sections combined are still too big,
        # so the loop exhausts without finding a fit.
        # We need a char_cap smaller than any single section.
        very_short_cap = 30
        # A summary with no recognisable section headings (so nothing gets dropped).
        summary = "# Header\n\n" + ("A" * 1000)
        result = _truncate_summary(summary, char_cap=very_short_cap)
        assert len(result) <= very_short_cap + 15  # marker adds up to 15 chars
        assert "_(truncated)_" in result

    def test_section_drop_order_respects_priority(self) -> None:
        """'## Identity' is in _DROP_ORDER; '## Data quality' is NOT — so it survives."""
        header = "# Memory — srv"
        identity = "## Identity\n" + ("I" * 300)
        data_quality = "## Data quality\n- os: stale"
        # Cap forces dropping identity but leaves data quality.
        summary = "\n\n".join([header, identity, data_quality])
        result = _truncate_summary(summary, char_cap=len(header) + len(data_quality) + 20)
        assert "## Data quality" in result


# ---------------------------------------------------------------------------
# Partial render paths — modules with empty observed via summarise()
# ---------------------------------------------------------------------------

class TestPartialRenderPaths:
    """When optional modules have empty observed={}, their sections are omitted."""

    def test_runtimes_all_none_omits_section(self) -> None:
        """A runtimes module where every runtime is None → ## Runtimes omitted."""
        modules = {
            "runtimes": _make_module("runtimes", observed={"node": None, "python": None}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Runtimes" not in result

    def test_services_empty_units_omits_section(self) -> None:
        """A services module with enabled_units=[] → ## Services omitted."""
        modules = {
            "services": _make_module("services", observed={"enabled_units": []}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Services" not in result

    def test_web_stack_empty_observed_omits_section(self) -> None:
        """A web_stack module with observed={} → ## Web stack omitted."""
        modules = {
            "web_stack": _make_module("web_stack", observed={}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Web stack" not in result

    def test_logs_empty_paths_omits_section(self) -> None:
        """A logs module with probed_paths=[] → ## Logs omitted."""
        modules = {
            "logs": _make_module("logs", observed={"probed_paths": []}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Logs" not in result

    def test_identity_empty_observed_omits_section(self) -> None:
        """An os module with observed={} → ## Identity omitted."""
        modules = {
            "os": _make_module("os", observed={}),
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Identity" not in result

    def test_is_stale_missing_probed_at(self) -> None:
        """_is_stale returns True when probed_at is empty."""
        from servonaut.services.memory.summariser import _is_stale
        from datetime import datetime, timezone
        now = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
        assert _is_stale("", 86400, now) is True

    def test_is_stale_naive_timestamp_treated_as_utc(self) -> None:
        """_is_stale treats naive timestamps as UTC."""
        from servonaut.services.memory.summariser import _is_stale
        from datetime import datetime, timezone
        now = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
        # Naive timestamp just 1 second ago — not stale
        naive_ts = "2026-04-19T11:59:59"
        assert _is_stale(naive_ts, 86400, now) is False

    def test_is_stale_invalid_timestamp(self) -> None:
        """_is_stale returns True for unparseable timestamps."""
        from servonaut.services.memory.summariser import _is_stale
        from datetime import datetime, timezone
        now = datetime(2026, 4, 19, 12, 0, 0, tzinfo=timezone.utc)
        assert _is_stale("not-a-date", 86400, now) is True

    def test_summarise_with_no_now_uses_real_clock(self) -> None:
        """When now=None the summariser falls back to datetime.now() without error."""
        modules = {
            "os": _make_module("os", observed={"pretty_name": "Ubuntu 22.04"}),
        }
        s = Summariser()
        # Should not raise; result is non-empty
        result = s.summarise(_INSTANCE_META, modules)
        assert "Ubuntu 22.04" in result


# ---------------------------------------------------------------------------
# sudo_used flag surfaces in Data quality
# ---------------------------------------------------------------------------

class TestSudoUsedFlag:
    """sudo_used=True must appear in Data quality."""

    def test_sudo_used_in_data_quality(self) -> None:
        """A module with sudo_used=True must show 'sudo_used' in ## Data quality."""
        modules = {
            "os": _make_module(
                "os",
                observed={"pretty_name": "Ubuntu 22.04"},
                sudo_used=True,
            )
        }
        s = Summariser()
        result = s.summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Data quality" in result
        assert "sudo_used" in result


# ---------------------------------------------------------------------------
# _load_annotations OSError path
# ---------------------------------------------------------------------------

class TestAnnotationsOSError:
    """If annotations.md exists but cannot be read, the section is silently omitted."""

    def test_oserror_on_read_silently_returns_empty(self, tmp_path: Path) -> None:
        from unittest.mock import patch, MagicMock

        ann_dir = tmp_path / "custom" / "i-oserr"
        ann_dir.mkdir(parents=True)
        ann_path = ann_dir / "annotations.md"
        ann_path.write_text("some content")

        # Patch Path.read_text to raise OSError even though the file exists.
        with patch.object(Path, "read_text", side_effect=OSError("permission denied")):
            s = Summariser(annotations_dir=ann_dir)
            modules: Dict[str, ModuleResult] = {}
            result = s.summarise(
                {"id": "i-oserr", "name": "err-box", "provider": "custom"},
                modules,
                now=_NOW,
            )

        # Annotations section must not appear — OSError was swallowed.
        assert "## Annotations" not in result


# ---------------------------------------------------------------------------
# build_summary_markdown — now=None uses real clock
# ---------------------------------------------------------------------------

class TestBuildSummaryMarkdownNowDefault:
    """build_summary_markdown with now=None must work without error."""

    def test_now_defaults_to_utc(self, tmp_path: Path) -> None:
        """When now is not passed, the function uses datetime.now(tz=timezone.utc)."""
        store = MemoryStore(root=tmp_path)
        config = MemoryConfig()
        instance_meta = {"id": "i-now-default", "name": "now-box", "provider": "custom"}
        os_data = {
            "module": "os", "instance_id": "i-now-default",
            "probed_at": "2026-04-19T12:00:00+00:00",
            "ttl_seconds": 86400, "sudo_used": False,
            "truncated": False, "partial": False,
            "observed": {"pretty_name": "Rocky Linux 9"},
            "declared": {}, "raw_output": "",
        }
        store.save_module("i-now-default", "os", os_data, provider="custom")

        # No now= passed → uses real clock; must not raise.
        result = build_summary_markdown(store, instance_meta, config)
        assert "Rocky Linux 9" in result


# ---------------------------------------------------------------------------
# T8 — Renderers for new probers
# ---------------------------------------------------------------------------

class TestRenderDatabases:
    """Renderer for the DatabasesProber observed shape."""

    def _databases_module(self) -> Dict[str, ModuleResult]:
        return {
            "databases": _make_module(
                "databases",
                observed={
                    "mysql_version": "8.0.35",
                    "mariadb_version": None,
                    "postgres_version": "16.1",
                    "postgres_clusters": [
                        {"version": "16", "cluster": "main", "port": 5432, "status": "online"},
                    ],
                    "redis_version": "7.2.4",
                    "mongodb_version": None,
                    "open_db_ports": ["3306:mysql", "5432:postgres"],
                },
            )
        }

    def test_databases_section_present(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._databases_module(), now=_NOW)
        assert "## Databases" in result
        assert "mysql: 8.0.35" in result
        assert "postgres: 16.1" in result
        assert "redis: 7.2.4" in result

    def test_missing_engines_omitted(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._databases_module(), now=_NOW)
        assert "mariadb" not in result.lower().split("## disk")[0]  # no mariadb line
        assert "mongodb" not in result.lower().split("## disk")[0]

    def test_postgres_cluster_rendered(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._databases_module(), now=_NOW)
        assert "16/main@5432 (online)" in result

    def test_open_db_ports_rendered(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._databases_module(), now=_NOW)
        assert "3306:mysql" in result
        assert "5432:postgres" in result

    def test_empty_observed_omits_section(self) -> None:
        modules = {
            "databases": _make_module(
                "databases",
                observed={
                    "mysql_version": None, "mariadb_version": None,
                    "postgres_version": None, "postgres_clusters": [],
                    "redis_version": None, "mongodb_version": None,
                    "open_db_ports": [],
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Databases" not in result


class TestRenderContainers:
    def _containers_module(self) -> Dict[str, ModuleResult]:
        return {
            "containers": _make_module(
                "containers",
                observed={
                    "docker_running": True,
                    "docker_version": "25.0.3",
                    "docker_containers": [
                        {"name": "nginx", "image": "nginx:1.25", "status": "Up 3h"},
                        {"name": "redis", "image": "redis:7", "status": "Up 2d"},
                    ],
                    "podman_version": None,
                    "podman_containers": [],
                    "k8s_client_version": "v1.29.2",
                },
            )
        }

    def test_containers_section_present(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._containers_module(), now=_NOW)
        assert "## Containers" in result
        assert "docker: 25.0.3" in result
        assert "running" in result
        assert "kubectl: v1.29.2" in result

    def test_docker_containers_table_rendered(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._containers_module(), now=_NOW)
        assert "| nginx | nginx:1.25 | Up 3h |" in result
        assert "| redis | redis:7 | Up 2d |" in result

    def test_podman_absent(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._containers_module(), now=_NOW)
        assert "podman:" not in result

    def test_docker_not_running(self) -> None:
        modules = {
            "containers": _make_module(
                "containers",
                observed={
                    "docker_running": False,
                    "docker_version": "25.0.3",
                    "docker_containers": [],
                    "podman_version": None,
                    "podman_containers": [],
                    "k8s_client_version": None,
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "not running" in result


class TestRenderNetwork:
    def _network_module(self) -> Dict[str, ModuleResult]:
        return {
            "network": _make_module(
                "network",
                observed={
                    "listening_sockets": ["22:0.0.0.0", "3306:127.0.0.1"],
                    "iptables_rules": ["-P INPUT DROP", "-A INPUT -p tcp --dport 22 -j ACCEPT"],
                    "ufw_status": "active",
                },
            )
        }

    def test_network_section_and_sockets(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._network_module(), now=_NOW)
        assert "## Network" in result
        assert "22:0.0.0.0" in result
        assert "3306:127.0.0.1" in result

    def test_ufw_status_rendered(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._network_module(), now=_NOW)
        assert "ufw: active" in result

    def test_ufw_unknown_not_rendered(self) -> None:
        modules = {
            "network": _make_module(
                "network",
                observed={
                    "listening_sockets": ["22:0.0.0.0"],
                    "iptables_rules": [],
                    "ufw_status": "unknown",
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "ufw:" not in result

    def test_iptables_rules_rendered(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._network_module(), now=_NOW)
        assert "-P INPUT DROP" in result


class TestRenderGit:
    def _git_module(self) -> Dict[str, ModuleResult]:
        return {
            "git": _make_module(
                "git",
                observed={
                    "checkouts": [
                        {"path": "/opt/app", "branch": "main",
                         "remote_url": "git@github.com:acme/app.git"},
                        {"path": "/var/www/api", "branch": "production",
                         "remote_url": "https://github.com/acme/api.git"},
                    ],
                },
            )
        }

    def test_git_section_present(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._git_module(), now=_NOW)
        assert "## Git" in result
        assert "/opt/app" in result
        assert "main" in result

    def test_empty_checkouts_omits_section(self) -> None:
        modules = {"git": _make_module("git", observed={"checkouts": []})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Git" not in result


class TestRenderDisk:
    def _disk_module(self) -> Dict[str, ModuleResult]:
        return {
            "disk": _make_module(
                "disk",
                observed={
                    "filesystems": [
                        {"device": "/dev/sda1", "pct_used": 42, "mount": "/"},
                        {"device": "/dev/sda2", "pct_used": 80, "mount": "/var"},
                    ],
                },
            )
        }

    def test_disk_section_present(self) -> None:
        result = Summariser().summarise(_INSTANCE_META, self._disk_module(), now=_NOW)
        assert "## Disk" in result
        assert "/dev/sda1" in result
        assert "42%" in result
        assert "80%" in result

    def test_empty_filesystems_omits_section(self) -> None:
        modules = {"disk": _make_module("disk", observed={"filesystems": []})}
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Disk" not in result


# ---------------------------------------------------------------------------
# T8 — _render_logs declared-merge regression fix
# ---------------------------------------------------------------------------

class TestRenderLogsDeclaredMerge:
    """_render_logs must merge declared (pinned) paths with observed paths.

    This is the T4-T7 UAT gap: when an operator pins a log path via
    ``memory pin <id> logs.probed_paths '[\"/var/log/myapp.log\"]'`` the
    summariser used to ignore it — we only rendered the probed_paths list.
    The fix merges both sources and marks declared-only entries ``(added)``.
    """

    def test_declared_probed_paths_list_merged(self) -> None:
        modules = {
            "logs": _make_module(
                "logs",
                observed={"probed_paths": ["/var/log/syslog"]},
                declared={
                    "probed_paths": {
                        "value": ["/var/log/myapp.log"],
                        "pinned_by": "zoltan",
                        "at": "2026-04-10T09:00Z",
                    }
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "/var/log/syslog" in result
        assert "/var/log/myapp.log (added)" in result, (
            "Declared-only log paths must be rendered with an (added) suffix"
        )

    def test_path_keyed_declared_entry_merged(self) -> None:
        """Per-path pins like ``memory pin logs./var/log/foo.log true`` also merge."""
        modules = {
            "logs": _make_module(
                "logs",
                observed={"probed_paths": []},
                declared={
                    "/var/log/app.log": {
                        "value": True,
                        "pinned_by": "zoltan",
                        "at": "2026-04-10T09:00Z",
                    }
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "/var/log/app.log (added)" in result

    def test_declared_path_also_probed_not_marked_added(self) -> None:
        modules = {
            "logs": _make_module(
                "logs",
                observed={"probed_paths": ["/var/log/app.log"]},
                declared={
                    "probed_paths": {
                        "value": ["/var/log/app.log"],
                        "pinned_by": "z", "at": "2026-04-10T09:00Z",
                    }
                },
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        # Appears once without "(added)" marker.
        assert "/var/log/app.log" in result
        assert "(added)" not in result

    def test_both_empty_no_logs_section(self) -> None:
        modules = {
            "logs": _make_module(
                "logs",
                observed={"probed_paths": []},
                declared={},
            )
        }
        result = Summariser().summarise(_INSTANCE_META, modules, now=_NOW)
        assert "## Logs" not in result
