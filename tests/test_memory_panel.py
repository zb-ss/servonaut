"""Tests for the cached-memory snapshot renderer (utils/memory_panel.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from servonaut.utils.memory_panel import format_runtime, human_age, render_memory_panel


def _iso_ago(**kwargs) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(**kwargs)).isoformat()


class TestHumanAge:
    def test_empty_returns_question(self):
        assert human_age("") == "?"

    def test_minutes(self):
        assert human_age(_iso_ago(minutes=5)) == "5m ago"

    def test_hours(self):
        assert human_age(_iso_ago(hours=2)) == "2h ago"

    def test_days(self):
        assert human_age(_iso_ago(days=3)) == "3d ago"

    def test_just_now(self):
        assert human_age(_iso_ago(seconds=5)) == "just now"

    def test_garbage_returns_question(self):
        assert human_age("not-a-date") == "?"


class TestFormatRuntime:
    """Each runtime reads "<name> <version>", its name shown once."""

    @pytest.mark.parametrize(
        ("runtime", "stored", "shown"),
        [
            # What the runtimes probe stores: each command's own output.
            ("python", "Python 3.11.2", "Python 3.11.2"),
            ("node", "v20.11.1", "Node 20.11.1"),
            ("php", "PHP 8.2.7", "PHP 8.2.7"),
            ("go", "go1.22.1", "Go 1.22.1"),
            ("ruby", "ruby 3.2.2", "Ruby 3.2.2"),
            # A bare version (older snapshots, other writers) gets the name too.
            ("python", "3.12.3", "Python 3.12.3"),
            ("node", "20.11", "Node 20.11"),
        ],
    )
    def test_name_then_version(self, runtime, stored, shown):
        assert format_runtime(runtime, stored) == shown

    def test_panel_line_names_each_runtime_once(self):
        modules = {
            "runtimes": {
                "observed": {
                    "python": "Python 3.11.2",
                    "node": "v20.11.1",
                    "php": "PHP 8.2.7",
                    "go": "go1.22.1",
                    "ruby": "ruby 3.2.2",
                },
                "probed_at": _iso_ago(minutes=10),
            },
        }
        out = render_memory_panel(modules)
        runtime_line = next(line for line in out.splitlines() if "Runtime" in line)
        assert runtime_line.endswith(
            "Python 3.11.2 · Node 20.11.1 · PHP 8.2.7 · Go 1.22.1 · Ruby 3.2.2"
        )

    def test_markup_in_a_version_is_escaped(self):
        modules = {
            "runtimes": {
                "observed": {"python": "Python [bold]3[/bold]"},
                "probed_at": _iso_ago(minutes=1),
            },
        }
        assert "Python \\[bold]3\\[/bold]" in render_memory_panel(modules)


class TestRenderMemoryPanel:
    def test_empty_shows_build_cta(self):
        out = render_memory_panel({})
        assert "No memory cached" in out
        assert "[b]M[/b]" in out

    def test_renders_os_and_disk(self):
        modules = {
            "os": {
                "observed": {"pretty_name": "Ubuntu 24.04 LTS", "kernel": "6.8.0-31-generic"},
                "probed_at": _iso_ago(hours=2),
            },
            "disk": {
                "observed": {"pct_used": "61%", "mount": "/"},
                "probed_at": _iso_ago(hours=2),
            },
        }
        out = render_memory_panel(modules)
        assert "Ubuntu 24.04 LTS" in out
        assert "6.8.0-31-generic" in out
        assert "61%" in out
        assert "2h ago" in out

    def test_partial_flag_shown(self):
        modules = {
            "os": {"observed": {"pretty_name": "Debian 12"}, "probed_at": _iso_ago(minutes=1), "partial": True},
        }
        out = render_memory_panel(modules)
        assert "partial" in out

    def test_web_db_runtime_containers(self):
        modules = {
            "web_stack": {"observed": {"nginx": "1.24.0"}, "probed_at": _iso_ago(minutes=10)},
            "databases": {"observed": {"postgres_version": "16.2"}, "probed_at": _iso_ago(minutes=10)},
            "runtimes": {"observed": {"python": "3.12.3", "node": "20.11"}, "probed_at": _iso_ago(minutes=10)},
            "containers": {"observed": {"docker_version": "26.0.0", "docker_running": "6"}, "probed_at": _iso_ago(minutes=10)},
        }
        out = render_memory_panel(modules)
        assert "nginx 1.24.0" in out
        assert "postgres 16.2" in out
        assert "Python 3.12.3" in out
        assert "Node 20.11" in out
        assert "26.0.0" in out
        assert "6 running" in out

    def test_rich_markup_in_observed_value_is_escaped(self):
        # A server name / value containing markup must not break rendering.
        modules = {
            "os": {"observed": {"pretty_name": "Evil [bold]OS[/bold]"}, "probed_at": _iso_ago(minutes=1)},
        }
        out = render_memory_panel(modules)
        # The raw markup should be escaped, not passed through verbatim.
        assert "Evil \\[bold]OS\\[/bold]" in out

    def test_modules_present_but_no_known_facts(self):
        modules = {
            "logs": {"observed": {"some_unknown_key": "x"}, "probed_at": _iso_ago(minutes=1)},
        }
        out = render_memory_panel(modules)
        assert "Server Memory" in out
        assert "No structured facts" in out
