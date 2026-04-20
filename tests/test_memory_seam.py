"""Cross-seam tests: prober _parse → ModuleResult → Summariser.

These tests drive a real prober ``_parse()`` on a hand-written realistic
stdout fixture (matching the format produced by ``ModuleProber.probe()``),
wrap the result in a ``ModuleResult``, feed it through ``Summariser.summarise``,
and assert expected values appear in the rendered output.

They exist specifically to catch prober↔summariser key-name drift, which is
the class of bug that caused the ## Web stack and OS version fields to silently
render empty in production (CRITICAL-1 and CRITICAL-2).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from servonaut.services.memory.interfaces import ModuleResult
from servonaut.services.memory.modules.os import OSProber
from servonaut.services.memory.modules.runtimes import RuntimesProber
from servonaut.services.memory.modules.web_stack import WebStackProber
from servonaut.services.memory.summariser import Summariser

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 4, 20, tzinfo=timezone.utc)
_INSTANCE_META = {"id": "i-seam-test", "name": "seam-server", "provider": "AWS"}


def _make_result(module_name: str, observed: dict, prober_ttl: int = 86400) -> ModuleResult:
    return ModuleResult(
        module=module_name,
        instance_id="i-seam-test",
        observed=observed,
        declared={},
        sudo_used=False,
        truncated=False,
        partial=False,
        probed_at=_NOW.isoformat(),
        ttl_seconds=prober_ttl,
        raw_output="",
    )


# ---------------------------------------------------------------------------
# The format that ModuleProber.probe() builds:
#   raw_parts.append(f"{cmd} →\n{stdout}\n")
#   raw_output = "\n".join(raw_parts)
# So the raw_output looks like: "<cmd> →\n<stdout>\n\n<cmd2> →\n<stdout2>\n"
# ---------------------------------------------------------------------------

def _build_raw_output(*cmd_stdout_pairs: tuple[str, str]) -> str:
    """Build a raw_output string in the exact format produced by ModuleProber.probe()."""
    parts = [f"{cmd} →\n{stdout}\n" for cmd, stdout in cmd_stdout_pairs]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# OS seam: _parse → summariser
# ---------------------------------------------------------------------------

class TestOsSeam:
    """Feed a realistic /etc/os-release + uname stdout through OSProber._parse
    then assert the identity section renders correctly in the summary."""

    _OS_RELEASE = (
        'NAME="Ubuntu"\n'
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'ID=ubuntu\n'
        'VERSION_ID="22.04"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
    )
    _UNAME = "5.15.0-91-generic x86_64 x86_64 x86_64 GNU/Linux\n"

    def _parsed_result(self) -> ModuleResult:
        raw_output = _build_raw_output(
            ("cat /etc/os-release", self._OS_RELEASE),
            ("uname -rma", self._UNAME),
        )
        prober = OSProber()
        observed = prober._parse(raw_output)
        return _make_result("os", observed, prober.ttl_seconds)

    def test_version_id_appears_in_summary(self) -> None:
        """version_id (22.04) must appear in the Identity section."""
        result = self._parsed_result()
        # Confirm the prober emits version_id (not version).
        assert "version_id" in result.observed, (
            f"OSProber._parse did not emit 'version_id'. Keys: {list(result.observed)}"
        )
        assert result.observed["version_id"] == "22.04"

        summary = Summariser().summarise(_INSTANCE_META, {"os": result}, now=_NOW)
        assert "22.04" in summary, (
            f"OS version_id '22.04' not found in summary.\n{summary}"
        )

    def test_pretty_name_appears_in_summary(self) -> None:
        """pretty_name must be present in the identity section."""
        result = self._parsed_result()
        summary = Summariser().summarise(_INSTANCE_META, {"os": result}, now=_NOW)
        assert "Ubuntu 22.04.3 LTS" in summary, (
            f"pretty_name not found in summary.\n{summary}"
        )

    def test_identity_section_present(self) -> None:
        """## Identity section heading must be present."""
        result = self._parsed_result()
        summary = Summariser().summarise(_INSTANCE_META, {"os": result}, now=_NOW)
        assert "## Identity" in summary


# ---------------------------------------------------------------------------
# Web stack seam: _parse → summariser
# ---------------------------------------------------------------------------

class TestWebStackSeam:
    """Feed realistic nginx/apache version + sites-enabled stdout through
    WebStackProber._parse then assert the web stack section renders correctly."""

    # nginx -v writes to stderr; we redirect stderr to stdout via 2>&1.
    _NGINX_V = "nginx version: nginx/1.24.0\n"
    _APACHE_V = ""  # apache not installed
    _NGINX_SITES = "api.example.com\nwww.example.com\n"
    _APACHE_SITES = ""  # no apache sites

    def _parsed_result(self) -> ModuleResult:
        raw_output = _build_raw_output(
            ("nginx -v 2>&1", self._NGINX_V),
            ("apache2 -v 2>/dev/null || httpd -v 2>/dev/null", self._APACHE_V),
            ("ls /etc/nginx/sites-enabled/ 2>/dev/null", self._NGINX_SITES),
            ("ls /etc/apache2/sites-enabled/ 2>/dev/null", self._APACHE_SITES),
        )
        prober = WebStackProber()
        observed = prober._parse(raw_output)
        return _make_result("web_stack", observed, prober.ttl_seconds)

    def test_nginx_version_appears_in_summary(self) -> None:
        """nginx version string must appear in the ## Web stack section."""
        result = self._parsed_result()
        # Confirm prober emits "nginx" key (not "nginx_version").
        assert "nginx" in result.observed, (
            f"WebStackProber._parse did not emit 'nginx'. Keys: {list(result.observed)}"
        )
        assert result.observed["nginx"] == "nginx/1.24.0"

        summary = Summariser().summarise(_INSTANCE_META, {"web_stack": result}, now=_NOW)
        assert "nginx" in summary.lower(), (
            f"'nginx' not found in summary.\n{summary}"
        )
        assert "1.24.0" in summary, (
            f"nginx version '1.24.0' not found in summary.\n{summary}"
        )

    def test_sites_appear_in_summary(self) -> None:
        """Site names from nginx_sites_enabled must appear in the summary."""
        result = self._parsed_result()
        # Confirm prober emits nginx_sites_enabled key (not sites_enabled).
        assert "nginx_sites_enabled" in result.observed, (
            f"WebStackProber._parse did not emit 'nginx_sites_enabled'. "
            f"Keys: {list(result.observed)}"
        )
        assert "api.example.com" in result.observed["nginx_sites_enabled"]

        summary = Summariser().summarise(_INSTANCE_META, {"web_stack": result}, now=_NOW)
        assert "api.example.com" in summary, (
            f"'api.example.com' not found in summary.\n{summary}"
        )
        assert "www.example.com" in summary, (
            f"'www.example.com' not found in summary.\n{summary}"
        )

    def test_web_stack_section_present(self) -> None:
        """## Web stack section heading must be present."""
        result = self._parsed_result()
        summary = Summariser().summarise(_INSTANCE_META, {"web_stack": result}, now=_NOW)
        assert "## Web stack" in summary

    def test_apache_and_nginx_sites_merged(self) -> None:
        """When both nginx and apache sites exist, they are merged in the summary."""
        raw_output = _build_raw_output(
            ("nginx -v 2>&1", "nginx version: nginx/1.24.0\n"),
            ("apache2 -v 2>/dev/null || httpd -v 2>/dev/null", "Server version: Apache/2.4.58\n"),
            ("ls /etc/nginx/sites-enabled/ 2>/dev/null", "nginx-site.com\n"),
            ("ls /etc/apache2/sites-enabled/ 2>/dev/null", "apache-site.com\n"),
        )
        prober = WebStackProber()
        observed = prober._parse(raw_output)
        result = _make_result("web_stack", observed, prober.ttl_seconds)

        summary = Summariser().summarise(_INSTANCE_META, {"web_stack": result}, now=_NOW)
        assert "nginx-site.com" in summary
        assert "apache-site.com" in summary
        assert "nginx" in summary.lower()
        assert "Apache" in summary


# ---------------------------------------------------------------------------
# Runtimes seam: _parse → summariser
# ---------------------------------------------------------------------------

class TestRuntimesSeam:
    """Feed a realistic multi-runtime stdout through RuntimesProber._parse
    then assert the runtimes table renders correctly."""

    def _parsed_result(self) -> ModuleResult:
        raw_output = _build_raw_output(
            ("node -v 2>/dev/null", "v20.11.0\n"),
            ("python3 -V 2>/dev/null", "Python 3.11.2\n"),
            ("php -v 2>/dev/null | head -1", "PHP 8.3.4 (cli) (built: ...)\n"),
            ("ruby -v 2>/dev/null", ""),   # ruby not installed
            ("go version 2>/dev/null", "go version go1.21.5 linux/amd64\n"),
        )
        prober = RuntimesProber()
        observed = prober._parse(raw_output)
        return _make_result("runtimes", observed, prober.ttl_seconds)

    def test_installed_runtimes_in_summary(self) -> None:
        """Installed runtimes (non-None) must appear in the runtimes table."""
        result = self._parsed_result()
        assert result.observed.get("node") == "v20.11.0"
        assert result.observed.get("python") is not None
        assert result.observed.get("go") is not None

        summary = Summariser().summarise(_INSTANCE_META, {"runtimes": result}, now=_NOW)
        assert "## Runtimes" in summary
        assert "v20.11.0" in summary, f"node version not in summary.\n{summary}"
        assert "Python" in summary, f"python version not in summary.\n{summary}"
        assert "go1.21.5" in summary, f"go version not in summary.\n{summary}"

    def test_absent_runtime_excluded_from_summary(self) -> None:
        """Runtimes with None value must not appear in the table."""
        result = self._parsed_result()
        assert result.observed.get("ruby") is None

        summary = Summariser().summarise(_INSTANCE_META, {"runtimes": result}, now=_NOW)
        assert "ruby" not in summary
