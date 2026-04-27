"""Tests for servonaut.services.memory.modules build_default_probers factory.

Covers the branch where log_viewer_service / ssh_service / connection_service
are provided (LogsProber included) and where log_viewer_service is None
(LogsProber omitted).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from servonaut.services.memory.modules import build_default_probers
from servonaut.services.memory.modules.logs import LogsProber
from servonaut.services.memory.modules.os import OSProber
from servonaut.services.memory.modules.runtimes import RuntimesProber
from servonaut.services.memory.modules.services import ServicesProber
from servonaut.services.memory.modules.web_stack import WebStackProber


class TestBuildDefaultProbersNoServices:
    """Factory with all services=None returns all non-SSH probers.

    T2 shipped four (os, runtimes, services, web_stack); T8 added five more
    (databases, containers, network, git, disk).
    """

    def test_returns_nine_probers_when_no_services(self) -> None:
        probers = build_default_probers()
        assert len(probers) == 9

    def test_order_is_os_runtimes_services_webstack(self) -> None:
        probers = build_default_probers()
        assert isinstance(probers[0], OSProber)
        assert isinstance(probers[1], RuntimesProber)
        assert isinstance(probers[2], ServicesProber)
        assert isinstance(probers[3], WebStackProber)

    def test_no_logs_prober_when_log_viewer_missing(self) -> None:
        probers = build_default_probers(log_viewer_service=None)
        assert not any(isinstance(p, LogsProber) for p in probers)

    def test_no_logs_prober_when_ssh_service_missing(self) -> None:
        """Even with log_viewer_service present, missing ssh_service omits LogsProber."""
        mock_lv = MagicMock()
        mock_conn = MagicMock()
        probers = build_default_probers(
            log_viewer_service=mock_lv,
            ssh_service=None,
            connection_service=mock_conn,
        )
        assert not any(isinstance(p, LogsProber) for p in probers)

    def test_no_logs_prober_when_connection_service_missing(self) -> None:
        """Even with log_viewer_service + ssh_service, missing connection_service omits LogsProber."""
        mock_lv = MagicMock()
        mock_ssh = MagicMock()
        probers = build_default_probers(
            log_viewer_service=mock_lv,
            ssh_service=mock_ssh,
            connection_service=None,
        )
        assert not any(isinstance(p, LogsProber) for p in probers)


class TestBuildDefaultProbersWithServices:
    """Factory with all three services returns all probers including LogsProber.

    Count: four T2 MVP + five T8 additions + LogsProber = 10.
    """

    def _make_probers(self) -> list[Any]:
        return build_default_probers(
            log_viewer_service=MagicMock(),
            ssh_service=MagicMock(),
            connection_service=MagicMock(),
        )

    def test_returns_ten_probers(self) -> None:
        probers = self._make_probers()
        assert len(probers) == 10

    def test_logs_prober_is_last(self) -> None:
        """LogsProber is appended after all non-SSH probers."""
        probers = self._make_probers()
        assert isinstance(probers[-1], LogsProber)

    def test_first_four_are_standard_probers(self) -> None:
        probers = self._make_probers()
        assert isinstance(probers[0], OSProber)
        assert isinstance(probers[1], RuntimesProber)
        assert isinstance(probers[2], ServicesProber)
        assert isinstance(probers[3], WebStackProber)

    def test_logs_prober_holds_log_viewer_service(self) -> None:
        """The LogsProber must be constructed with the provided log_viewer_service."""
        mock_lv = MagicMock(name="log_viewer_svc")
        probers = build_default_probers(
            log_viewer_service=mock_lv,
            ssh_service=MagicMock(),
            connection_service=MagicMock(),
        )
        logs_prober = probers[-1]
        assert isinstance(logs_prober, LogsProber)
        # The prober stores it as _log_viewer_service
        assert logs_prober._log_viewer_service is mock_lv

    def test_logs_prober_module_name(self) -> None:
        probers = self._make_probers()
        logs_prober = probers[-1]
        assert logs_prober.name == "logs"

    def test_all_probers_have_name_and_ttl(self) -> None:
        """Every prober must expose name and ttl_seconds attributes."""
        probers = self._make_probers()
        for prober in probers:
            assert hasattr(prober, "name"), f"{prober!r} missing .name"
            assert hasattr(prober, "ttl_seconds"), f"{prober!r} missing .ttl_seconds"
            assert prober.ttl_seconds > 0
