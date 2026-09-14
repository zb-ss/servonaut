"""Distribution gates for update and optional-dependency setup."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from textual.app import App, ComposeResult

from servonaut.config.schema import VoiceConfig
from servonaut.runtime import DistributionKind, RuntimeEvidence, resolve_runtime
from servonaut.screens.hetzner_setup import HetznerSetupScreen
from servonaut.screens.ovh_setup import OVHSetupScreen
from servonaut.screens.settings.panels.voice import VoicePanel
from servonaut.services.update_service import UpdateService
from servonaut.services.voice_setup_service import VoiceSetupService


def _runtime(kind: DistributionKind):
    executable = Path(sys.executable)
    return resolve_runtime(RuntimeEvidence(
        executable=executable,
        executable_root=executable.parent,
        resource_root=Path("/resources"),
        home=Path("/home/user"),
        is_frozen=kind is DistributionKind.FROZEN_CLI,
        package_version="2.17.0",
        package_is_installed=kind is not DistributionKind.SOURCE,
        source_install_path="file:///project" if kind is DistributionKind.SOURCE else None,
        path_console=None,
        pipx_executable=Path("/usr/bin/pipx") if kind is DistributionKind.PIPX else None,
        pipx_contains_servonaut=kind is DistributionKind.PIPX,
        marker=None,
    ))


def test_frozen_updater_does_not_query_or_spawn_an_installer() -> None:
    service = UpdateService(_runtime(DistributionKind.FROZEN_CLI))
    with patch("urllib.request.urlopen") as request, patch(
        "asyncio.create_subprocess_exec", new_callable=AsyncMock
    ) as spawn:
        assert service.check_for_update() is None
        ok, message = asyncio.run(service.run_upgrade())

    assert ok is False
    assert "signed build" in message
    assert service.update_status == message
    request.assert_not_called()
    spawn.assert_not_called()


def test_source_updater_has_no_upgrade_command_or_external_pip_probe() -> None:
    service = UpdateService(_runtime(DistributionKind.SOURCE))
    with patch("subprocess.run") as run:
        assert service.get_upgrade_command() is None
        assert service.installed_version_external() is None
    run.assert_not_called()


def test_pipx_dependency_install_argv_comes_from_runtime_capability() -> None:
    service = VoiceSetupService(VoiceConfig(), _runtime(DistributionKind.PIPX))
    assert service.install_command() == [
        str(Path("/usr/bin/pipx")), "inject", "servonaut", *service.packages()
    ]


def test_source_voice_setup_offers_manual_guidance_without_spawning() -> None:
    service = VoiceSetupService(VoiceConfig(), _runtime(DistributionKind.SOURCE))
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn:
        ok, message = asyncio.run(service.install_packages())
    assert ok is False
    assert "source installation" in message
    assert "pip install -e" in message
    spawn.assert_not_called()


def test_frozen_voice_setup_is_unavailable_without_spawning() -> None:
    service = VoiceSetupService(VoiceConfig(), _runtime(DistributionKind.FROZEN_CLI))
    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn:
        ok, message = asyncio.run(service.install_tts_packages())
    assert ok is False
    assert "packaged build" in message
    spawn.assert_not_called()


def test_source_hetzner_setup_installs_through_its_runtime_capability() -> None:
    app = MagicMock()
    app.runtime_layout = _runtime(DistributionKind.SOURCE)
    screen = HetznerSetupScreen()
    with patch.object(
        HetznerSetupScreen, "app", new_callable=PropertyMock, return_value=app
    ), patch.dict(sys.modules, {"hcloud": None}), patch(
        "servonaut.screens.hetzner_setup.subprocess.check_call"
    ) as install, patch("asyncio.to_thread", new_callable=AsyncMock) as to_thread:
        assert asyncio.run(screen._install_hcloud_if_needed()) is True

    to_thread.assert_awaited_once_with(install, [
        sys.executable, "-m", "pip", "install", "hcloud"
    ])


def test_source_ovh_setup_installs_through_its_runtime_capability() -> None:
    app = MagicMock()
    app.runtime_layout = _runtime(DistributionKind.SOURCE)
    screen = OVHSetupScreen()
    with patch.object(
        OVHSetupScreen, "app", new_callable=PropertyMock, return_value=app
    ), patch.dict(sys.modules, {"ovh": None}), patch(
        "servonaut.screens.ovh_setup.subprocess.check_call"
    ) as install, patch("asyncio.to_thread", new_callable=AsyncMock) as to_thread:
        assert asyncio.run(screen._install_ovh_if_needed()) is True

    to_thread.assert_awaited_once_with(install, [
        sys.executable, "-m", "pip", "install", "ovh"
    ])


def test_frozen_provider_setup_does_not_spawn_an_installer() -> None:
    app = MagicMock()
    app.runtime_layout = _runtime(DistributionKind.FROZEN_CLI)
    screen = HetznerSetupScreen()
    with patch.object(
        HetznerSetupScreen, "app", new_callable=PropertyMock, return_value=app
    ), patch.dict(sys.modules, {"hcloud": None}), patch(
        "servonaut.screens.hetzner_setup.subprocess.check_call"
    ) as install:
        assert asyncio.run(screen._install_hcloud_if_needed()) is False

    install.assert_not_called()


class _VoicePanelApp(App[None]):
    """Minimal headless host for the packaged-voice setup card."""

    def compose(self) -> ComposeResult:
        yield VoicePanel()


def test_voice_settings_panel_mounts_in_a_headless_textual_app() -> None:
    """Golden UI path: the opt-in setup card remains renderable."""
    async def exercise() -> None:
        app = _VoicePanelApp()
        async with app.run_test():
            assert app.query_one(VoicePanel)
            assert app.query_one("#voice_enabled")
            assert app.query_one("#voice_requirements")

    asyncio.run(exercise())
