"""Tests for the Voice Input settings panel.

Panel logic is exercised without mounting a Textual app: the widget-facing
methods are driven against stubbed ``query_one`` results, which keeps the
tests fast and focused on the decisions (validation bounds, what gets
persisted, which requirement row is offered) rather than on layout.
"""

from __future__ import annotations

import dataclasses
from unittest.mock import MagicMock, patch

import pytest

from servonaut.config.schema import AppConfig, VoiceConfig
from servonaut.screens.settings.base import ValidationError
from servonaut.screens.settings.panels.voice import VoicePanel, requirement_note
from servonaut.screens.settings.registry import PANELS
from servonaut.services.voice_setup_service import VoiceReadiness


def _readiness(**overrides) -> VoiceReadiness:
    base = dict(
        packages_ok=True, portaudio_ok=True, device_ok=True,
        model_ok=True, model_size="small",
    )
    base.update(overrides)
    return VoiceReadiness(**base)


class _StubWidgets:
    """Serves stub widgets from ``query_one`` keyed by selector."""

    def __init__(self, values: dict) -> None:
        self._widgets = {}
        for selector, value in values.items():
            widget = MagicMock()
            if isinstance(value, bool):
                widget.value = value
            else:
                widget.value = value
            self._widgets[selector] = widget

    def query_one(self, selector, _type=None):
        if selector in self._widgets:
            return self._widgets[selector]
        raise KeyError(selector)


def _panel_with(values: dict) -> VoicePanel:
    """Build a panel whose ``query_one`` returns stubs for *values*."""
    panel = VoicePanel()
    stub = _StubWidgets(values)
    panel.query_one = stub.query_one  # type: ignore[method-assign]
    return panel


_FORM = {
    "#voice_enabled": True,
    "#voice_model_size": "small",
    "#voice_language": "en",
    "#voice_input_device": "",
    "#voice_max_recording_seconds": "60",
    "#voice_auto_submit": False,
    "#voice_engine": "whisper",
    "#voice_latency": 320,
}


def _form(**overrides) -> dict:
    values = dict(_FORM)
    values.update({f"#voice_{k}": v for k, v in overrides.items()})
    return values


class TestRegistration:

    def test_panel_is_registered_under_ai(self):
        spec = next((p for p in PANELS if p.id == "voice"), None)
        assert spec is not None
        assert spec.group == "AI"
        assert spec.factory() is VoicePanel

    def test_search_keywords_cover_the_obvious_terms(self):
        spec = next(p for p in PANELS if p.id == "voice")
        for term in ("voice", "microphone", "dictation", "whisper"):
            assert term in spec.keywords

    def test_panel_id_matches_the_spec(self):
        assert VoicePanel.PANEL_ID == "voice"


class TestValidation:

    def test_valid_form_collects_cleanly(self):
        fields = _panel_with(_form()).collect()
        assert fields == {
            "enabled": True,
            "model_size": "small",
            "language": "en",
            "input_device": None,
            "max_recording_seconds": 60,
            "auto_submit": False,
            "engine": "whisper",
            "nemotron_latency_ms": 320,
        }

    def test_blank_language_falls_back_to_english(self):
        assert _panel_with(_form(language="")).collect()["language"] == "en"

    def test_auto_language_is_accepted(self):
        assert _panel_with(_form(language="auto")).collect()["language"] == "auto"

    def test_a_sentence_is_rejected_as_a_language(self):
        """It would reach the model verbatim and fail mid-dictation."""
        with pytest.raises(ValidationError) as exc:
            _panel_with(_form(language="English please")).collect()
        assert exc.value.field_id == "voice_language"

    def test_non_numeric_cap_is_rejected(self):
        with pytest.raises(ValidationError) as exc:
            _panel_with(_form(max_recording_seconds="abc")).collect()
        assert exc.value.field_id == "voice_max_recording_seconds"

    def test_zero_cap_is_rejected(self):
        with pytest.raises(ValidationError):
            _panel_with(_form(max_recording_seconds="0")).collect()

    def test_absurd_cap_is_rejected(self):
        with pytest.raises(ValidationError):
            _panel_with(_form(max_recording_seconds="99999")).collect()

    def test_blank_cap_falls_back_to_the_default(self):
        fields = _panel_with(_form(max_recording_seconds="")).collect()
        assert fields["max_recording_seconds"] == 60

    def test_blank_device_becomes_none_not_empty_string(self):
        """The service treats None as 'system default'; '' is not a device."""
        assert _panel_with(_form(input_device="")).collect()["input_device"] is None

    def test_named_device_is_preserved(self):
        fields = _panel_with(_form(input_device="USB Audio")).collect()
        assert fields["input_device"] == "USB Audio"


class TestPersist:

    def _panel_with_app(self, values: dict, existing: VoiceConfig):
        panel = _panel_with(values)
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(voice=existing)
        app.voice_input_service = MagicMock()
        app.voice_setup_service = MagicMock()
        # Patched away: they touch widgets the stub does not serve.
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel.persist()
        return app

    def test_persist_writes_the_nested_voice_config(self):
        app = self._panel_with_app(_form(enabled=True), VoiceConfig())
        kwargs = app.config_manager.update.call_args.kwargs
        assert isinstance(kwargs["voice"], VoiceConfig)
        assert kwargs["voice"].enabled is True

    def test_persist_replaces_rather_than_rebuilds_the_config(self):
        """Read-modify-write is what lets a later release add an unexposed field.

        VoiceConfig currently has no field the panel leaves alone, so this
        asserts the mechanism (a copy of the existing object with the panel's
        fields applied) instead of the preservation it buys.
        """
        existing = VoiceConfig(model_size="tiny")
        app = self._panel_with_app(_form(), existing)
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert saved is not existing
        assert saved == dataclasses.replace(
            existing,
            enabled=True, model_size="small", language="en",
            input_device=None, max_recording_seconds=60, auto_submit=False,
            engine="whisper", nemotron_latency_ms=320,
        )

    def test_persist_resets_the_service_availability_cache(self):
        """A stale verdict would describe the settings just replaced."""
        app = self._panel_with_app(_form(), VoiceConfig())
        app.voice_input_service.reset_availability.assert_called_once()

    def test_persist_rebinds_both_services_to_the_new_config(self):
        app = self._panel_with_app(_form(model_size="base"), VoiceConfig())
        saved = app.config_manager.update.call_args.kwargs["voice"]
        assert app.voice_input_service._config is saved
        assert app.voice_setup_service._config is saved

    def test_persist_survives_a_missing_service(self):
        panel = _panel_with(_form())
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig()
        app.voice_input_service = None
        app.voice_setup_service = None
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel.persist()
        app.config_manager.update.assert_called_once()


class TestDirtyTracking:

    def test_current_values_reflect_the_widgets(self):
        values = _panel_with(_form(language="auto")).current_values()
        assert values["language"] == "auto"
        assert values["enabled"] is True

    def test_values_are_stripped(self):
        panel = VoicePanel()
        stub = _StubWidgets(_form())
        stub._widgets["#voice_language"].value = "  en  "
        panel.query_one = stub.query_one  # type: ignore[method-assign]
        assert panel.current_values()["language"] == "en"


class TestHumanBytes:

    @pytest.mark.parametrize("size,expected", [
        (0, "0 B"),
        (2048, "2 KB"),
        (5 * 1024 * 1024, "5 MB"),
    ])
    def test_scales_to_a_readable_unit(self, size, expected):
        assert VoicePanel._human_bytes(size) == expected

    def test_gigabytes_get_a_decimal(self):
        assert VoicePanel._human_bytes(3 * 1024 ** 3) == "3.0 GB"


class TestBannerCopy:

    def _banner_for(self, readiness, *, enabled=True) -> str:
        panel = _panel_with(_form(enabled=enabled))
        banner = MagicMock()
        panel._readiness = readiness
        original = panel.query_one

        def query_one(selector, _type=None):
            if selector == "#voice_status_banner":
                return banner
            return original(selector, _type)

        panel.query_one = query_one  # type: ignore[method-assign]
        panel._render_banner()
        return banner.update.call_args[0][0]

    def test_ready_and_enabled_tells_the_user_how_to_start(self):
        text = self._banner_for(_readiness(), enabled=True)
        assert "Ready" in text
        assert "ctrl+t" in text

    def test_ready_but_disabled_points_at_the_switch(self):
        text = self._banner_for(_readiness(), enabled=False)
        assert "switched off" in text

    @pytest.mark.parametrize("missing,phrase", [
        ("packages_ok", "Python packages"),
        ("portaudio_ok", "PortAudio"),
        ("device_ok", "no microphone"),
        ("model_ok", "not downloaded"),
    ])
    def test_each_unmet_requirement_gets_its_own_wording(self, missing, phrase):
        text = self._banner_for(_readiness(**{missing: False}))
        assert phrase in text

    def test_a_missing_setup_service_is_reported_not_crashed(self):
        panel = _panel_with(_form())
        banner = MagicMock()
        panel.query_one = lambda s, t=None: banner  # type: ignore[method-assign]
        app = MagicMock()
        app.voice_setup_service = None
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._refresh_readiness()
        assert "unavailable" in banner.update.call_args[0][0]


class TestRequirementNotes:
    """Row notes must not assert a cause that was never established."""

    def test_microphone_is_not_blamed_on_ssh_before_any_probe_ran(self):
        """Without PortAudio there was no enumeration to conclude anything from."""
        note = requirement_note(
            "device",
            _readiness(packages_ok=True, portaudio_ok=False, device_ok=False),
        )
        assert note == "not checked yet"

    def test_a_real_device_miss_explains_the_likely_cause(self):
        note = requirement_note(
            "device",
            _readiness(packages_ok=True, portaudio_ok=True, device_ok=False),
        )
        assert "SSH" in note

    def test_a_present_device_is_reported_as_detected(self):
        assert requirement_note("device", _readiness()) == "detected"

    def test_installed_packages_are_not_labelled_with_a_download_size(self):
        """A pending-download note beside OK reads as outstanding work."""
        note = requirement_note("packages", _readiness())
        assert note == "installed"
        assert "MB" not in note

    def test_missing_packages_do_show_the_download_size(self):
        assert "200 MB" in requirement_note("packages", _readiness(packages_ok=False))

    def test_missing_portaudio_flags_that_it_needs_sudo(self):
        """pip cannot install it, so the note must not imply the button will."""
        note = requirement_note("portaudio", _readiness(portaudio_ok=False))
        assert "sudo" in note

    def test_unknown_requirement_yields_no_note(self):
        assert requirement_note("nonsense", _readiness()) == ""


class TestChatPanelNotification:
    """The mic button has to recover without an app restart.

    This path failed silently once already: ``app.query()`` does not
    traverse into screens, so an app-level search returned nothing even
    with a chat panel mounted, and the broad except around it meant no
    error surfaced — the microphone simply stayed greyed out.
    """

    def _panel_with_screens(self, screens):
        panel = _panel_with(_form())
        app = MagicMock()
        app.screen_stack = screens
        return panel, app

    def test_every_screen_in_the_stack_is_searched(self):
        chat_a, chat_b = MagicMock(), MagicMock()
        screen_with = MagicMock()
        screen_with.query.return_value = [chat_a]
        screen_under = MagicMock()
        screen_under.query.return_value = [chat_b]
        panel, app = self._panel_with_screens([screen_under, screen_with])

        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._notify_chat_panels()

        chat_a.refresh_voice_affordance.assert_called_once()
        chat_b.refresh_voice_affordance.assert_called_once()

    def test_no_chat_panel_mounted_is_not_an_error(self):
        screen = MagicMock()
        screen.query.return_value = []
        panel, app = self._panel_with_screens([screen])
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._notify_chat_panels()

    def test_a_failing_panel_does_not_break_the_settings_save(self):
        chat = MagicMock()
        chat.refresh_voice_affordance.side_effect = RuntimeError("panel is going away")
        screen = MagicMock()
        screen.query.return_value = [chat]
        panel, app = self._panel_with_screens([screen])
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._notify_chat_panels()

    def test_a_forced_refresh_notifies_the_chat_panels(self):
        """Forced refresh follows a setup action — the moment staleness bites."""
        panel = _panel_with(_form())
        setup = MagicMock()
        setup.probe.return_value = _readiness()
        panel._setup_service = lambda: setup  # type: ignore[method-assign]
        panel._render_banner = MagicMock()  # type: ignore[method-assign]
        panel._render_requirements = MagicMock()  # type: ignore[method-assign]
        panel._notify_chat_panels = MagicMock()  # type: ignore[method-assign]

        panel._refresh_readiness(force=True)
        panel._notify_chat_panels.assert_called_once()

    def test_an_unforced_refresh_does_not_churn_the_chat_panels(self):
        panel = _panel_with(_form())
        setup = MagicMock()
        setup.probe.return_value = _readiness()
        panel._setup_service = lambda: setup  # type: ignore[method-assign]
        panel._render_banner = MagicMock()  # type: ignore[method-assign]
        panel._render_requirements = MagicMock()  # type: ignore[method-assign]
        panel._notify_chat_panels = MagicMock()  # type: ignore[method-assign]

        panel._refresh_readiness()
        panel._notify_chat_panels.assert_not_called()


class TestAutoSubmitSetting:
    """Auto-submit must be opt-in and must round-trip."""

    def test_auto_submit_is_off_by_default(self):
        """A misheard word would reach an assistant that can run commands."""
        assert VoiceConfig().auto_submit is False

    def test_auto_submit_is_collected(self):
        fields = _panel_with(_form(auto_submit=True)).collect()
        assert fields["auto_submit"] is True

    def test_auto_submit_reaches_the_saved_config(self):
        panel = _panel_with(_form(auto_submit=True))
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig()
        app.voice_input_service = None
        app.voice_setup_service = None
        panel._finish_save = MagicMock()  # type: ignore[method-assign]
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel.persist()
        assert app.config_manager.update.call_args.kwargs["voice"].auto_submit is True

    def test_auto_submit_is_part_of_dirty_tracking(self):
        assert _panel_with(_form(auto_submit=True)).current_values()["auto_submit"] is True


class TestEngineSwitchCleanup:
    """Switching model must offer to reclaim the previous download.

    Each model is several hundred megabytes in a cache directory nobody
    thinks to check, so a silent switch strands the disk.
    """

    def _panel(self, *, stale, loaded_engine="whisper", loaded_size="small",
               loaded_latency=320):
        panel = _panel_with(_form())
        panel._loaded_engine = loaded_engine
        panel._loaded_model_size = loaded_size
        panel._loaded_latency = loaded_latency
        setup = MagicMock()
        setup.stale_models.return_value = stale
        setup.current_model_label.return_value = "Whisper small"
        panel._setup_service = lambda: setup  # type: ignore[method-assign]
        return panel, setup

    def _stale_model(self, label="Whisper medium", size=1500 * 1024 * 1024):
        model = MagicMock()
        model.label = label
        model.size_bytes = size
        model.human_size = "1.5 GB"
        model.in_use = False
        return model

    def test_a_switch_offers_cleanup(self):
        panel, _setup = self._panel(stale=[self._stale_model()])
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
        app.push_screen.assert_called_once()

    def test_nothing_stale_means_no_prompt(self):
        """Never interrupt a save that stranded nothing."""
        panel, _setup = self._panel(stale=[])
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
        app.push_screen.assert_not_called()

    def test_confirming_removes_every_stale_model(self):
        first, second = self._stale_model("Whisper medium"), self._stale_model("Whisper tiny")
        panel, setup = self._panel(stale=[first, second])
        setup.remove_installed.return_value = (True, "removed")
        app = MagicMock()
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
            callback = app.push_screen.call_args[0][1]
            callback(True)
        assert setup.remove_installed.call_count == 2

    def test_declining_removes_nothing(self):
        panel, setup = self._panel(stale=[self._stale_model()])
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
            app.push_screen.call_args[0][1](False)
        setup.remove_installed.assert_not_called()

    def test_dismissing_without_choosing_removes_nothing(self):
        """Escape resolves to None; the safe reading of that is 'keep'."""
        panel, setup = self._panel(stale=[self._stale_model()])
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
            app.push_screen.call_args[0][1](None)
        setup.remove_installed.assert_not_called()

    def test_a_failed_removal_is_reported(self):
        panel, setup = self._panel(stale=[self._stale_model()])
        setup.remove_installed.return_value = (False, "permission denied")
        app = MagicMock()
        panel._refresh_readiness = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
            app.push_screen.call_args[0][1](True)
        severities = [c.kwargs.get("severity") for c in app.notify.call_args_list]
        assert "error" in severities

    def test_an_inventory_failure_does_not_break_the_save(self):
        panel, setup = self._panel(stale=[])
        setup.stale_models.side_effect = OSError("cache unreadable")
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
        app.push_screen.assert_not_called()

    def test_no_setup_service_means_no_prompt(self):
        panel = _panel_with(_form())
        panel._setup_service = lambda: None  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._offer_model_cleanup()
        app.push_screen.assert_not_called()


class TestEngineFields:

    def test_engine_is_collected_and_normalised(self):
        fields = _panel_with(_form(engine="nemotron")).collect()
        assert fields["engine"] == "nemotron"

    def test_an_unknown_engine_is_normalised_on_save(self):
        fields = _panel_with(_form(engine="not-an-engine")).collect()
        assert fields["engine"] == "whisper"

    def test_latency_is_collected(self):
        fields = _panel_with(_form(latency=160)).collect()
        assert fields["nemotron_latency_ms"] == 160

    def test_engine_and_latency_are_part_of_dirty_tracking(self):
        values = _panel_with(_form(engine="nemotron", latency=80)).current_values()
        assert values["engine"] == "nemotron"
        assert values["nemotron_latency_ms"] == 80


class TestPendingSelectionDrivesActions:
    """Setup actions must act on the dropdown, not the last-saved config.

    Regression guard: pressing Download after picking a different engine
    used to re-check the *previous* engine's model, find it cached, and
    report instant success without fetching anything.
    """

    def _panel_and_service(self, *, saved_engine="whisper", picked_engine="nemotron"):
        panel = _panel_with(_form(engine=picked_engine))
        service = MagicMock()
        service.download_size_hint_for.return_value = "~683 MB"
        service._config = VoiceConfig(engine=saved_engine)
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(
            voice=VoiceConfig(engine=saved_engine)
        )
        return panel, service, app

    def test_sync_repoints_the_service_at_the_picked_engine(self):
        panel, service, app = self._panel_and_service()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._sync_setup_service_config()
        assert service._config.engine == "nemotron"

    def test_sync_carries_the_picked_latency(self):
        panel = _panel_with(_form(engine="nemotron", latency=80))
        service = MagicMock()
        service._config = VoiceConfig()
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._sync_setup_service_config()
        assert service._config.nemotron_latency_ms == 80

    def test_sync_drops_the_cached_availability_verdict(self):
        """A verdict cached for the old engine would describe the wrong model."""
        panel, service, app = self._panel_and_service()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._sync_setup_service_config()
        service.reset_availability.assert_called_once()

    def test_sync_preserves_unrelated_voice_settings(self):
        panel = _panel_with(_form(engine="nemotron"))
        service = MagicMock()
        service._config = VoiceConfig()
        panel._setup_service = lambda: service  # type: ignore[method-assign]
        app = MagicMock()
        app.config_manager.get.return_value = AppConfig(
            voice=VoiceConfig(auto_submit=True, max_recording_seconds=45)
        )
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._sync_setup_service_config()
        assert service._config.auto_submit is True
        assert service._config.max_recording_seconds == 45

    def test_download_syncs_before_dispatching(self):
        panel, service, app = self._panel_and_service()
        panel._show_download_progress = MagicMock()  # type: ignore[method-assign]
        panel.run_worker = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._start_download()
        assert service._config.engine == "nemotron"
        panel.run_worker.assert_called_once()

    def test_download_announces_the_picked_model(self):
        """"Downloading the small model" while Nemotron is picked is a lie."""
        panel, service, app = self._panel_and_service()
        panel._show_download_progress = MagicMock()  # type: ignore[method-assign]
        panel.run_worker = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._start_download()
        announced = app.notify.call_args[0][0]
        assert "Nemotron" in announced
        assert "small" not in announced

    def test_install_syncs_before_dispatching(self):
        """Otherwise it installs the extra for the engine you switched away from."""
        panel, service, app = self._panel_and_service()
        panel.run_worker = MagicMock()  # type: ignore[method-assign]
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._start_install()
        assert service._config.engine == "nemotron"

    def test_sync_survives_a_missing_service(self):
        panel = _panel_with(_form())
        panel._setup_service = lambda: None  # type: ignore[method-assign]
        app = MagicMock()
        with patch.object(type(panel), 'app', property(lambda _self: app)):
            panel._sync_setup_service_config()


class TestDownloadProgress:
    """A multi-hundred-megabyte download must show that it is progressing."""

    def _panel_with_progress_widgets(self):
        panel = VoicePanel()
        widgets = {
            "#voice_download_row": MagicMock(),
            "#voice_download_label": MagicMock(),
            "#voice_download_bar": MagicMock(),
        }
        panel.query_one = lambda sel, _t=None: widgets[sel]  # type: ignore[method-assign]
        return panel, widgets

    def test_known_total_drives_a_determinate_bar(self):
        panel, widgets = self._panel_with_progress_widgets()
        panel._render_download_progress("encoder.int8.onnx", 200 * 1024 ** 2, 683 * 1024 ** 2)
        kwargs = widgets["#voice_download_bar"].update.call_args.kwargs
        assert kwargs["total"] == 683 * 1024 ** 2
        assert kwargs["progress"] == 200 * 1024 ** 2

    def test_the_label_reports_both_figures(self):
        panel, widgets = self._panel_with_progress_widgets()
        panel._render_download_progress("encoder.int8.onnx", 200 * 1024 ** 2, 683 * 1024 ** 2)
        label = widgets["#voice_download_label"].update.call_args[0][0]
        assert "200 MB" in label
        assert "683 MB" in label

    def test_unknown_total_stays_indeterminate(self):
        """The batch downloader reports nothing; a fake percentage would lie."""
        panel, widgets = self._panel_with_progress_widgets()
        panel._render_download_progress("model", 0, 0)
        assert widgets["#voice_download_bar"].update.call_args.kwargs["total"] is None

    def test_showing_reveals_the_row(self):
        panel, widgets = self._panel_with_progress_widgets()
        panel._show_download_progress("Starting")
        widgets["#voice_download_row"].remove_class.assert_called_with("hidden")

    def test_hiding_conceals_the_row(self):
        panel, widgets = self._panel_with_progress_widgets()
        panel._hide_download_progress()
        widgets["#voice_download_row"].add_class.assert_called_with("hidden")

    def test_progress_after_the_panel_closed_is_ignored(self):
        panel = VoicePanel()
        panel.query_one = MagicMock(side_effect=Exception("gone"))  # type: ignore[method-assign]
        panel._render_download_progress("x", 1, 2)
        panel._hide_download_progress()
