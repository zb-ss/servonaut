"""OVH instance monitoring screen for Servonaut."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from servonaut.widgets.sidebar import Sidebar
from servonaut.screens._binding_guard import check_action_passthrough

if TYPE_CHECKING:
    from servonaut.app import ServonautApp

logger = logging.getLogger(__name__)

_PERIODS = [
    ("Day", "lastday"),
    ("Week", "lastweek"),
    ("Month", "lastmonth"),
    ("Year", "lastyear"),
]


def _format_series(series: List[dict], unit: str = "") -> str:
    """Render a list of {timestamp, value} dicts as an ASCII text table."""
    if not series:
        return "  [dim]No data available.[/dim]"

    lines: List[str] = []
    lines.append(f"  {'Timestamp':<28}  {'Value':>12}")
    lines.append("  " + "-" * 42)
    for point in series[-20:]:  # show at most the last 20 samples
        ts = str(point.get("timestamp", "")).replace("T", " ").rstrip("Z")
        raw_value = point.get("value")
        if raw_value is None:
            value_str = "n/a"
        else:
            try:
                value_str = f"{float(raw_value):.4f}{unit}"
            except (TypeError, ValueError):
                value_str = str(raw_value)
        lines.append(f"  {ts:<28}  {value_str:>12}")

    if len(series) > 20:
        lines.append(f"  [dim]... {len(series) - 20} earlier samples omitted[/dim]")

    return "\n".join(lines)


class OVHMonitoringScreen(Screen):
    """Display monitoring metrics (CPU, RAM, Network) for an OVH instance."""

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
    ]

    @property
    def app(self) -> "ServonautApp":
        return super().app  # type: ignore

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        return check_action_passthrough(self, action)

    def __init__(self, instance: dict) -> None:
        """Initialise the monitoring screen.

        Args:
            instance: Instance dict from ``app.instances``.  Must contain at
                least ``name`` and ``provider_type``.  Cloud instances encode
                the composite ID as ``{project_id}/{id}`` in the ``id`` field.
        """
        super().__init__()
        self._instance = instance
        self._period: str = "lastday"
        self._provider_type: str = instance.get("provider_type", "vps")

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        instance_name = self._instance.get("name", "Unknown")
        yield Header()
        with Horizontal(id="main-layout"):
            yield Sidebar()
            yield ScrollableContainer(
                Static(
                    f"[bold cyan]Monitoring: {instance_name}[/bold cyan]",
                    id="monitoring_title",
                ),
                Horizontal(
                    *[
                        Button(
                            label,
                            id=f"period_{period_key}",
                            variant="primary" if period_key == self._period else "default",
                        )
                        for label, period_key in _PERIODS
                    ],
                    id="period_selector",
                ),
                Static("[bold]CPU Usage[/bold]", classes="section_header"),
                Static("Loading...", id="cpu_data"),
                Static("[bold]Memory Usage[/bold]", classes="section_header"),
                Static("Loading...", id="ram_data"),
                Static("[bold]Network I/O[/bold]", classes="section_header"),
                Static("Loading...", id="net_data"),
                Button("Back", id="btn_back", variant="default"),
                id="monitoring_container",
            )
        yield Footer()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._fetch_metrics()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""

        if button_id == "btn_back":
            self.app.pop_screen()
            return

        for _label, period_key in _PERIODS:
            if button_id == f"period_{period_key}":
                if period_key != self._period:
                    self._period = period_key
                    self._update_period_buttons()
                    self._fetch_metrics()
                return

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_period_buttons(self) -> None:
        for _label, period_key in _PERIODS:
            btn = self.query_one(f"#period_{period_key}", Button)
            btn.variant = "primary" if period_key == self._period else "default"

    def _fetch_metrics(self) -> None:
        provider_type = self._provider_type

        if provider_type == "cloud":
            self.run_worker(self._load_cloud_metrics(), exclusive=True)
        elif provider_type == "dedicated":
            self.run_worker(self._load_dedicated_metrics(), exclusive=True)
        else:
            # Default: VPS
            self.run_worker(self._load_vps_metrics(), exclusive=True)

    async def _load_vps_metrics(self) -> None:
        svc = getattr(self.app, "ovh_monitoring_service", None)
        vps_name = self._instance.get("id", self._instance.get("name", ""))
        self._set_loading()
        try:
            if svc is None:
                raise RuntimeError("OVHMonitoringService not initialised")
            data = await svc.get_vps_monitoring(vps_name, self._period)
        except Exception as exc:
            logger.error("VPS monitoring fetch failed: %s", exc)
            self._set_error(str(exc))
            return

        self.query_one("#cpu_data", Static).update(
            _format_series(data.get("cpu", []), unit="%")
        )
        self.query_one("#ram_data", Static).update(
            _format_series(data.get("ram", []), unit=" MB")
        )
        net_in = data.get("net_in", [])
        net_out = data.get("net_out", [])
        self.query_one("#net_data", Static).update(
            "[dim]--- Network In ---[/dim]\n"
            + _format_series(net_in, unit=" B/s")
            + "\n\n[dim]--- Network Out ---[/dim]\n"
            + _format_series(net_out, unit=" B/s")
        )

    async def _load_dedicated_metrics(self) -> None:
        svc = getattr(self.app, "ovh_monitoring_service", None)
        server_name = self._instance.get("id", self._instance.get("name", ""))
        self._set_loading()
        try:
            if svc is None:
                raise RuntimeError("OVHMonitoringService not initialised")
            data = await svc.get_dedicated_monitoring(server_name, self._period)
        except Exception as exc:
            logger.error("Dedicated monitoring fetch failed: %s", exc)
            self._set_error(str(exc))
            return

        self.query_one("#cpu_data", Static).update(
            _format_series(data.get("cpu", []), unit="%")
        )
        self.query_one("#ram_data", Static).update(
            _format_series(data.get("ram", []), unit=" MB")
        )
        net_rx = data.get("net_rx", [])
        net_tx = data.get("net_tx", [])
        self.query_one("#net_data", Static).update(
            "[dim]--- Network RX ---[/dim]\n"
            + _format_series(net_rx, unit=" B/s")
            + "\n\n[dim]--- Network TX ---[/dim]\n"
            + _format_series(net_tx, unit=" B/s")
        )

    async def _load_cloud_metrics(self) -> None:
        svc = getattr(self.app, "ovh_monitoring_service", None)
        # Cloud instances encode composite ID as "{project_id}/{instance_id}"
        raw_id: str = self._instance.get("id", "")
        self._set_loading()
        try:
            if svc is None:
                raise RuntimeError("OVHMonitoringService not initialised")
            if "/" not in raw_id:
                raise ValueError(
                    f"Cloud instance ID must be 'project_id/instance_id', got: {raw_id!r}"
                )
            project_id, instance_id = raw_id.split("/", 1)
            data = await svc.get_cloud_monitoring(project_id, instance_id, self._period)
        except Exception as exc:
            logger.error("Cloud monitoring fetch failed: %s", exc)
            self._set_error(str(exc))
            return

        self.query_one("#cpu_data", Static).update(
            _format_series(data.get("cpu", []), unit="%")
        )
        self.query_one("#ram_data", Static).update(
            "  [dim]RAM metrics are not available for Public Cloud instances.[/dim]"
        )
        net_in = data.get("net_in", [])
        net_out = data.get("net_out", [])
        self.query_one("#net_data", Static).update(
            "[dim]--- Network In ---[/dim]\n"
            + _format_series(net_in, unit=" B/s")
            + "\n\n[dim]--- Network Out ---[/dim]\n"
            + _format_series(net_out, unit=" B/s")
        )

    def _set_loading(self) -> None:
        for widget_id in ("#cpu_data", "#ram_data", "#net_data"):
            self.query_one(widget_id, Static).update("[dim]Loading...[/dim]")

    def _set_error(self, message: str) -> None:
        error_text = f"[red]Error fetching metrics: {message}[/red]"
        for widget_id in ("#cpu_data", "#ram_data", "#net_data"):
            self.query_one(widget_id, Static).update(error_text)
