"""Presentation for the dashboard's live SSH metrics section."""

from __future__ import annotations

from rich.markup import escape

from servonaut.utils.live_stats import LiveStats


def stats_bar(pct: float | None, width: int = 12) -> str:
    """Render the dashboard's resource gauge."""
    if pct is None:
        return "[dim]" + "·" * width + "[/dim]"
    filled = max(0, min(width, round(pct / 100 * width)))
    color = "green" if pct < 70 else ("yellow" if pct < 90 else "red")
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (width - filled)}[/dim]"


def format_live_stats(stats: LiveStats) -> str:
    """Render a Linux resource snapshot without implying historical coverage."""
    cpu = f"{stats.cpu_pct:.0f}%" if stats.cpu_pct is not None else "?"
    memory = "?"
    if stats.mem_pct is not None:
        memory = f"{stats.mem_pct:.0f}% [dim]({stats.mem_used_mb}/{stats.mem_total_mb} MB)[/dim]"
    loads = (stats.load_1m, stats.load_5m, stats.load_15m)
    load = " ".join(f"{value:.2f}" if value is not None else "?" for value in loads)
    disk = "?"
    if stats.disk_pct is not None:
        disk = f"{stats.disk_pct}% [dim]({stats.disk_used_gb}/{stats.disk_total_gb} GB)[/dim]"
    uptime = escape(stats.uptime) if stats.uptime else "?"
    return (
        "[bold]Live via SSH[/bold]  [dim]· press [b]L[/b] to stop[/dim]\n\n"
        f"  [dim]CPU [/dim] {stats_bar(stats.cpu_pct)} {cpu}\n"
        f"  [dim]RAM [/dim] {stats_bar(stats.mem_pct)} {memory}\n"
        f"  [dim]Load[/dim] {load}    [dim]Disk[/dim] {stats_bar(stats.disk_pct)} {disk}\n"
        f"  [dim]Up  [/dim] {uptime}"
    )
