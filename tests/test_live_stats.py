"""Tests for the live resource-stats parser (utils/live_stats.py)."""

from __future__ import annotations

from servonaut.utils.live_stats import (
    LIVE_STATS_COMMAND,
    LiveStats,
    parse_live_stats,
)


def _sample(
    cpu1: str = "cpu  1000 0 500 8000 200 0 50 0 0 0",
    cpu2: str = "cpu  1100 0 520 8700 210 0 55 0 0 0",
    mem_line: str = "Mem:           15761        3465         512         128        4360        4500",
    load_line: str = "0.40 0.55 0.60 1/234 5678",
    up_line: str = "456789.12 3456789.00",
    disk_line: str = "/dev/xvda1   58G   11G   47G  18% /",
) -> str:
    return (
        f"SVN_CPU\n{cpu1}\n{cpu2}\n"
        f"SVN_MEM\n{mem_line}\n"
        f"SVN_LOAD\n{load_line}\n"
        f"SVN_UP\n{up_line}\n"
        f"SVN_DISK\n{disk_line}\n"
    )


class TestParseLiveStats:
    def test_full_parse(self):
        s = parse_live_stats(_sample())
        # delta_total = (1100+520+8700+210+55) - (1000+500+8000+200+50) = 10585-9750 = 835
        # delta_idle  = (8700+210) - (8000+200) = 710 ; busy = 100*(1-710/835) ≈ 15.0
        assert s.cpu_pct is not None and 14.0 <= s.cpu_pct <= 16.0
        assert s.mem_total_mb == 15761
        assert s.mem_used_mb == 3465
        assert s.load_1m == 0.40
        assert s.load_5m == 0.55
        assert s.load_15m == 0.60
        assert s.uptime is not None and s.uptime.startswith("up ")
        assert s.disk_total_gb == 58
        assert s.disk_used_gb == 11
        assert s.disk_pct == 18

    def test_uptime_formatting(self):
        # 456789s = 5d 6h 53m
        s = parse_live_stats(_sample(up_line="456789.12 0"))
        assert s.uptime == "up 5d 6h 53m"

    def test_uptime_under_a_day(self):
        s = parse_live_stats(_sample(up_line="3700.0 0"))  # 1h 1m
        assert s.uptime == "up 1h 1m"

    def test_mem_pct_derived(self):
        s = parse_live_stats(_sample())
        assert s.mem_pct == round(3465 / 15761 * 100, 1)

    def test_empty_input_all_none(self):
        s = parse_live_stats("")
        assert s == LiveStats()
        assert s.mem_pct is None

    def test_garbage_input_does_not_raise(self):
        s = parse_live_stats("totally unrelated\noutput here\n")
        assert isinstance(s, LiveStats)
        assert s.cpu_pct is None
        assert s.load_1m is None

    def test_single_cpu_sample_yields_none(self):
        # Only one /proc/stat line → cannot compute a delta.
        text = "SVN_CPU\ncpu  1000 0 500 8000 200 0 50 0 0 0\nSVN_MEM\nMem: 1000 400\n"
        s = parse_live_stats(text)
        assert s.cpu_pct is None
        assert s.mem_used_mb == 400

    def test_cpu_idle_only_is_zero_busy(self):
        # No movement except idle → 0% busy.
        text = (
            "SVN_CPU\ncpu  100 0 100 1000 0 0 0 0 0 0\n"
            "cpu  100 0 100 1100 0 0 0 0 0 0\nSVN_MEM\n"
        )
        s = parse_live_stats(text)
        assert s.cpu_pct == 0.0

    def test_missing_cpu_section_other_fields_survive(self):
        text = (
            "SVN_MEM\nMem:  1000  400  600\n"
            "SVN_LOAD\n0.10 0.20 0.30\n"
            "SVN_DISK\n/dev/sda1 10G 2G 8G 20% /\n"
        )
        s = parse_live_stats(text)
        assert s.cpu_pct is None
        assert s.mem_used_mb == 400
        assert s.load_1m == 0.10
        assert s.disk_pct == 20

    def test_command_is_read_only(self):
        for tok in (" > ", " >> ", " tee ", " rm ", " dd ", " mv "):
            assert tok not in LIVE_STATS_COMMAND

    def test_command_avoids_nonportable_tools(self):
        # Regression: must not depend on top / uptime -p (Amazon Linux gaps).
        assert "top " not in LIVE_STATS_COMMAND
        assert "uptime -p" not in LIVE_STATS_COMMAND
        assert "/proc/stat" in LIVE_STATS_COMMAND
        assert "/proc/uptime" in LIVE_STATS_COMMAND

    def test_disk_with_gigabyte_suffix(self):
        s = parse_live_stats(_sample(disk_line="/dev/root 40G 12G 28G 30% /"))
        assert s.disk_total_gb == 40
        assert s.disk_used_gb == 12
        assert s.disk_pct == 30
