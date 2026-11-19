"""Native process birth identities for update leases."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path


class UnknownProcess(OSError):
    """The process cannot be proved to have exited or been identified."""


def birth(pid: int) -> str | None:
    """Return an OS creation identity, None for a dead process, or raise."""
    if pid <= 0:
        return None
    if sys.platform.startswith("linux"):
        return _linux_birth(pid)
    if sys.platform == "darwin":
        return _mac_birth(pid)
    if os.name == "nt":
        return _windows_birth(pid)
    raise UnknownProcess("Process identity is unavailable on this platform")


def boot_identity() -> str | None:
    """Return a native boot identifier where one is available."""
    try:
        if sys.platform.startswith("linux"):
            return Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
        if sys.platform == "darwin":
            buffer = ctypes.create_string_buffer(64)
            size = ctypes.c_size_t(ctypes.sizeof(buffer))
            sysctl = ctypes.CDLL(None).sysctlbyname
            sysctl.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                               ctypes.c_void_p, ctypes.c_size_t]
            sysctl.restype = ctypes.c_int
            if sysctl(b"kern.bootsessionuuid", buffer, ctypes.byref(size), None, 0) == 0:
                return buffer.value.decode("ascii") or None
    except (AttributeError, OSError, UnicodeError):
        pass
    return None


def _linux_birth(pid: int) -> str | None:
    try:
        _, _, tail = Path(f"/proc/{pid}/stat").read_text().rpartition(")")
        fields = tail.split()
        if fields[0] in {"Z", "X"}:
            return None
        ticks = int(fields[19])
    except FileNotFoundError:
        if not Path("/proc/self/stat").is_file():
            raise UnknownProcess("Process table is unavailable") from None
        return None
    except (IndexError, ValueError) as exc:
        raise UnknownProcess("Invalid process identity") from exc
    boot_id = boot_identity()
    if not boot_id:
        raise UnknownProcess("Boot identity is unavailable")
    return f"{boot_id}:{ticks}"


class _MacProcessInfo(ctypes.Structure):
    # proc_bsdinfo in the public XNU proc_info.h ABI.
    _fields_ = [
        ("numbers", ctypes.c_uint32 * 12),
        ("command", ctypes.c_char * 16),
        ("name", ctypes.c_char * 32),
        ("status_fields", ctypes.c_uint32 * 6),
        ("start_seconds", ctypes.c_uint64),
        ("start_microseconds", ctypes.c_uint64),
    ]


def _mac_birth(pid: int) -> str | None:
    info = _MacProcessInfo()
    proc_pidinfo = ctypes.CDLL("libproc.dylib").proc_pidinfo
    proc_pidinfo.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int
    ]
    proc_pidinfo.restype = ctypes.c_int
    if proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) == ctypes.sizeof(info):
        if info.numbers[1] == 5:  # SZOMB
            return None
        return f"{info.start_seconds}:{info.start_microseconds}"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    raise UnknownProcess("Could not read process identity")


def _windows_birth(pid: int) -> str | None:
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    handle = kernel.OpenProcess(0x00101000, False, pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: no such PID
            return None
        raise UnknownProcess("Could not open process")
    try:
        wait_status = kernel.WaitForSingleObject(handle, 0)
        if wait_status == 0:
            return None
        stamps = [wintypes.FILETIME() for _ in range(4)]
        if wait_status != 258 or not kernel.GetProcessTimes(handle, *map(ctypes.byref, stamps)):
            raise UnknownProcess("Could not read process creation time")
        return str((stamps[0].dwHighDateTime << 32) | stamps[0].dwLowDateTime)
    finally:
        kernel.CloseHandle(handle)
