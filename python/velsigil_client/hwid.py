"""Hardware id derivation; the same in every Velsigil SDK."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from typing import Optional

from .errors import HardwareIdError

HWID_PREFIX = "vx-hwid-v1:"

_LINUX_MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")
_MACOS_IOREG = "/usr/sbin/ioreg"
_IOREG_UUID_RE = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')
_MAX_ID_FILE_BYTES = 4096


def normalize_machine_id(machine_id: str) -> str:
    """Trim surrounding whitespace and lower-case a raw machine id."""
    return machine_id.strip().lower()


def hwid_from_machine_id(machine_id: str) -> str:
    """Derive the protocol HWID from a raw machine identifier."""
    if not isinstance(machine_id, str):
        raise TypeError("machine_id must be a string")
    normalized = normalize_machine_id(machine_id)
    if not normalized:
        raise ValueError("machine_id is empty")
    return hashlib.sha256((HWID_PREFIX + normalized).encode("utf-8")).hexdigest()


def _read_windows_machine_guid() -> str:
    import winreg  # type: ignore[import-not-found]

    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, access
        ) as key:
            value, value_type = winreg.QueryValueEx(key, "MachineGuid")
    except OSError as exc:
        raise HardwareIdError("cannot read MachineGuid from the registry") from exc
    if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str):
        raise HardwareIdError("MachineGuid has an unexpected registry type")
    return value


# systemd's placeholder, which cloned images would share; skipped like an empty file.
_MACHINE_ID_PLACEHOLDER = "uninitialized"


def _read_linux_machine_id() -> str:
    for path in _LINUX_MACHINE_ID_PATHS:
        try:
            with open(path, "rb") as handle:
                content = handle.read(_MAX_ID_FILE_BYTES)
        except OSError:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        normalized = normalize_machine_id(text)
        if normalized and normalized != _MACHINE_ID_PLACEHOLDER:
            return text
    raise HardwareIdError("no machine-id found in /etc/machine-id or /var/lib/dbus/machine-id")


def _read_macos_platform_uuid() -> str:
    # Absolute path only, so a PATH entry cannot substitute ioreg.
    if not os.path.isfile(_MACOS_IOREG):
        raise HardwareIdError("%s not found" % _MACOS_IOREG)
    try:
        completed = subprocess.run(
            [_MACOS_IOREG, "-rd1", "-c", "IOPlatformExpertDevice"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=10,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HardwareIdError("cannot run ioreg") from exc
    match = _IOREG_UUID_RE.search(completed.stdout.decode("utf-8", "replace"))
    if completed.returncode != 0 or match is None:
        raise HardwareIdError("IOPlatformUUID not found in ioreg output")
    return match.group(1)


def read_machine_id(platform: Optional[str] = None) -> str:
    """Return the raw machine id; raises :class:`HardwareIdError` if unavailable."""
    plat = platform or sys.platform
    if plat.startswith("win"):
        raw = _read_windows_machine_guid()
    elif plat == "darwin":
        raw = _read_macos_platform_uuid()
    elif plat.startswith("linux"):
        raw = _read_linux_machine_id()
    else:
        raise HardwareIdError("unsupported platform %r; pass an explicit hwid" % plat)
    if not raw.strip():
        raise HardwareIdError("machine id is empty")
    return raw


def get_hardware_id() -> str:
    """Return this machine's Velsigil HWID (64 lowercase hex characters)."""
    return hwid_from_machine_id(read_machine_id())


__all__ = [
    "HWID_PREFIX",
    "normalize_machine_id",
    "hwid_from_machine_id",
    "read_machine_id",
    "get_hardware_id",
]
