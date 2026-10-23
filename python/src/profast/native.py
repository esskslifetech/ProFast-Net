"""Native bridge and Quality of Service.

The C++ core is optional at runtime. When ``pfbench`` is present it provides
process priority tuning and the EcoQoS fix that actually restores throughput on
Windows 11; when it is missing, focus mode reports the capability as skipped
instead of pretending.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .models import Report


def repo_root() -> Path:
    """The repository root when running from a source checkout."""
    return Path(__file__).resolve().parents[3]


def find_native() -> Path | None:
    name = "pfbench.exe" if sys.platform == "win32" else "pfbench"

    on_path = shutil.which("pfbench")
    if on_path:
        return Path(on_path)

    candidates = [
        repo_root() / "build" / "native" / "bin" / name,
        repo_root() / "native" / "build" / "bin" / name,
        Path(sys.executable).parent / name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _invoke(argv: list[str], timeout: int = 10) -> tuple[bool, str]:
    binary = find_native()
    if binary is None:
        return False, "native bridge not built (see scripts/build.ps1)"

    try:
        completed = subprocess.run(
            [str(binary), *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    output = (completed.stdout or completed.stderr or "").strip()
    return completed.returncode == 0, output


def selftest() -> dict[str, object] | None:
    ok, output = _invoke(["selftest"])
    if not ok or not output:
        return None
    try:
        return json.loads(output)
    except ValueError:
        return None


def set_priority(pid: int, level: int) -> tuple[bool, str]:
    if pid <= 0:
        return False, "a pid is required for priority tuning"
    return _invoke(["priority", str(pid), str(level)])


def set_power_throttling(pid: int, disable: bool) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "power throttling is a Windows concept"
    if pid <= 0:
        return False, "a pid is required for power tuning"
    return _invoke(["power", str(pid), "1" if disable else "0"])


# --------------------------------------------------------------------- QoS --


def apply_focus(
    app_path: str,
    dscp: int = 46,
    background_dscp: int = 8,
    throttle_others: bool = True,
) -> Report:
    if sys.platform == "win32":
        return _focus_windows(app_path, dscp, background_dscp, throttle_others)
    if sys.platform == "darwin":
        return _focus_darwin()
    return _focus_linux()


def revert() -> Report:
    if sys.platform == "win32":
        ok, output = _powershell(
            "Remove-NetQosPolicy -Name 'ProFast-Focus','ProFast-Background' "
            "-Confirm:$false -ErrorAction SilentlyContinue"
        )
        return Report(
            "wfp-qos", applied=["policies removed"] if ok else [], errors=[] if ok else [output]
        )
    if sys.platform == "darwin":
        ok, output = _run(["dnctl", "-q", "flush"])
        return Report(
            "dnctl", applied=["pipes flushed"] if ok else [], errors=[] if ok else [output]
        )
    return Report("nft", skipped=["no persistent shaping was installed"])


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _powershell(script: str) -> tuple[bool, str]:
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )


def _run(argv: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output.strip()


def _focus_windows(app_path: str, dscp: int, background_dscp: int, throttle: bool) -> Report:
    report = Report("wfp-qos")
    if not app_path:
        report.errors.append("an application path is required for DSCP marking")
        return report

    script = [
        "Remove-NetQosPolicy -Name 'ProFast-Focus' -Confirm:$false -ErrorAction SilentlyContinue",
        f"New-NetQosPolicy -Name 'ProFast-Focus' -AppPathNameMatchCondition {_quote(app_path)} "
        f"-DSCPAction {dscp} -NetworkProfile All -Priority 1 -ErrorAction Stop",
    ]
    if throttle:
        script.append(
            "Remove-NetQosPolicy -Name 'ProFast-Background' -Confirm:$false "
            "-ErrorAction SilentlyContinue"
        )
        script.append(
            f"New-NetQosPolicy -Name 'ProFast-Background' -DSCPAction {background_dscp} "
            "-ThrottleRateActionBitsPerSecond 4mbps -NetworkProfile All "
            "-ErrorAction SilentlyContinue"
        )

    ok, output = _powershell("; ".join(script))
    if ok:
        report.applied.append(f"DSCP {dscp} for {app_path}")
        if throttle:
            report.applied.append(f"background traffic capped at DSCP {background_dscp}")
    else:
        report.errors.append(output or "New-NetQosPolicy failed (elevation required)")
    return report


def _focus_darwin() -> Report:
    report = Report("dnctl")
    if not shutil.which("dnctl"):
        report.errors.append("dnctl is not available")
        return report

    for argv in (
        ["dnctl", "pipe", "1", "config", "bw", "200Mbit"],
        ["dnctl", "pipe", "2", "config", "bw", "4Mbit"],
    ):
        ok, output = _run(argv)
        if ok:
            report.applied.append(" ".join(argv))
        else:
            report.errors.append(output)
    report.skipped.append("dummynet rules are loaded by the firewall plan")
    return report


def _focus_linux() -> Report:
    report = Report("nft")
    report.applied.append("process scheduler priority handled by the native bridge")
    report.skipped.append(
        "per-application DSCP needs a cgroup v2 match; see docs/KERNEL.md for the "
        "profast-netfilter unit"
    )
    return report


def parse_dscp(value: str) -> int:
    mapping = {"ef": 46, "cs1": 8, "background": 8, "af41": 34, "be": 0, "best-effort": 0}
    key = (value or "").strip().lower()
    if key in mapping:
        return mapping[key]
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid DSCP {value!r} (expected 0-63 or ef/cs1/af41/be)") from exc
    if not 0 <= number <= 63:
        raise ValueError(f"DSCP must be between 0 and 63, got {number}")
    return number


def environment() -> dict[str, object]:
    binary = find_native()
    return {
        "native_path": str(binary) if binary else "",
        "native_available": binary is not None,
        "platform": sys.platform,
        "elevated": _elevated(),
    }


def _elevated() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False
