"""Asking Windows for administrator rights from inside the window.

A process cannot promote itself: UAC hands an elevated token to a *new*
process, so the sidebar control re-launches this application through
``ShellExecuteW(..., "runas", ...)`` and the caller closes the old window.

Privileges belong to whichever process runs the engine, not to the window, so
when the window is attached to a daemon the daemon is what has to be replaced.
``stop_daemon()`` runs after the elevated copy is up, which is why the elevated
copy is always started with ``--embedded``: it owns its engine instead of
attaching to the daemon that is about to disappear.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Sequence
from ctypes import wintypes

import psutil

from .. import rpc
from ..firewall import elevated

# Used when argv[0] is not a re-runnable program (python -c, a .py file,
# pythonw). ``main()`` reads its arguments from sys.argv, so the original
# arguments can simply follow the bootstrap.
_BOOTSTRAP = "import sys; from profast.cli import main; sys.exit(main())"

_SW_SHOWNORMAL = 1
_ERROR_ACCESS_DENIED = 5

_DAEMON_NAMES = {"profastd", "profastd.exe", "profastd-py", "profastd-py.exe"}


def supported() -> bool:
    """True where there is a UAC prompt to ask with."""
    return sys.platform == "win32"


def is_elevated() -> bool:
    return elevated()


def relaunch_command(argv: Sequence[str], extra: Sequence[str] = ()) -> tuple[str, str]:
    """Map this process's argv onto ``(executable, parameters)`` for a re-launch.

    A pip console script is a real ``.exe`` and can be started again directly.
    Anything else has to go back through the interpreter. ``extra`` is inserted
    ahead of the original arguments because the CLI's global flags (``--json``,
    ``--embedded``) must precede the subcommand.
    """
    script = str(argv[0]) if argv else ""
    # ``extra`` wins: a flag already on the command line is not repeated.
    rest = [str(part) for part in argv[1:] if str(part) not in extra]
    tail = [*extra, *rest]
    if "gui" not in tail:
        # Only when the window was started straight from app.py; the normal
        # entry point already carries the subcommand.
        tail.append("gui")
    if script.lower().endswith(".exe") and os.path.isfile(script):
        return script, subprocess.list2cmdline(tail)
    return sys.executable, subprocess.list2cmdline(["-c", _BOOTSTRAP, *tail])


def relaunch(argv: Sequence[str], extra: Sequence[str] = ()) -> tuple[bool, str]:
    """Ask for elevation and start the elevated copy. Returns ``(ok, message)``."""
    if not supported():
        return False, "asking for administrator rights is only wired up on Windows"

    exe, params = relaunch_command(argv, extra)
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.argtypes = (
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    )
    shell32.ShellExecuteW.restype = wintypes.HINSTANCE
    code = int(shell32.ShellExecuteW(None, "runas", exe, params, os.getcwd(), _SW_SHOWNORMAL) or 0)
    if code > 32:
        return True, ""
    if code == _ERROR_ACCESS_DENIED:
        return False, "the request for administrator rights was cancelled"
    return False, f"Windows refused to start the elevated copy (error {code})"


def daemon_is_ours(pid: int) -> bool:
    """Guard: only ever stop a process we can positively identify as a daemon."""
    try:
        proc = psutil.Process(pid)
        name = (proc.name() or "").lower()
        if name in _DAEMON_NAMES:
            return True
        if not name.startswith("python"):
            return False
        return any("profast" in part.lower() for part in proc.cmdline())
    except psutil.Error:
        return False


def stop_daemon(timeout: float = 5.0) -> tuple[bool, str]:
    """Stop the daemon the window was attached to.

    There is no shutdown method in the protocol; both daemons treat SIGTERM as
    their stop signal, which on Windows is a terminate.
    """
    endpoint = rpc.read_endpoint()
    if not endpoint:
        return True, "no daemon was running"
    pid = int(endpoint.get("pid") or 0)
    if pid <= 0 or not daemon_is_ours(pid):
        return False, f"refused to stop pid {pid}: it does not look like a ProFast daemon"
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout)
    except psutil.NoSuchProcess:
        return True, "the daemon had already exited"
    except (psutil.Error, OSError) as exc:
        return False, f"could not stop the daemon: {exc}"
    if proc.is_running():
        return False, f"pid {pid} is still running"
    return True, "daemon stopped"
