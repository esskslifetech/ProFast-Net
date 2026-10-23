"""The elevation helper: command construction and the daemon-stop guard."""

import os
import sys

from profast.gui import elevate


class _FakeProc:
    def __init__(self, name: str, cmdline: list[str] | None = None) -> None:
        self._name = name
        self._cmdline = list(cmdline or [])

    def name(self) -> str:
        return self._name

    def cmdline(self) -> list[str]:
        return self._cmdline


def _console_script(tmp_path) -> str:
    """A pip console script is a real .exe, which can be started again."""
    script = tmp_path / "profast.exe"
    script.write_bytes(b"MZ")
    return str(script)


def test_command_reuses_the_console_script(tmp_path):
    exe, params = elevate.relaunch_command([_console_script(tmp_path), "gui"], ["--embedded"])
    assert exe.endswith("profast.exe")
    # Global flags must precede the subcommand or argparse rejects them.
    assert params == "--embedded gui"


def test_command_falls_back_to_the_interpreter(tmp_path):
    # "python -c ..." has no re-runnable argv[0], so the CLI is re-entered.
    exe, params = elevate.relaunch_command(["-c", "gui"], ["--embedded"])
    assert exe == sys.executable
    assert params.startswith("-c ")
    assert params.endswith("--embedded gui")


def test_command_does_not_repeat_a_flag_it_already_has(tmp_path):
    # A window started with --embedded must not hand the copy two of them.
    _exe, params = elevate.relaunch_command(
        [_console_script(tmp_path), "--embedded", "gui"], ["--embedded"]
    )
    assert params == "--embedded gui"


def test_command_adds_the_subcommand_when_missing(tmp_path):
    script = tmp_path / "app.py"
    script.write_text("")
    _exe, params = elevate.relaunch_command([str(script)], ["--embedded"])
    assert params.endswith("--embedded gui")


def test_unsupported_platform_refuses(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert elevate.supported() is False
    ok, message = elevate.relaunch(["profast", "gui"], ["--embedded"])
    assert ok is False
    assert "Windows" in message


def test_supported_platform_is_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert elevate.supported() is True


def test_guard_accepts_the_daemon_names(monkeypatch):
    for name in ("profastd.exe", "profastd", "profastd-py.exe"):
        monkeypatch.setattr(elevate.psutil, "Process", lambda _pid, n=name: _FakeProc(n))
        assert elevate.daemon_is_ours(1234) is True


def test_guard_follows_the_python_daemon_cmdline(monkeypatch):
    cmdline = [sys.executable, "-m", "profast.daemon"]
    monkeypatch.setattr(elevate.psutil, "Process", lambda _pid: _FakeProc("python.exe", cmdline))
    assert elevate.daemon_is_ours(1234) is True


def test_guard_rejects_unrelated_processes(monkeypatch):
    monkeypatch.setattr(elevate.psutil, "Process", lambda _pid: _FakeProc("explorer.exe"))
    assert elevate.daemon_is_ours(1234) is False

    other = [sys.executable, "-m", "http.server"]
    monkeypatch.setattr(elevate.psutil, "Process", lambda _pid: _FakeProc("python.exe", other))
    assert elevate.daemon_is_ours(1234) is False


def test_guard_rejects_a_dead_pid(monkeypatch):
    def boom(_pid):
        raise elevate.psutil.NoSuchProcess(_pid)

    monkeypatch.setattr(elevate.psutil, "Process", boom)
    assert elevate.daemon_is_ours(1234) is False


def test_stop_daemon_is_a_no_op_without_one(monkeypatch):
    monkeypatch.setattr(elevate.rpc, "read_endpoint", lambda: None)
    assert elevate.stop_daemon() == (True, "no daemon was running")


def test_stop_daemon_refuses_a_foreign_process(monkeypatch):
    # A stale or hand-edited endpoint file must never turn into a kill.
    monkeypatch.setattr(elevate.rpc, "read_endpoint", lambda: {"pid": 4242})
    monkeypatch.setattr(elevate, "daemon_is_ours", lambda _pid: False)
    ok, message = elevate.stop_daemon()
    assert ok is False
    assert "refused" in message


def test_stop_daemon_terminates_our_daemon(monkeypatch):
    class _Stoppable(_FakeProc):
        def terminate(self) -> None:
            self.stopped = True

        def wait(self, _timeout: float) -> None:
            return None

        def is_running(self) -> bool:
            return False

    proc = _Stoppable("profastd.exe")
    monkeypatch.setattr(elevate.rpc, "read_endpoint", lambda: {"pid": os.getpid()})
    monkeypatch.setattr(elevate, "daemon_is_ours", lambda _pid: True)
    monkeypatch.setattr(elevate.psutil, "Process", lambda _pid: proc)
    assert elevate.stop_daemon() == (True, "daemon stopped")
    assert getattr(proc, "stopped", False) is True
