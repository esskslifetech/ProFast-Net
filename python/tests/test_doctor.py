"""doctor() must report the right firewall tool on each platform."""

import sys

from profast import cli


def test_backend_tool_on_windows(monkeypatch):
    # sys.platform is "win32" on Windows; "windows" would fall through to nft.
    monkeypatch.setattr(sys, "platform", "win32")
    assert cli.backend_tool() == "powershell"


def test_backend_tool_on_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert cli.backend_tool() == "pfctl"


def test_backend_tool_on_linux(monkeypatch):
    for platform in ("linux", "linux2", "freebsd14"):
        monkeypatch.setattr(sys, "platform", platform)
        assert cli.backend_tool() == "nft"
