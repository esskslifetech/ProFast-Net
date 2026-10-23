"""ProFast-Net control plane.

The Python package is the user-facing half of the product: CLI, dashboard,
GUI and the reference implementation of every daemon method. It speaks the
same JSON-RPC contract as the Go daemon, so the UI never cares which one is
running.
"""

from .version import PROTOCOL_VERSION, VERSION

__all__ = ["VERSION", "PROTOCOL_VERSION"]
__version__ = VERSION
