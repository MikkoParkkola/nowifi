"""Platform abstraction -- auto-detects OS and imports correct module."""

import sys

if sys.platform == "darwin":
    from .platform_mac import *  # noqa: F401, F403
    from .platform_mac import StateGuard  # noqa: F401
elif sys.platform == "linux":
    from .platform_linux import *  # noqa: F401, F403
    from .platform_linux import StateGuard, clear_system_socks_proxy  # noqa: F401
else:
    raise RuntimeError(f"Unsupported platform: {sys.platform}")
