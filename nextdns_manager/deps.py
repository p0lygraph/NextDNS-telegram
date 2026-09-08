"""Optional third-party dependencies, resolved once at import time."""

from __future__ import annotations

from typing import Any


MISSING_MODULES: list[str] = []
requests: Any

try:
    import requests as _requests
    requests = _requests
except ImportError:
    requests = None  # type: ignore[assignment]
    MISSING_MODULES.append("requests")

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> bool:  # type: ignore[no-redef]
        return False

    MISSING_MODULES.append("python-dotenv")

if not MISSING_MODULES:
    load_dotenv()
