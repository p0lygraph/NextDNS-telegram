#!/usr/bin/env python3
"""NextDNS Desktop Manager launcher.

Run the GUI with `python nextdns_manager_gui.py` or the poller with `--headless`.
Application code lives in the nextdns_manager package.
"""

from __future__ import annotations

from pathlib import Path

from nextdns_manager.cli import launch_app


if __name__ == "__main__":
    launch_app(Path(__file__).resolve().parent)
