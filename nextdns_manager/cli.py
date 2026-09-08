"""Command line entry point."""

from __future__ import annotations

import argparse
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

from .deps import MISSING_MODULES
from .headless import run_headless
from .utils import configure_windows_gui_console


def launch_app(root_dir: Path) -> None:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--headless", action="store_true", help="Run without GUI and send Telegram alerts")
    args, _ = parser.parse_known_args()

    configure_windows_gui_console(args.headless)

    if MISSING_MODULES:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Missing Python modules",
            "Missing modules: " + ", ".join(MISSING_MODULES) + "\n\n"
            "Install them with:\n"
            "pip install requests python-dotenv",
        )
        root.destroy()
        return

    if args.headless:
        run_headless(root_dir)
        return

    # Imported lazily so headless runs never touch the GUI modules.
    from .gui.app import NextDNSManagerApp

    app = NextDNSManagerApp(root_dir=root_dir)
    app.mainloop()
