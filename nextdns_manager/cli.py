"""Command line entry point."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .deps import MISSING_MODULES
from .headless import run_headless
from .utils import configure_windows_gui_console


def launch_app(root_dir: Path) -> None:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--headless", action="store_true", help="Run without GUI and send Telegram alerts")
    parser.add_argument("--data-dir", type=str, default=None, help="Directory for state and configuration files")
    args, _ = parser.parse_known_args()

    data_dir_env = os.getenv("APP_DATA_DIR") or os.getenv("NEXTDNS_DATA_DIR")
    effective_data_dir = Path(args.data_dir or data_dir_env).resolve() if (args.data_dir or data_dir_env) else root_dir
    effective_data_dir.mkdir(parents=True, exist_ok=True)

    configure_windows_gui_console(args.headless)

    if MISSING_MODULES:
        missing_text = (
            "Missing modules: " + ", ".join(MISSING_MODULES) + "\n\n"
            "Install them with:\n"
            "pip install requests python-dotenv"
        )
        if args.headless:
            print(f"[ERROR] {missing_text}")
            return
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Missing Python modules", missing_text)
            root.destroy()
        except Exception:
            print(f"[ERROR] {missing_text}")
        return

    if args.headless:
        run_headless(effective_data_dir)
        return

    # Imported lazily so headless runs never touch the GUI modules.
    from .gui.app import NextDNSManagerApp

    app = NextDNSManagerApp(root_dir=effective_data_dir)
    app.mainloop()
