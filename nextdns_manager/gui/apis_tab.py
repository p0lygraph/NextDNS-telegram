"""APIs tab: API key entry and persistence."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class ApisTabMixin:
    """API keys tab behaviour for NextDNSManagerApp."""

    def _build_apis_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="APIs")

        card = ttk.LabelFrame(tab, text="API Keys", padding=12)
        card.pack(fill="x")

        self.api_fields: dict[str, tuple[tk.StringVar, ttk.Entry]] = {}
        rows = [
            ("nextdns_api_key", "NextDNS API key"),
            ("urlhaus_api_key", "URLHaus API key"),
            ("urlscan_api_key", "URLScan API key"),
            ("telegram_bot_token", "Telegram bot token"),
        ]

        for idx, (key, label) in enumerate(rows):
            ttk.Label(card, text=label).grid(row=idx * 2, column=0, sticky="w", pady=(0 if idx == 0 else 8, 0))
            if key == "telegram_bot_token":
                var = self.shared_telegram_token_var()
            else:
                var = tk.StringVar(value=self.store.data["api"].get(key, ""))
            entry = ttk.Entry(card, textvariable=var, show="*")
            entry.grid(row=idx * 2 + 1, column=0, sticky="ew")
            btn = ttk.Button(card, text="Show")
            btn.configure(command=lambda e=entry, b=btn: self._toggle_entry_mask(e, b))
            btn.grid(row=idx * 2 + 1, column=1, padx=(6, 0))
            self.api_fields[key] = (var, entry)

        ttk.Button(card, text="Save API settings", command=self.save_api_settings).grid(row=len(rows) * 2 + 1, column=0, sticky="w", pady=(10, 0))
        card.columnconfigure(0, weight=1)

    def _toggle_entry_mask(self, entry: ttk.Entry, btn: ttk.Button | None = None) -> None:
        current = entry.cget("show")
        entry.configure(show="" if current == "*" else "*")
        if btn:
            btn.configure(text="Hide" if current == "*" else "Show")

    def save_api_settings(self) -> None:
        for key, (var, _) in self.api_fields.items():
            self.store.data["api"][key] = var.get().strip()

        self.store.data["api"]["telegram_bot_token"] = self.telegram_token_var.get().strip()
        self.store.data["api"]["telegram_chat_id"] = self.telegram_chat_var.get().strip()

        self.store.save()
        self._set_status("API settings saved")
