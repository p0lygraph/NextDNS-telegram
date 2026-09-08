"""Settings tab: polling, threat intelligence and parsing options."""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import colorchooser, ttk
from typing import Any

from ..utils import normalize_lines
from .widgets import MultiSelectMenu


class SettingsTabMixin:
    """Settings tab behaviour for NextDNSManagerApp."""

    def _build_settings_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=0)
        self.notebook.add(tab, text="Settings")

        # Scrollable canvas wrapper so Settings tab works in small windows
        settings_canvas = tk.Canvas(tab, highlightthickness=0)
        settings_scrollbar = ttk.Scrollbar(tab, orient="vertical", command=settings_canvas.yview)
        settings_inner = ttk.Frame(settings_canvas, padding=10)

        settings_inner.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all")),
        )
        self._settings_canvas_window = settings_canvas.create_window((0, 0), window=settings_inner, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)

        settings_scrollbar.pack(side="right", fill="y")
        settings_canvas.pack(side="left", fill="both", expand=True)

        # Make inner frame stretch to canvas width
        def _on_settings_canvas_configure(event: tk.Event) -> None:
            settings_canvas.itemconfig(self._settings_canvas_window, width=event.width)
        settings_canvas.bind("<Configure>", _on_settings_canvas_configure)

        # Mousewheel scrolling
        def _on_settings_mousewheel(event: tk.Event) -> None:
            settings_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_settings_mousewheel(_event: tk.Event) -> None:
            settings_canvas.bind_all("<MouseWheel>", _on_settings_mousewheel)

        def _unbind_settings_mousewheel(_event: tk.Event) -> None:
            settings_canvas.unbind_all("<MouseWheel>")

        settings_canvas.bind("<Enter>", _bind_settings_mousewheel)
        settings_canvas.bind("<Leave>", _unbind_settings_mousewheel)

        general = ttk.LabelFrame(settings_inner, text="General and Polling", padding=12)
        general.pack(fill="x")

        settings = self.store.data["settings"]
        self.poll_interval_var = tk.IntVar(value=int(settings.get("poll_interval_seconds", 30)))
        self.autorefresh_enabled_var = tk.BooleanVar(value=bool(settings.get("autorefresh_enabled", False)))
        self.headless_continuous_var = tk.BooleanVar(value=bool(settings.get("headless_continuous", True)))
        self.log_limit_var = tk.IntVar(value=int(settings.get("log_limit_per_profile", 500)))
        self.lookback_hours_var = tk.IntVar(value=int(settings.get("log_lookback_hours", 3)))
        self.ti_enabled_var = tk.BooleanVar(value=bool(settings.get("ti_enabled", True)))
        self.ti_only_blocked_var = tk.BooleanVar(value=bool(settings.get("ti_only_blocked_domains", True)))
        self.ti_max_domains_var = tk.IntVar(value=int(settings.get("ti_max_domains_per_refresh", 80)))
        self.ti_ttl_var = tk.IntVar(value=int(settings.get("ti_cache_ttl_seconds", 1800)))
        self.include_unblocked_var = tk.BooleanVar(value=bool(settings.get("include_unblocked_logs", True)))
        self.blocked_color_mode_var = tk.StringVar(value=str(settings.get("blocked_row_color_mode", "default")))
        self.blocked_custom_color_var = tk.StringVar(value=str(settings.get("blocked_row_custom_color", "#ffd6d6")))

        ttk.Label(general, text="Poll interval (seconds)").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
        ttk.Entry(general, textvariable=self.poll_interval_var, width=12).grid(row=0, column=1, sticky="w", pady=(0, 6))

        ttk.Label(general, text="Logs limit per profile").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(general, textvariable=self.log_limit_var, width=12).grid(row=1, column=1, sticky="w", pady=6)

        ttk.Label(general, text="Log lookback (hours)").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(general, textvariable=self.lookback_hours_var, width=12).grid(row=2, column=1, sticky="w", pady=6)

        ttk.Checkbutton(general, text="Enable auto-refresh", variable=self.autorefresh_enabled_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Checkbutton(general, text="Include unblocked logs by default", variable=self.include_unblocked_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(general, text="Headless mode: continuous polling", variable=self.headless_continuous_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))

        ti = ttk.LabelFrame(settings_inner, text="Threat Intelligence", padding=12)
        ti.pack(fill="x", pady=(10, 0))

        ttk.Checkbutton(ti, text="Enable threat intelligence", variable=self.ti_enabled_var).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(ti, text="TI scan only blocked domains", variable=self.ti_only_blocked_var).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))

        ttk.Label(ti, text="Max TI domains per refresh").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(10, 0))
        ttk.Entry(ti, textvariable=self.ti_max_domains_var, width=12).grid(row=2, column=1, sticky="w", pady=(10, 0))

        ttk.Label(ti, text="TI cache TTL (seconds)").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
        ttk.Entry(ti, textvariable=self.ti_ttl_var, width=12).grid(row=3, column=1, sticky="w", pady=(6, 0))

        self.settings_ti_profiles_menu = MultiSelectMenu(ti, "Profiles", self.refresh_ti_reason_editor)
        self.settings_ti_profiles_menu.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        ti_profiles_actions = ttk.Frame(ti)
        ti_profiles_actions.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(ti_profiles_actions, text="Load TI-skip reasons", command=self.refresh_ti_reason_editor).pack(side="left")
        ttk.Button(ti_profiles_actions, text="Select all profiles", command=lambda: (self.settings_ti_profiles_menu.select_all(), self.refresh_ti_reason_editor())).pack(side="left", padx=(8, 0))
        ttk.Button(ti_profiles_actions, text="Deselect all profiles", command=lambda: (self.settings_ti_profiles_menu.deselect_all(), self.refresh_ti_reason_editor())).pack(side="left", padx=(8, 0))

        self.ti_skip_reason_menu = MultiSelectMenu(ti, "TI skip reasons", self._save_ti_skip_reason_selection)
        self.ti_skip_reason_menu.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.ti_skip_hint_var = tk.StringVar(value="If a domain is blocked only by selected reasons, TI scan is skipped.")
        ttk.Label(ti, textvariable=self.ti_skip_hint_var).grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))

        parse = ttk.LabelFrame(settings_inner, text="Domain and TLD Parsing", padding=12)
        parse.pack(fill="x", pady=(10, 0))

        ttk.Label(parse, text="Normal/popular TLDs (comma-separated)").grid(row=0, column=0, sticky="w")
        normal_text = ", ".join(self._get_normal_tlds())
        self.normal_tlds_var = tk.StringVar(value=normal_text)
        ttk.Entry(parse, textvariable=self.normal_tlds_var, width=90).grid(row=1, column=0, columnspan=3, sticky="ew", pady=(6, 0))

        color_row = ttk.Frame(parse)
        color_row.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        ttk.Label(color_row, text="Blocked row color").pack(side="left")
        ttk.Radiobutton(color_row, text="Default", value="default", variable=self.blocked_color_mode_var, command=self._update_blocked_color_preview).pack(side="left", padx=(10, 0))
        ttk.Radiobutton(color_row, text="Light red", value="light-red", variable=self.blocked_color_mode_var, command=self._update_blocked_color_preview).pack(side="left", padx=(8, 0))
        ttk.Radiobutton(color_row, text="Custom", value="custom", variable=self.blocked_color_mode_var, command=self._update_blocked_color_preview).pack(side="left", padx=(8, 0))
        ttk.Button(color_row, text="Choose color", command=self._choose_blocked_custom_color).pack(side="left", padx=(8, 0))

        self.blocked_color_preview = tk.Label(parse, text="Blocked row preview", width=24, anchor="w")
        self.blocked_color_preview.grid(row=3, column=0, sticky="w", pady=(6, 0))
        self._update_blocked_color_preview()

        actions = ttk.Frame(settings_inner)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Save settings", command=self.save_settings).pack(side="left")
        ttk.Button(actions, text="Reload TI reasons", command=self.refresh_ti_reason_editor).pack(side="left", padx=(8, 0))

        general.columnconfigure(1, weight=1)
        ti.columnconfigure(1, weight=1)
        parse.columnconfigure(0, weight=1)

    def _update_blocked_color_preview(self) -> None:
        if not hasattr(self, "blocked_color_preview"):
            return
        mode = self.blocked_color_mode_var.get() if hasattr(self, "blocked_color_mode_var") else "default"
        custom = self.blocked_custom_color_var.get() if hasattr(self, "blocked_custom_color_var") else "#ffd6d6"
        color = "#f8f8f0"
        if mode == "light-red":
            color = "#ffeaea"
        elif mode == "custom" and re.match(r"^#[0-9a-fA-F]{6}$", custom):
            color = custom
        self.blocked_color_preview.configure(bg=color)

    def _choose_blocked_custom_color(self) -> None:
        initial = self.blocked_custom_color_var.get() if hasattr(self, "blocked_custom_color_var") else "#ffd6d6"
        _rgb, chosen = colorchooser.askcolor(color=initial, title="Choose blocked-row color")
        if chosen:
            self.blocked_custom_color_var.set(chosen)
            self.blocked_color_mode_var.set("custom")
            self._update_blocked_color_preview()

    def _selected_ti_profile_ids(self) -> list[str]:
        if not hasattr(self, "settings_ti_profiles_menu"):
            return [p["id"] for p in self.profiles]
        ids = list(self.settings_ti_profiles_menu.values())
        if not ids:
            ids = [p["id"] for p in self.profiles]
        return ids

    def refresh_ti_reason_editor(self) -> None:
        profile_ids = self._selected_ti_profile_ids()
        if not profile_ids:
            if hasattr(self, "ti_skip_reason_menu"):
                self.ti_skip_reason_menu.set_options([], set())
            return

        def job() -> list[tuple[str, str]]:
            reason_map: dict[str, str] = {}
            for pid in profile_ids:
                for reason in self.nextdns.get_analytics_reasons(pid):
                    rid = str(reason.get("id", "")).strip()
                    if not rid:
                        continue
                    reason_map[rid] = str(reason.get("name", rid)).strip()
            return sorted([(rid, f"{name} ({rid})") for rid, name in reason_map.items()])

        self.submit_job("load_ti_skip_reasons", job, self._on_ti_reasons_loaded)

    def _on_ti_reasons_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Failed to load TI skip reasons: {result}")
            return
        selected = set(self.store.data["settings"].get("ti_skip_reason_ids", []))
        self.ti_skip_reason_menu.set_options(result, selected)
        self._set_status(f"Loaded {len(result)} TI reason filters")

    def _save_ti_skip_reason_selection(self) -> None:
        if not hasattr(self, "ti_skip_reason_menu"):
            return
        self.store.data["settings"]["ti_skip_reason_ids"] = sorted(list(self.ti_skip_reason_menu.values()))
        self.store.save()
        self.ti_scan_generation += 1
        self._set_status("TI skip reasons updated. Restarting TI scan...")
        if self.log_rows and self.ti_enabled_var.get() and self.store.data["settings"].get("ti_enabled", True):
            self._refresh_ti_async()

    def save_settings(self) -> None:
        try:
            self.store.data["settings"]["poll_interval_seconds"] = max(5, int(self.poll_interval_var.get()))
            self.store.data["settings"]["autorefresh_enabled"] = bool(self.autorefresh_enabled_var.get())
            self.store.data["settings"]["headless_continuous"] = bool(self.headless_continuous_var.get())
            self.store.data["settings"]["log_limit_per_profile"] = max(0, min(1000, int(self.log_limit_var.get())))
            self.store.data["settings"]["log_lookback_hours"] = max(1, min(168, int(self.lookback_hours_var.get())))
            self.store.data["settings"]["ti_enabled"] = bool(self.ti_enabled_var.get())
            self.store.data["settings"]["ti_only_blocked_domains"] = bool(self.ti_only_blocked_var.get())
            self.store.data["settings"]["ti_max_domains_per_refresh"] = max(0, int(self.ti_max_domains_var.get()))
            self.store.data["settings"]["ti_cache_ttl_seconds"] = max(30, int(self.ti_ttl_var.get()))
            if hasattr(self, "ti_skip_reason_menu"):
                self.store.data["settings"]["ti_skip_reason_ids"] = sorted(list(self.ti_skip_reason_menu.values()))
            self.store.data["settings"]["include_unblocked_logs"] = bool(self.include_unblocked_var.get())
            self.store.data["settings"]["blocked_row_color_mode"] = str(self.blocked_color_mode_var.get()).strip() or "default"
            self.store.data["settings"]["blocked_row_custom_color"] = str(self.blocked_custom_color_var.get()).strip() or "#ffd6d6"
            self.store.data["settings"]["normal_tlds"] = normalize_lines(self.normal_tlds_var.get().replace(",", "\n"))
        except (ValueError, TypeError, tk.TclError) as exc:
            self._show_error(f"Invalid settings: {exc}")
            return

        self.store.save()
        self._set_status("Settings saved")
        self._schedule_auto_refresh()
        self._update_blocked_color_preview()
        self._render_logs_table()
