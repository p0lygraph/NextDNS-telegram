"""Alerts tab: Telegram delivery, reason overrides and ignore patterns."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from ..alerts import AlertBatchQP, format_batch_message_qp
from ..constants import APP_TIMEOUT, APP_TITLE
from ..deps import requests
from ..telegram_bot import redact_telegram_token, send_alert_message
from ..threat_intel import queryparser_enrichment_sync
from ..utils import (
    collect_context_qp,
    domain_matches_pattern,
    format_timestamp_display,
    get_event_key_qp,
    is_valid_domain_pattern,
    normalize_domain,
    normalize_lines,
    now_iso,
    row_is_blocked,
)
from .widgets import MultiSelectMenu


class AlertsTabMixin:
    """Alerts tab behaviour for NextDNSManagerApp."""

    def _build_alerts_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Alerts")

        alerts_canvas = tk.Canvas(tab, highlightthickness=0)
        alerts_scrollbar = ttk.Scrollbar(tab, orient="vertical", command=alerts_canvas.yview)
        alerts_inner = ttk.Frame(alerts_canvas, padding=(0, 0, 0, 10))

        alerts_inner.bind(
            "<Configure>",
            lambda e: alerts_canvas.configure(scrollregion=alerts_canvas.bbox("all")),
        )
        self._alerts_canvas_window = alerts_canvas.create_window((0, 0), window=alerts_inner, anchor="nw")
        alerts_canvas.configure(yscrollcommand=alerts_scrollbar.set)

        alerts_scrollbar.pack(side="right", fill="y")
        alerts_canvas.pack(side="left", fill="both", expand=True)

        def _on_alerts_canvas_configure(event: tk.Event) -> None:
            alerts_canvas.itemconfig(self._alerts_canvas_window, width=event.width)

        alerts_canvas.bind("<Configure>", _on_alerts_canvas_configure)

        def _on_alerts_mousewheel(event: tk.Event) -> None:
            alerts_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_alerts_mousewheel(_event: tk.Event) -> None:
            alerts_canvas.bind_all("<MouseWheel>", _on_alerts_mousewheel)

        def _unbind_alerts_mousewheel(_event: tk.Event) -> None:
            alerts_canvas.unbind_all("<MouseWheel>")

        alerts_canvas.bind("<Enter>", _bind_alerts_mousewheel)
        alerts_canvas.bind("<Leave>", _unbind_alerts_mousewheel)

        top = ttk.LabelFrame(alerts_inner, text="Telegram Delivery", padding=12)
        top.pack(fill="x")

        self.telegram_enabled = tk.BooleanVar(value=self.store.data["ui"].get("enabled_telegram_alerts", False))
        ttk.Checkbutton(top, text="Enable Telegram alerts", variable=self.telegram_enabled, command=self._save_ui_state).grid(row=0, column=0, sticky="w")

        ttk.Label(top, text="Bot token").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.telegram_token_var = tk.StringVar(value=self.store.data["api"].get("telegram_bot_token", ""))
        ttk.Entry(top, textvariable=self.telegram_token_var, show="*").grid(row=2, column=0, sticky="ew")

        ttk.Label(top, text="Chat ID").grid(row=1, column=1, sticky="w", pady=(8, 0), padx=(10, 0))
        self.telegram_chat_var = tk.StringVar(value=self.store.data["api"].get("telegram_chat_id", ""))
        ttk.Entry(top, textvariable=self.telegram_chat_var).grid(row=2, column=1, sticky="ew", padx=(10, 0))

        controls = ttk.Frame(top)
        controls.grid(row=0, column=1, sticky="e", padx=(10, 0))
        ttk.Button(controls, text="Send test alert", command=self.send_test_alert).pack(side="right")
        ttk.Button(controls, text="Save Telegram settings", command=self.save_api_settings).pack(side="right", padx=(0, 6))

        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=1)

        reason_card = ttk.LabelFrame(alerts_inner, text="Alert Ignore Rules (DNS Blocking Reasons)", padding=12)
        reason_card.pack(fill="both", expand=True, pady=(10, 0))

        toolbar = ttk.Frame(reason_card)
        toolbar.pack(fill="x")
        self.alert_profiles_menu = MultiSelectMenu(toolbar, "Profiles", self._on_alert_profiles_changed)
        self.alert_profiles_menu.pack(side="left")
        ttk.Button(toolbar, text="Load reasons", command=self.refresh_alert_reason_editor).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Save to selected profiles", command=self.save_alert_reason_overrides).pack(side="left", padx=(8, 0))
        ttk.Button(toolbar, text="Clear profile override (use global rules)", command=self.clear_alert_reason_overrides).pack(side="left", padx=(8, 0))


        self.alert_reason_hint_var = tk.StringVar(value="Global rules are in state.json: disabled_reasons. Profile override replaces global list only for selected profiles.")
        ttk.Label(reason_card, textvariable=self.alert_reason_hint_var).pack(anchor="w", pady=(8, 0))

        self.alert_reason_menu = MultiSelectMenu(reason_card, "Ignored reasons", self._save_alert_reason_overrides)
        self.alert_reason_menu.pack(fill="x", pady=(8, 0))

        self.alert_profile_overview = ttk.Treeview(reason_card, columns=["profile", "mode", "count"], show="headings", height=8)
        for col, width in [("profile", 260), ("mode", 140), ("count", 120)]:
            self.alert_profile_overview.heading(col, text=col.title())
            self.alert_profile_overview.column(col, width=width, stretch=True)
        self.alert_profile_overview.pack(fill="both", expand=True, pady=(10, 0))

        domain_card = ttk.LabelFrame(alerts_inner, text="Ignored Domains for Alerts", padding=12)
        domain_card.pack(fill="both", expand=True, pady=(10, 0))

        domain_toolbar = ttk.Frame(domain_card)
        domain_toolbar.pack(fill="x")
        self.alert_ignore_profiles_menu = MultiSelectMenu(domain_toolbar, "Profiles", self._on_alert_ignore_profiles_changed)
        self.alert_ignore_profiles_menu.pack(side="left")
        ttk.Button(domain_toolbar, text="Reload patterns", command=self.refresh_alert_ignored_domain_editor).pack(side="left", padx=(8, 0))

        self.alert_ignore_hint_var = tk.StringVar(value="Ignore patterns apply to selected profiles below. Supports domain.tld and *.domain.tld")
        ttk.Label(domain_card, textvariable=self.alert_ignore_hint_var).pack(anchor="w")

        domain_controls = ttk.Frame(domain_card)
        domain_controls.pack(fill="x", pady=(8, 0))

        self.alert_ignore_domain_var = tk.StringVar(value="")
        ttk.Entry(domain_controls, textvariable=self.alert_ignore_domain_var, width=42).pack(side="left", fill="x", expand=True)
        ttk.Button(domain_controls, text="Add pattern", command=self.add_alert_ignored_domain).pack(side="left", padx=(8, 0))
        ttk.Button(domain_controls, text="Remove selected", command=self.remove_selected_alert_ignored_domains).pack(side="left", padx=(8, 0))
        ttk.Button(domain_controls, text="Delete all in selected profiles", command=self.clear_alert_ignored_domains).pack(side="left", padx=(8, 0))

        domain_file_controls = ttk.Frame(domain_card)
        domain_file_controls.pack(fill="x", pady=(8, 0))
        ttk.Button(domain_file_controls, text="Import from file", command=self.import_alert_ignored_domains).pack(side="left")
        ttk.Button(domain_file_controls, text="Export merged", command=self.export_alert_ignored_domains).pack(side="left", padx=(8, 0))

        domain_table_wrap = ttk.Frame(domain_card)
        domain_table_wrap.pack(fill="both", expand=True, pady=(8, 0))

        self.alert_ignore_table = ttk.Treeview(domain_table_wrap, columns=["pattern", "profiles"], show="headings", height=7)
        self.alert_ignore_table.heading("pattern", text="Pattern", command=lambda: self._sort_tree(self.alert_ignore_table, "pattern", False))
        self.alert_ignore_table.heading("profiles", text="Applies to", command=lambda: self._sort_tree(self.alert_ignore_table, "profiles", False))
        self.alert_ignore_table.column("pattern", width=280, stretch=True)
        self.alert_ignore_table.column("profiles", width=360, stretch=True)

        alert_ignore_scroll = ttk.Scrollbar(domain_table_wrap, orient="vertical", command=self.alert_ignore_table.yview)
        alert_ignore_scroll.pack(side="right", fill="y")
        self.alert_ignore_table.pack(side="left", fill="both", expand=True)
        self.alert_ignore_table.configure(yscrollcommand=alert_ignore_scroll.set)

    def _selected_alert_profile_ids(self) -> list[str]:
        ids = list(self.alert_profiles_menu.values())
        if not ids:
            ids = [p["id"] for p in self.profiles]
        return ids

    def _selected_alert_profiles(self) -> list[dict[str, Any]]:
        ids = set(self._selected_alert_profile_ids())
        return [p for p in self.profiles if p["id"] in ids]

    def _on_alert_profiles_changed(self) -> None:
        self._save_ui_state()
        self.refresh_alert_reason_editor()

    def _selected_alert_ignore_profile_ids(self) -> list[str]:
        if not hasattr(self, "alert_ignore_profiles_menu"):
            return [p["id"] for p in self.profiles]
        ids = list(self.alert_ignore_profiles_menu.values())
        if not ids:
            ids = [p["id"] for p in self.profiles]
        return ids

    def _selected_alert_ignore_profiles(self) -> list[dict[str, Any]]:
        ids = set(self._selected_alert_ignore_profile_ids())
        return [p for p in self.profiles if p["id"] in ids]

    def _on_alert_ignore_profiles_changed(self) -> None:
        self._save_ui_state()
        self.refresh_alert_ignored_domain_editor()

    def _selected_alert_ignore_patterns(self) -> list[str]:
        selected: list[str] = []
        if not hasattr(self, "alert_ignore_table"):
            return selected
        for iid in self.alert_ignore_table.selection():
            values = self.alert_ignore_table.item(iid, "values")
            if values and values[0]:
                selected.append(str(values[0]).strip().lower())
        return selected

    def refresh_alert_ignored_domain_editor(self) -> None:
        if not hasattr(self, "alert_ignore_table"):
            return

        selected_profiles = self._selected_alert_ignore_profiles()
        for item in self.alert_ignore_table.get_children():
            self.alert_ignore_table.delete(item)

        if not selected_profiles:
            self.alert_ignore_hint_var.set("No profiles selected.")
            return

        pattern_map: dict[str, list[str]] = {}
        for profile in selected_profiles:
            profile_name = str(profile.get("name", profile["id"]))
            for pattern in self.legacy_state.get_ignore_patterns(profile["id"]):
                pattern_map.setdefault(pattern, []).append(profile_name)

        for idx, pattern in enumerate(sorted(pattern_map.keys())):
            names = sorted(set(pattern_map[pattern]))
            profiles_text = ", ".join(names)
            self.alert_ignore_table.insert("", "end", iid=f"alert_ignore_{idx}", values=(pattern, profiles_text))

        self.alert_ignore_hint_var.set(f"Loaded {len(pattern_map)} ignore pattern(s) for selected profiles.")

    def add_alert_ignored_domain(self) -> None:
        pattern = normalize_domain(self.alert_ignore_domain_var.get())
        if not is_valid_domain_pattern(pattern):
            self._show_error("Invalid pattern. Use domain.tld or *.domain.tld")
            return

        profile_ids = self._selected_alert_ignore_profile_ids()
        if not profile_ids:
            self._show_error("No profiles selected")
            return

        changed = 0
        with self.legacy_state.lock:
            for profile_id in profile_ids:
                current = self.legacy_state.get_ignore_patterns(profile_id)
                if pattern in current:
                    continue
                self.legacy_state.set_ignore_patterns(profile_id, current | {pattern})
                changed += 1

        self.legacy_state.save()

        self.alert_ignore_domain_var.set("")
        self.refresh_alert_ignored_domain_editor()
        self._set_status(f"Ignore pattern saved for {changed} profile(s)")

    def remove_selected_alert_ignored_domains(self) -> None:
        patterns = set(self._selected_alert_ignore_patterns())
        if not patterns:
            self._show_error("Select one or more patterns to remove")
            return

        profile_ids = self._selected_alert_ignore_profile_ids()
        changed = 0
        with self.legacy_state.lock:
            for profile_id in profile_ids:
                current = self.legacy_state.get_ignore_patterns(profile_id)
                updated = current - patterns
                if updated != current:
                    self.legacy_state.set_ignore_patterns(profile_id, updated)
                    changed += 1

        self.legacy_state.save()

        self.refresh_alert_ignored_domain_editor()
        self._set_status(f"Removed selected patterns from {changed} profile(s)")

    def clear_alert_ignored_domains(self) -> None:
        profile_ids = self._selected_alert_ignore_profile_ids()
        if not profile_ids:
            self._show_error("No profiles selected")
            return

        values_to_delete = 0
        profiles_with_data = 0
        for profile_id in profile_ids:
            current = self.legacy_state.get_ignore_patterns(profile_id)
            if current:
                profiles_with_data += 1
                values_to_delete += len(current)

        if values_to_delete == 0:
            self._set_status("Nothing to delete in selected profiles")
            return

        confirmed = messagebox.askyesno(
            APP_TITLE,
            (
                f"This will delete {values_to_delete} ignored domain pattern(s) "
                f"from {profiles_with_data} selected profile(s).\n\nContinue?"
            ),
            icon="warning",
        )
        if not confirmed:
            self._set_status("Delete canceled")
            return

        cleared = 0
        with self.legacy_state.lock:
            for profile_id in profile_ids:
                if self.legacy_state.get_ignore_patterns(profile_id):
                    self.legacy_state.set_ignore_patterns(profile_id, set())
                    cleared += 1

        self.legacy_state.save()

        self.refresh_alert_ignored_domain_editor()
        self._set_status(f"Cleared ignore patterns for {cleared} profile(s)")

    def import_alert_ignored_domains(self) -> None:
        path = filedialog.askopenfilename(title="Import ignored domains", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return

        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, PermissionError, UnicodeDecodeError) as exc:
            self._show_error(f"Cannot read file: {exc}")
            return

        imported: list[str] = []
        invalid = 0
        for line in normalize_lines(text):
            pattern = normalize_domain(line)
            if is_valid_domain_pattern(pattern):
                imported.append(pattern)
            else:
                invalid += 1

        imported_set = set(imported)
        if not imported_set:
            self._show_error("Import file has no valid patterns")
            return

        profile_ids = self._selected_alert_ignore_profile_ids()
        if not profile_ids:
            self._show_error("No profiles selected")
            return

        changed = 0
        with self.legacy_state.lock:
            for profile_id in profile_ids:
                current = self.legacy_state.get_ignore_patterns(profile_id)
                updated = current | imported_set
                if updated != current:
                    self.legacy_state.set_ignore_patterns(profile_id, updated)
                    changed += 1

        self.legacy_state.save()

        self.refresh_alert_ignored_domain_editor()
        self._set_status(f"Imported {len(imported_set)} pattern(s) to {changed} profile(s); invalid lines: {invalid}")

    def export_alert_ignored_domains(self) -> None:
        if not hasattr(self, "alert_ignore_table"):
            return

        patterns: list[str] = []
        for iid in self.alert_ignore_table.get_children():
            values = self.alert_ignore_table.item(iid, "values")
            if values and values[0]:
                patterns.append(str(values[0]).strip().lower())

        patterns = sorted(set(patterns))
        if not patterns:
            self._show_error("No patterns to export")
            return

        path = filedialog.asksaveasfilename(
            title="Export ignored domains",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                for pattern in patterns:
                    f.write(f"{pattern}\n")
        except (OSError, PermissionError) as exc:
            self._show_error(f"Export failed: {exc}")
            return

        self._set_status(f"Exported {len(patterns)} ignore pattern(s)")

    def refresh_alert_reason_editor(self) -> None:
        selected_profiles = self._selected_alert_profiles()
        if not selected_profiles:
            self.alert_reason_menu.set_options([], set())
            self.alert_reason_hint_var.set("No profiles selected.")
            return

        def job() -> tuple[list[tuple[str, str]], dict[str, list[str]]]:
            union_reasons: dict[str, str] = {}
            profile_modes: dict[str, list[str]] = {}
            for profile in selected_profiles:
                reasons = self.nextdns.get_analytics_reasons(profile["id"])
                for reason in reasons:
                    reason_id = str(reason.get("id", "")).strip()
                    if not reason_id:
                        continue
                    union_reasons[reason_id] = str(reason.get("name", reason_id))
                profile_modes[profile["id"]] = self.legacy_state.get_disabled_reasons(profile["id"])
            return sorted([(rid, f"{name} ({rid})") for rid, name in union_reasons.items()]), profile_modes

        self.submit_job("load_alert_reasons", job, self._on_alert_reasons_loaded)

    def _on_alert_reasons_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Failed to load alert reasons: {result}")
            return

        reason_options, profile_modes = result
        first_profile = self._selected_alert_profiles()[0] if self._selected_alert_profiles() else None
        selected_reason_ids = set(profile_modes.get(first_profile["id"], [])) if first_profile else set()
        self.alert_reason_menu.set_options(reason_options, selected_reason_ids)
        self._refresh_alert_profile_overview(profile_modes)

    def _refresh_alert_profile_overview(self, profile_modes: dict[str, list[str]]) -> None:
        for item in self.alert_profile_overview.get_children():
            self.alert_profile_overview.delete(item)
        for profile in self._selected_alert_profiles():
            reasons = profile_modes.get(profile["id"], [])
            legacy_cfg = self.legacy_state.get_profile(profile["id"])
            mode = "custom" if legacy_cfg.get("disabled_reasons_custom") is not None else "global"
            self.alert_profile_overview.insert("", "end", values=(f"{profile.get('name', profile['id'])} ({profile['id']})", mode, len(reasons)))

    def save_alert_reason_overrides(self) -> None:
        profile_ids = self._selected_alert_profile_ids()
        reason_ids = sorted(list(self.alert_reason_menu.values()))
        self.legacy_state.set_disabled_reasons(profile_ids, reason_ids)
        self.legacy_state.save()
        self._set_status("Alert filter overrides saved")
        self.refresh_alert_reason_editor()

    def _save_alert_reason_overrides(self) -> None:
        self.save_alert_reason_overrides()

    def clear_alert_reason_overrides(self) -> None:
        profile_ids = self._selected_alert_profile_ids()
        self.legacy_state.clear_disabled_reasons_override(profile_ids)
        self.legacy_state.save()
        self._set_status("Alert filter overrides cleared")
        self.refresh_alert_reason_editor()

    def send_test_alert(self) -> None:
        token = self.telegram_token_var.get().strip()
        chat_id = self.telegram_chat_var.get().strip()
        if not token or not chat_id:
            self._show_error("Fill Telegram token and chat ID first")
            return

        self._set_status("Sending Telegram test alert...")

        def job() -> tuple[bool, str]:
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = {"chat_id": chat_id, "text": f"{APP_TITLE}: test alert ({now_iso()})"}
                resp = requests.post(url, json=payload, timeout=APP_TIMEOUT)
                if resp.status_code == 200:
                    return True, "Test alert sent"
                return False, f"Telegram API error ({resp.status_code})"
            except requests.RequestException as exc:
                return False, f"Telegram request failed: {redact_telegram_token(str(exc), token)}"

        self.submit_job("telegram_test", job, lambda p: self._on_simple_action_result("Telegram test", p, lambda: None))

    def _send_startup_alert(self) -> None:
        token = self.telegram_token_var.get().strip()
        chat_id = self.telegram_chat_var.get().strip()
        if not token or not chat_id:
            return

        def job() -> tuple[bool, str]:
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                payload = {"chat_id": chat_id, "text": f"{APP_TITLE} started at {format_timestamp_display(now_iso())}"}
                resp = requests.post(url, json=payload, timeout=APP_TIMEOUT)
                if resp.status_code == 200:
                    return True, "Startup Telegram alert sent"
                return False, f"Telegram API error ({resp.status_code})"
            except requests.RequestException as exc:
                return False, f"Startup Telegram alert failed: {redact_telegram_token(str(exc), token)}"

        self.submit_job("telegram_startup", job, lambda p: self._on_simple_action_result("Telegram startup alert", p, lambda: None))

    def _dispatch_alerts_async(self, rows: list[dict[str, Any]]) -> None:
        if self.pause_event.is_set() or not self.telegram_enabled.get():
            return

        token = self.telegram_token_var.get().strip()
        chat_id = self.telegram_chat_var.get().strip()
        if not token or not chat_id:
            return

        batches: dict[str, AlertBatchQP] = {}
        ignore_cache: dict[str, set[str]] = {}
        disabled_cache: dict[str, set[str]] = {}

        for row in rows:
            if self.pause_event.is_set():
                return
            if not row_is_blocked(row):
                continue

            profile_id = str(row.get("profile_id", ""))
            profile_name = str(row.get("profile", ""))
            if profile_id not in ignore_cache:
                ignore_cache[profile_id] = self.legacy_state.get_ignore_patterns(profile_id)
                disabled_cache[profile_id] = set(self.legacy_state.get_disabled_reasons(profile_id))
            ignorelist = ignore_cache[profile_id]
            disabled_reasons = disabled_cache[profile_id]
            domain = str(row.get("domain", ""))

            if any(domain_matches_pattern(domain, p) for p in ignorelist):
                continue

            reason_ids = [s.strip() for s in str(row.get("reason_ids", "")).split(",") if s.strip()]
            if reason_ids and all(rid in disabled_reasons for rid in reason_ids):
                continue

            event = {
                "timestamp": row.get("timestamp_raw", row.get("timestamp", "")),
                "domain": domain,
                "clientIp": row.get("ip", ""),
            }
            event_key = get_event_key_qp(event, profile_id)
            if self.event_cache.contains(event_key):
                continue
            self.event_cache.add(event_key)

            batch_key = f"{profile_id}|{domain}"
            if batch_key in batches:
                b = batches[batch_key]
                b.count += 1
                b.last_timestamp = str(row.get("timestamp_raw", row.get("timestamp", "")))
                b.devices.add(str(row.get("device_name", "") or "Unknown"))
                b.reasons.update([s.strip() for s in str(row.get("reason", "")).split(",") if s.strip()])
                b.reason_ids.update(reason_ids)
            else:
                batches[batch_key] = AlertBatchQP(
                    domain=domain,
                    profile_id=profile_id,
                    profile_name=profile_name,
                    first_event_index=int(row.get("event_index", 0)),
                    first_timestamp=str(row.get("timestamp_raw", row.get("timestamp", ""))),
                    last_timestamp=str(row.get("timestamp_raw", row.get("timestamp", ""))),
                    count=1,
                    devices={str(row.get("device_name", "") or "Unknown")},
                    reasons=set([s.strip() for s in str(row.get("reason", "")).split(",") if s.strip()]),
                    reason_ids=set(reason_ids),
                )

        if not batches:
            return

        candidates = list(batches.values())

        self._set_status(f"Sending Telegram alerts: 0/{len(candidates)}")

        raw_logs_snapshot = dict(self.profile_raw_logs)

        def job() -> int:
            sent = 0
            for idx, batch in enumerate(candidates, start=1):
                if self.pause_event.is_set():
                    break
                enrichment = self._queryparser_enrichment(batch.domain)
                raw_logs = raw_logs_snapshot.get(batch.profile_id, [])
                if raw_logs and 0 <= batch.first_event_index < len(raw_logs):
                    context = collect_context_qp(raw_logs, batch.first_event_index, raw_logs[batch.first_event_index])
                else:
                    context = {"before": [], "after": [], "header": "Surrounding DNS Queries:"}
                msg = format_batch_message_qp(batch, enrichment, context)
                if send_alert_message(token, chat_id, self.legacy_state, batch, msg):
                    sent += 1
                if idx == 1 or idx % 5 == 0 or idx == len(candidates):
                    self._publish_progress(f"Sending Telegram alerts: {idx}/{len(candidates)}")
            return sent

        self.submit_job("telegram_alerts", job, self._on_alert_batch_done)

    def _on_alert_batch_done(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._set_status(f"Telegram alerts failed: {result}")
            return

        self._set_status(f"Telegram alerts sent: {result}")

    def _queryparser_enrichment(self, domain: str) -> str:
        return queryparser_enrichment_sync(
            domain,
            self.store.data["api"].get("urlhaus_api_key", "").strip(),
            self.store.data["api"].get("urlscan_api_key", "").strip(),
        )
