"""Logs tab: fetching, filtering, rendering and row actions."""

from __future__ import annotations

import re
import time
import tkinter as tk
from tkinter import ttk
from typing import Any

from ..constants import ALL_LOG_COLUMNS, BLOCKED_STATUSES, DEFAULT_LOG_COLUMNS, MAX_LOG_ROWS_IN_MEMORY
from ..utils import (
    build_row_search_blob,
    extract_device_info,
    format_timestamp_display,
    parse_domain_tld,
    parse_epoch_seconds,
    row_is_blocked,
)
from .widgets import MultiSelectMenu


class LogsTabMixin:
    """Logs tab behaviour for NextDNSManagerApp."""

    def _build_logs_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Logs")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill="x")

        source_row = ttk.Frame(toolbar)
        source_row.pack(fill="x")

        filter_row = ttk.Frame(toolbar)
        filter_row.pack(fill="x", pady=(6, 0))

        self.logs_profiles_menu = MultiSelectMenu(source_row, "Profiles", self._on_logs_filter_change)
        self.logs_profiles_menu.pack(side="left", fill="x", expand=False)

        self.logs_devices_menu = MultiSelectMenu(source_row, "Devices", self._on_logs_filter_change)
        self.logs_devices_menu.pack(side="left", fill="x", expand=False, padx=(8, 0))
        self.logs_devices_menu.set_options([], set(self.store.data["ui"].get("selected_devices", [])))

        ttk.Label(source_row, text="Search:").pack(side="left", padx=(10, 4))
        self.logs_search_var = tk.StringVar(value=self.store.data["ui"].get("logs_search", ""))
        logs_search_entry = ttk.Entry(source_row, textvariable=self.logs_search_var, width=34)
        logs_search_entry.pack(side="left")
        logs_search_entry.bind("<KeyRelease>", lambda _: self._debounce("logs_search", 250, self._on_logs_filter_change))

        self.logs_blocked_only = tk.BooleanVar(value=self.store.data["ui"]["logs_filters"].get("blocked_only", False))
        self.logs_malicious_only = tk.BooleanVar(value=self.store.data["ui"]["logs_filters"].get("malicious_only", False))
        self.logs_unusual_only = tk.BooleanVar(value=self.store.data["ui"]["logs_filters"].get("unusual_tld_only", False))
        self.logs_ignore_reasons = tk.BooleanVar(value=self.store.data["ui"]["logs_filters"].get("ignore_selected_reasons", True))

        ttk.Checkbutton(filter_row, text="Blocked only", variable=self.logs_blocked_only, command=self._on_logs_filter_change).pack(side="left")
        ttk.Checkbutton(filter_row, text="Malicious only", variable=self.logs_malicious_only, command=self._on_logs_filter_change).pack(side="left", padx=(8, 0))
        ttk.Checkbutton(filter_row, text="Unusual TLD only", variable=self.logs_unusual_only, command=self._on_logs_filter_change).pack(side="left", padx=(8, 0))

        self.reason_menu = MultiSelectMenu(filter_row, "Ignored reasons", self._on_logs_filter_change)
        self.reason_menu.pack(side="left", padx=(10, 0))
        ttk.Checkbutton(filter_row, text="Apply ignored reasons", variable=self.logs_ignore_reasons, command=self._on_logs_filter_change).pack(side="left", padx=(8, 0))

        ttk.Button(source_row, text="Columns", command=self._show_column_selector).pack(side="right")
        ttk.Button(source_row, text="Refresh", command=self.refresh_logs).pack(side="right", padx=(6, 6))

        table_frame = ttk.Frame(tab)
        table_frame.pack(fill="both", expand=True, pady=(8, 0))

        self.logs_table = ttk.Treeview(table_frame, show="headings", selectmode="browse")
        self.logs_table.bind("<Button-3>", self._show_logs_context_menu)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.logs_table.yview)
        yscroll.pack(side="right", fill="y")
        
        self.logs_table.pack(side="left", fill="both", expand=True)
        self.logs_table.configure(yscrollcommand=yscroll.set)

        self.logs_context_menu = tk.Menu(self, tearoff=0)
        self.logs_context_menu.add_command(label="Block domain", command=self._ctx_block_domain)
        self.logs_context_menu.add_command(label="Unblock domain", command=self._ctx_unblock_domain)

        copy_sub = tk.Menu(self.logs_context_menu, tearoff=0)
        copy_sub.add_command(label="Copy full row", command=lambda: self._copy_log_row("all"))
        copy_sub.add_command(label="Copy domain", command=lambda: self._copy_log_row("domain"))
        copy_sub.add_command(label="Copy device", command=lambda: self._copy_log_row("device"))
        copy_sub.add_command(label="Copy profile", command=lambda: self._copy_log_row("profile"))
        copy_sub.add_command(label="Copy reason", command=lambda: self._copy_log_row("reason"))
        self.logs_context_menu.add_cascade(label="Copy", menu=copy_sub)

    def _selected_profiles(self) -> list[dict[str, Any]]:
        ids = self.logs_profiles_menu.values()
        if not ids:
            ids = {p["id"] for p in self.profiles}
        return [p for p in self.profiles if p["id"] in ids]

    def refresh_logs(self) -> None:
        selected_profiles = self._selected_profiles()
        if not selected_profiles:
            self._set_status("No profiles selected")
            return

        self._save_ui_state()
        settings = self.store.data["settings"]
        limit = int(settings.get("log_limit_per_profile", 500))
        include_unblocked = bool(settings.get("include_unblocked_logs", True))
        lookback_seconds = max(1, int(settings.get("log_lookback_hours", 3))) * 3600
        self._set_status("Loading logs...")

        def fetch_since_paginated(profile_id: str, from_ts: int) -> tuple[list[dict[str, Any]], int]:
            all_logs: list[dict[str, Any]] = []
            current_from = max(0, int(from_ts))
            newest_seen = max(0, int(from_ts) - 1)
            while True:
                page = self.nextdns.get_logs_since(profile_id, current_from, limit=1000)
                if not page:
                    break
                all_logs.extend(page)
                page_max = max([parse_epoch_seconds(str(item.get("timestamp", ""))) for item in page] + [newest_seen])
                if page_max <= newest_seen:
                    break
                newest_seen = page_max
                current_from = newest_seen + 1
                if len(page) < 1000:
                    break
            return all_logs, newest_seen

        def job() -> tuple[list[dict[str, Any]], list[Any], dict[str, list[dict[str, Any]]]]:
            rows: list[dict[str, Any]] = []
            reason_map: dict[str, str] = {}
            raw_logs_map: dict[str, list[dict[str, Any]]] = {}
            state_changed = False

            for p_idx, p in enumerate(selected_profiles, start=1):
                if self.pause_event.is_set():
                    return rows, sorted([(rid, f"{reason_map[rid]} ({rid})") for rid in reason_map.keys()]), raw_logs_map
                self._publish_progress(f"Parsing logs: profile {p_idx}/{len(selected_profiles)} ({p.get('name', p['id'])})")

                profile_id = p["id"]
                with self.legacy_state.lock:
                    cfg = self.legacy_state.get_profile(profile_id)
                    cursor = str(cfg.get("cursor", "") or "").strip() or None
                    last_success_ts = int(cfg.get("last_success_ts") or 0)
                latest_ts = last_success_ts

                for r in self.nextdns.get_analytics_reasons(p["id"]):
                    rid = str(r.get("id", "")).strip()
                    if not rid:
                        continue
                    rname = str(r.get("name", rid)).strip()
                    reason_map[rid] = rname

                logs: list[dict[str, Any]] = []
                if limit == 0:
                    if cursor:
                        current_cursor = cursor
                        while True:
                            page, new_cursor = self.nextdns.get_logs_cursor(profile_id, cursor=current_cursor)
                            if page:
                                logs.extend(page)
                                latest_ts = max(latest_ts, max(parse_epoch_seconds(str(item.get("timestamp", ""))) for item in page))

                            if new_cursor and new_cursor != current_cursor:
                                current_cursor = new_cursor
                                self.legacy_state.update_profile(profile_id, cursor=new_cursor)
                                state_changed = True

                            if not page or len(page) < 1000:
                                break
                    elif last_success_ts > 0:
                        # Lookback caps the backlog fetched after a long downtime.
                        start_ts = max(last_success_ts + 1, int(time.time()) - lookback_seconds)
                        logs, latest_seen = fetch_since_paginated(profile_id, start_ts)
                        latest_ts = max(latest_ts, latest_seen)
                    else:
                        bootstrap_logs = self.nextdns.get_logs(profile_id, limit=1)
                        if bootstrap_logs:
                            latest_ts = max(latest_ts, max(parse_epoch_seconds(str(item.get("timestamp", ""))) for item in bootstrap_logs))
                else:
                    bootstrap_logs = self.nextdns.get_logs(profile_id, limit=limit)
                    logs = list(reversed(bootstrap_logs))
                    if logs:
                        latest_ts = max(latest_ts, max(parse_epoch_seconds(str(item.get("timestamp", ""))) for item in logs))

                if limit == 0 and latest_ts > 0 and latest_ts != last_success_ts:
                    self.legacy_state.update_profile(profile_id, last_success_ts=latest_ts)
                    state_changed = True

                raw_logs_map[profile_id] = logs
                for profile_event_index, item in enumerate(logs):
                    reason_objs = item.get("reasons", []) or []
                    rids = [r.get("id", "") for r in reason_objs if isinstance(r, dict)]
                    for r in reason_objs:
                        if isinstance(r, dict):
                            rid = str(r.get("id", "")).strip()
                            if rid:
                                reason_map[rid] = str(r.get("name", rid)).strip()

                    raw_status = str(item.get("status", "")).strip().lower()
                    status_value = "allowed" if raw_status in {"", "default"} else raw_status
                    if not include_unblocked and status_value not in BLOCKED_STATUSES:
                        continue

                    device_id, device_name = extract_device_info(item)

                    row = {
                        "timestamp": format_timestamp_display(str(item.get("timestamp", ""))),
                        "timestamp_raw": str(item.get("timestamp", "")),
                        "profile": p.get("name", p["id"]),
                        "profile_id": p["id"],
                        "device_id": device_id,
                        "device_name": device_name,
                        "ip": item.get("clientIp", ""),
                        "domain": item.get("domain", ""),
                        "query_type": item.get("type", ""),
                        "status": status_value,
                        "reason": ", ".join([r.get("name", r.get("id", "")) for r in reason_objs if isinstance(r, dict)]),
                        "reason_ids": ", ".join(rids),
                        "matched_name": item.get("matchedName", ""),
                        "protocol": item.get("protocol", ""),
                        "ti_score": "",
                        "ti_details": "",
                        # Context collection must use index within the profile logs list.
                        "event_index": profile_event_index,
                    }
                    row["search_blob"] = build_row_search_blob(row)
                    rows.append(row)

            if state_changed:
                self.legacy_state.save()

            rows.sort(key=lambda x: x.get("timestamp_raw", ""), reverse=True)
            reason_options = sorted([(rid, f"{reason_map[rid]} ({rid})") for rid in reason_map.keys()])
            return rows, reason_options, raw_logs_map

        if not self.submit_job("refresh_logs", job, self._on_logs_loaded, exclusive=True):
            self._set_status("Log refresh already running")

    def _on_logs_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Failed to load logs: {result}")
            return

        new_rows, reason_options, raw_logs_map = result

        # Build dedup keys from existing rows to avoid duplicates
        def _row_key(row: dict[str, Any]) -> str:
            return f"{row.get('timestamp_raw', '')}|{row.get('profile_id', '')}|{row.get('domain', '')}|{row.get('device_id', '')}|{row.get('query_type', '')}"

        existing_keys: set[str] = {_row_key(r) for r in self.log_rows}

        # Merge: append only truly new rows, preserving old ones (and their TI data)
        added = 0
        for row in new_rows:
            key = _row_key(row)
            if key not in existing_keys:
                self.log_rows.append(row)
                existing_keys.add(key)
                added += 1

        # Sort all rows by timestamp descending
        self.log_rows.sort(key=lambda x: x.get("timestamp_raw", ""), reverse=True)

        # Cap total rows to prevent unbounded memory growth
        if len(self.log_rows) > MAX_LOG_ROWS_IN_MEMORY:
            self.log_rows = self.log_rows[:MAX_LOG_ROWS_IN_MEMORY]

        # Update raw logs per-profile for alert context (replace with latest fetch)
        for profile_id, logs in raw_logs_map.items():
            self.profile_raw_logs[profile_id] = logs

        self.reason_options = [opt[0] for opt in reason_options]
        ignored = set(self.store.data["ui"].get("ignored_reasons", []))
        self.reason_menu.set_options(reason_options, ignored)
        self._refresh_logs_device_filter_options()

        self._render_logs_table()
        total = len(self.log_rows)
        self._set_status(f"Fetched {len(new_rows)} logs (+{added} new, {total} total)")

        if self.ti_enabled_var.get() and self.store.data["settings"].get("ti_enabled", True):
            self._refresh_ti_async()

        # Only dispatch alerts for newly fetched rows
        self._dispatch_alerts_async(new_rows)

    def _refresh_logs_device_filter_options(self) -> None:
        if not hasattr(self, "logs_devices_menu"):
            return

        selected = self.logs_devices_menu.values()
        if not selected and not self.logs_devices_menu.vars:
            selected = set(self.store.data["ui"].get("selected_devices", []))

        labels_by_id: dict[str, str] = {}
        for row in self.log_rows:
            device_id = str(row.get("device_id", "")).strip()
            if not device_id:
                continue
            device_name = str(row.get("device_name", "")).strip()
            if device_name and device_name != device_id:
                label = f"{device_name} ({device_id})"
            else:
                label = device_id
            labels_by_id.setdefault(device_id, label)

        options = sorted(labels_by_id.items(), key=lambda item: item[1].lower())
        self.logs_devices_menu.set_options(options, selected)

    def _refresh_ti_async(self) -> None:
        if self.pause_event.is_set():
            return
        self.ti_scan_generation += 1
        scan_id = self.ti_scan_generation
        max_domains = max(0, int(self.store.data["settings"].get("ti_max_domains_per_refresh", 80)))
        only_blocked = bool(self.store.data["settings"].get("ti_only_blocked_domains", True))
        ti_skip_reason_ids = set(self.store.data["settings"].get("ti_skip_reason_ids", []))
        domains: list[str] = []
        seen: set[str] = set()
        for row in self.log_rows:
            if only_blocked and not row_is_blocked(row):
                continue

            reason_ids = set(filter(None, [s.strip() for s in str(row.get("reason_ids", "")).split(",")]))
            if reason_ids and ti_skip_reason_ids and reason_ids.issubset(ti_skip_reason_ids):
                continue

            domain = row.get("domain", "").strip().lower()
            if not domain or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
            if max_domains and len(domains) >= max_domains:
                break

        if not domains:
            return

        self._set_status("Enriching threat intelligence...")

        def job() -> dict[str, dict[str, Any]]:
            out: dict[str, dict[str, Any]] = {}
            total = len(domains)
            for idx, d in enumerate(domains, start=1):
                if self.pause_event.is_set() or scan_id != self.ti_scan_generation:
                    break
                if idx == 1 or idx % 5 == 0 or idx == total:
                    self._publish_progress(f"TI scan progress: {idx}/{total}")
                out[d] = self.ti.score_domain(d)
            return out

        self.submit_job(f"ti_enrichment_{scan_id}", job, lambda payload: self._on_ti_ready(payload, scan_id))

    def _on_ti_ready(self, payload: tuple[str, Any], scan_id: int | None = None) -> None:
        if scan_id is not None and scan_id != self.ti_scan_generation:
            self._set_status("TI scan interrupted and replaced with latest filters")
            return
        _, result = payload
        if isinstance(result, Exception):
            self._set_status(f"TI enrichment failed: {result}")
            return

        ti_map: dict[str, dict[str, Any]] = result
        for row in self.log_rows:
            domain = row.get("domain", "").strip().lower()
            if domain in ti_map:
                info = ti_map[domain]
                row["ti_score"] = str(info.get("score", ""))
                row["ti_details"] = str(info.get("details", ""))
                row["search_blob"] = build_row_search_blob(row)

        self._render_logs_table()
        self._set_status("Threat intelligence updated")

    def _filtered_log_rows(self) -> list[dict[str, Any]]:
        rows = list(self.log_rows)
        query = self.logs_search_var.get().strip().lower()
        selected_profiles = self.logs_profiles_menu.values()
        selected_devices = self.logs_devices_menu.values() if hasattr(self, "logs_devices_menu") else set()
        ignored_reasons = self.reason_menu.values() if self.logs_ignore_reasons.get() else set()
        normal_tlds = set(self._get_normal_tlds())

        blocked_only = self.logs_blocked_only.get()
        malicious_only = self.logs_malicious_only.get()
        unusual_only = self.logs_unusual_only.get()

        filtered: list[dict[str, Any]] = []
        for row in rows:
            if selected_profiles and row.get("profile_id", "") not in selected_profiles:
                continue
            if selected_devices and str(row.get("device_id", "")) not in selected_devices:
                continue

            reason_ids = set(filter(None, [s.strip() for s in str(row.get("reason_ids", "")).split(",")]))
            if ignored_reasons and reason_ids and reason_ids.issubset(ignored_reasons):
                continue

            if blocked_only and not row_is_blocked(row):
                continue

            if malicious_only:
                try:
                    score = int(row.get("ti_score") or 0)
                except ValueError:
                    score = 0
                if score < 40:
                    continue

            if unusual_only:
                tld = parse_domain_tld(str(row.get("domain", "")))
                if tld in normal_tlds:
                    continue

            if query and query not in row.get("search_blob", ""):
                continue

            filtered.append(row)

        return filtered

    def _resolve_blocked_row_color(self) -> str:
        mode = str(self.store.data.get("settings", {}).get("blocked_row_color_mode", "default"))
        custom = str(self.store.data.get("settings", {}).get("blocked_row_custom_color", "#ffd6d6"))
        if mode == "light-red":
            return "#ffeaea"
        if mode == "custom" and re.match(r"^#[0-9a-fA-F]{6}$", custom):
            return custom
        return "#f8f8f0"

    def _render_logs_table(self) -> None:
        selected_columns = self.store.data["ui"].get("selected_log_columns", DEFAULT_LOG_COLUMNS)
        selected_columns = [c for c in selected_columns if c in ALL_LOG_COLUMNS]
        if not selected_columns:
            selected_columns = DEFAULT_LOG_COLUMNS

        self.logs_table.configure(columns=selected_columns)
        header_overrides = {
            "ti_score": "TI score",
            "ti_details": "TI details",
            "device_id": "Device ID",
            "device_name": "Device name",
            "profile_id": "Profile ID",
            "query_type": "Query type",
            "reason_ids": "Reason IDs",
        }
        for col in selected_columns:
            col_label = header_overrides.get(col, col.replace("_", " ").title())
            self.logs_table.heading(col, text=col_label, command=lambda c=col: self._sort_tree(self.logs_table, c, False))
            width = 170
            if col in {"domain", "ti_details", "reason"}:
                width = 280
            if col in {"timestamp", "profile", "device_id", "device_name"}:
                width = 190
            self.logs_table.column(col, width=width, stretch=True)

        for item in self.logs_table.get_children():
            self.logs_table.delete(item)

        self.log_row_by_iid.clear()
        for idx, row in enumerate(self._filtered_log_rows()):
            values = [row.get(c, "") for c in selected_columns]
            tags = ("blocked",) if row_is_blocked(row) else ()
            iid = f"log_{idx}"
            self.log_row_by_iid[iid] = row
            self.logs_table.insert("", "end", iid=iid, values=values, tags=tags)

        self.logs_table.tag_configure("blocked", background=self._resolve_blocked_row_color())

    def _show_column_selector(self) -> None:
        dlg = tk.Toplevel(self)
        dlg.title("Select log columns")
        dlg.resizable(False, False)
        dlg.grab_set()

        frame = ttk.Frame(dlg, padding=12)
        frame.pack(fill="both", expand=True)

        vars_map: dict[str, tk.BooleanVar] = {}
        selected = set(self.store.data["ui"].get("selected_log_columns", DEFAULT_LOG_COLUMNS))

        for col in ALL_LOG_COLUMNS:
            var = tk.BooleanVar(value=col in selected)
            vars_map[col] = var
            ttk.Checkbutton(frame, text=col, variable=var).pack(anchor="w")

        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=(8, 0))

        def sel_all() -> None:
            for v in vars_map.values():
                v.set(True)

        def desel_all() -> None:
            for v in vars_map.values():
                v.set(False)

        def apply_cols() -> None:
            chosen = [c for c, v in vars_map.items() if v.get()]
            self.store.data["ui"]["selected_log_columns"] = chosen or DEFAULT_LOG_COLUMNS
            self.store.save()
            self._render_logs_table()
            dlg.destroy()

        ttk.Button(controls, text="Select all", command=sel_all).pack(side="left")
        ttk.Button(controls, text="Deselect all", command=desel_all).pack(side="left", padx=(6, 0))
        ttk.Button(controls, text="Cancel", command=dlg.destroy).pack(side="right")
        ttk.Button(controls, text="Apply", command=apply_cols).pack(side="right", padx=(6, 0))

    def _on_logs_filter_change(self) -> None:
        self._save_ui_state()
        self._render_logs_table()

    def _selected_log_row_data(self) -> dict[str, Any] | None:
        sel = self.logs_table.selection()
        if not sel:
            return None
        # Treeview only holds visible columns, so profile_id must come from the backing row.
        return self.log_row_by_iid.get(sel[0])

    def _show_logs_context_menu(self, event: tk.Event) -> None:
        iid = self.logs_table.identify_row(event.y)
        if iid:
            self.logs_table.selection_set(iid)
            self.logs_context_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_block_domain(self) -> None:
        row = self._selected_log_row_data()
        if not row:
            return
        domain = row.get("domain", "")
        profile_id = row.get("profile_id", "")
        if not domain or not profile_id:
            self._show_error("Selected row has no domain/profile")
            return

        self._set_status(f"Blocking {domain}...")
        self.submit_job(
            "block_domain",
            lambda: self.nextdns.add_deny_domain(profile_id, domain),
            lambda p: self._on_simple_action_result("Block domain", p, self.refresh_denylist),
        )

    def _ctx_unblock_domain(self) -> None:
        row = self._selected_log_row_data()
        if not row:
            return
        domain = row.get("domain", "")
        profile_id = row.get("profile_id", "")
        if not domain or not profile_id:
            self._show_error("Selected row has no domain/profile")
            return

        self._set_status(f"Unblocking {domain}...")
        self.submit_job(
            "unblock_domain",
            lambda: self.nextdns.remove_deny_domain(profile_id, domain),
            lambda p: self._on_simple_action_result("Unblock domain", p, self.refresh_denylist),
        )

    def _copy_log_row(self, mode: str) -> None:
        row = self._selected_log_row_data()
        if not row:
            return

        if mode == "domain":
            text = row.get("domain", "")
        elif mode == "device":
            text = f"{row.get('device_id', '')} {row.get('device_name', '')}".strip()
        elif mode == "profile":
            text = row.get("profile", "")
        elif mode == "reason":
            text = row.get("reason", "")
        else:
            text = " | ".join([f"{col}={row.get(col, '')}" for col in ALL_LOG_COLUMNS])

        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Copied")
