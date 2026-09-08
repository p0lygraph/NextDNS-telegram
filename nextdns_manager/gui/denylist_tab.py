"""Denylist tab: blocked domains per profile."""

from __future__ import annotations

import csv
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, simpledialog, ttk
from typing import Any

from ..constants import DENYLIST_COLUMNS
from ..utils import is_valid_domain, normalize_domain, normalize_lines
from .widgets import MultiSelectMenu, ProfilePickerDialog


class DenylistTabMixin:
    """Denylist tab behaviour for NextDNSManagerApp."""

    def _build_denylist_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Denylist")

        top = ttk.Frame(tab)
        top.pack(fill="x")

        self.deny_profiles_menu = MultiSelectMenu(top, "Profiles", self._render_deny_table)
        self.deny_profiles_menu.pack(side="left")

        ttk.Label(top, text="Search:").pack(side="left", padx=(10, 4))
        self.deny_search_var = tk.StringVar(value=self.store.data["ui"].get("denylist_search", ""))
        deny_search_entry = ttk.Entry(top, textvariable=self.deny_search_var, width=32)
        deny_search_entry.pack(side="left")
        deny_search_entry.bind("<KeyRelease>", lambda _: self._debounce("deny_search", 250, self._render_deny_table))

        ttk.Button(top, text="Refresh", command=self.refresh_denylist).pack(side="right")
        ttk.Button(top, text="Export", command=self.export_denylist).pack(side="right", padx=(6, 6))
        ttk.Button(top, text="Bulk import", command=self.bulk_import_denylist).pack(side="right")
        ttk.Button(top, text="Add domain", command=self.add_single_deny_domain).pack(side="right", padx=(6, 0))

        table_frame = ttk.Frame(tab)
        table_frame.pack(fill="both", expand=True, pady=(8, 0))

        self.deny_table = ttk.Treeview(table_frame, columns=DENYLIST_COLUMNS, show="headings")
        for col in DENYLIST_COLUMNS:
            self.deny_table.heading(col, text=col.title(), command=lambda c=col: self._sort_tree(self.deny_table, c, False))
            self.deny_table.column(col, width=220 if col == "domain" else 170, stretch=True)
        self.deny_table.bind("<Button-3>", self._show_deny_context_menu)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.deny_table.yview)
        yscroll.pack(side="right", fill="y")

        self.deny_table.pack(side="left", fill="both", expand=True)
        self.deny_table.configure(yscrollcommand=yscroll.set)

        self.deny_context = tk.Menu(self, tearoff=0)
        self.deny_context.add_command(label="Block domain", command=self._ctx_block_domain_deny)
        self.deny_context.add_command(label="Unblock domain", command=self._ctx_unblock_domain_deny)
        self.deny_context.add_command(label="Copy domain", command=self._ctx_copy_domain_deny)

    def refresh_denylist(self) -> None:
        selected_ids = self.deny_profiles_menu.values() or {p["id"] for p in self.profiles}
        selected_profiles = [p for p in self.profiles if p["id"] in selected_ids]
        if not selected_profiles:
            self._set_status("No profiles selected")
            return

        self._set_status("Loading denylist...")

        def job() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for p in selected_profiles:
                domains = self.nextdns.get_denylist(p["id"])
                for d in domains:
                    rows.append({
                        "profile": p.get("name", p["id"]),
                        "profile_id": p["id"],
                        "domain": d,
                        "source": "remote",
                    })
            return rows

        if not self.submit_job("refresh_denylist", job, self._on_denylist_loaded, exclusive=True):
            self._set_status("Denylist refresh already running")

    def _on_denylist_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Failed to load denylist: {result}")
            return
        self.deny_rows = result
        self._render_deny_table()
        self._set_status(f"Loaded {len(self.deny_rows)} denylist rows")

    def _render_deny_table(self) -> None:
        query = self.deny_search_var.get().strip().lower()
        selected_profiles = self.deny_profiles_menu.values()

        for item in self.deny_table.get_children():
            self.deny_table.delete(item)

        rows = []
        for row in self.deny_rows:
            if selected_profiles and row["profile_id"] not in selected_profiles:
                continue
            if query and query not in " | ".join([str(v).lower() for v in row.values()]):
                continue
            rows.append(row)

        rows.sort(key=lambda r: (r["profile"], r["domain"]))
        for i, row in enumerate(rows):
            values = [row.get(c, "") for c in DENYLIST_COLUMNS]
            self.deny_table.insert("", "end", iid=f"deny_{i}", values=values)

    def _show_deny_context_menu(self, event: tk.Event) -> None:
        iid = self.deny_table.identify_row(event.y)
        if iid:
            self.deny_table.selection_set(iid)
            self.deny_context.tk_popup(event.x_root, event.y_root)

    def _selected_deny_row(self) -> dict[str, str] | None:
        sel = self.deny_table.selection()
        if not sel:
            return None
        vals = self.deny_table.item(sel[0], "values")
        return dict(zip(DENYLIST_COLUMNS, vals))

    def _ctx_block_domain_deny(self) -> None:
        row = self._selected_deny_row()
        if not row:
            return
        profile_id = row.get("profile_id", "")
        domain = row.get("domain", "")
        self.submit_job(
            "deny_block",
            lambda: self.nextdns.add_deny_domain(profile_id, domain),
            lambda p: self._on_simple_action_result("Block domain", p, self.refresh_denylist),
        )

    def _ctx_unblock_domain_deny(self) -> None:
        row = self._selected_deny_row()
        if not row:
            return
        profile_id = row.get("profile_id", "")
        domain = row.get("domain", "")
        self.submit_job(
            "deny_unblock",
            lambda: self.nextdns.remove_deny_domain(profile_id, domain),
            lambda p: self._on_simple_action_result("Unblock domain", p, self.refresh_denylist),
        )

    def _ctx_copy_domain_deny(self) -> None:
        row = self._selected_deny_row()
        if not row:
            return
        self.clipboard_clear()
        self.clipboard_append(row.get("domain", ""))
        self._set_status("Copied domain")

    def bulk_import_denylist(self) -> None:
        path = filedialog.askopenfilename(title="Select denylist import file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, PermissionError, UnicodeDecodeError) as exc:
            self._show_error(f"Cannot read file: {exc}")
            return

        domains = [d for d in normalize_lines(text) if is_valid_domain(d)]
        if not domains:
            self._show_error("Import file has no valid domains")
            return

        dlg = ProfilePickerDialog(self, self.profiles, "Choose profiles for denylist import")
        self.wait_window(dlg)
        if not dlg.result:
            return

        profiles = dlg.result
        self._set_status("Running smart denylist import...")

        def job() -> tuple[int, int]:
            changed = 0
            skipped = 0
            for p in profiles:
                current = set(self.nextdns.get_denylist(p["id"]))
                for d in domains:
                    if d in current:
                        skipped += 1
                        continue
                    ok, _ = self.nextdns.add_deny_domain(p["id"], d)
                    if ok:
                        changed += 1
            return changed, skipped

        self.submit_job("bulk_import_denylist", job, self._on_bulk_deny_done)

    def add_single_deny_domain(self) -> None:
        domain_raw = simpledialog.askstring("Add domain", "Enter domain to block:", parent=self)
        if domain_raw is None:
            return

        domain = normalize_domain(domain_raw)
        if not domain:
            self._show_error("Domain is empty")
            return
        if not is_valid_domain(domain):
            self._show_error("Invalid domain format")
            return

        dlg = ProfilePickerDialog(self, self.profiles, "Choose profiles to block the domain in")
        self.wait_window(dlg)
        if not dlg.result:
            return

        profiles = dlg.result
        self._set_status(f"Blocking {domain} in selected profiles...")

        def job() -> tuple[int, int, int]:
            added = 0
            already = 0
            failed = 0
            for p in profiles:
                ok, message = self.nextdns.add_deny_domain(p["id"], domain)
                if ok:
                    if "already blocked" in message.lower():
                        already += 1
                    else:
                        added += 1
                else:
                    failed += 1
            return added, already, failed

        self.submit_job("add_single_deny_domain", job, self._on_add_single_deny_done)

    def _on_add_single_deny_done(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Add domain failed: {result}")
            return
        added, already, failed = result
        self._set_status(f"Add domain done. Added: {added}, already blocked: {already}, failed: {failed}")
        self.refresh_denylist()

    def _on_bulk_deny_done(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Bulk denylist import failed: {result}")
            return
        changed, skipped = result
        self._set_status(f"Denylist import done. Added: {changed}, skipped: {skipped}")
        self.refresh_denylist()

    def export_denylist(self) -> None:
        path = filedialog.asksaveasfilename(title="Export denylist", defaultextension=".txt", filetypes=[("Text file", "*.txt"), ("CSV file", "*.csv")])
        if not path:
            return

        rows = []
        selected_profiles = self.deny_profiles_menu.values()
        query = self.deny_search_var.get().strip().lower()
        for row in self.deny_rows:
            if selected_profiles and row["profile_id"] not in selected_profiles:
                continue
            if query and query not in " | ".join([str(v).lower() for v in row.values()]):
                continue
            rows.append(row)

        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=DENYLIST_COLUMNS, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(rows)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    for row in rows:
                        f.write(f"{row['domain']}\n")
            self._set_status(f"Exported {len(rows)} denylist rows")
        except (OSError, PermissionError, csv.Error) as exc:
            self._show_error(f"Export failed: {exc}")
