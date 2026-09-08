"""TLDs tab: blocked top-level domains per profile."""

from __future__ import annotations

import csv
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any

from ..constants import TLD_COLUMNS
from ..utils import is_valid_tld, normalize_lines
from .widgets import MultiSelectMenu, ProfilePickerDialog


class TldsTabMixin:
    """TLD tab behaviour for NextDNSManagerApp."""

    def _build_tlds_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="TLDs")

        top = ttk.Frame(tab)
        top.pack(fill="x")

        self.tlds_profiles_menu = MultiSelectMenu(top, "Profiles", self._render_tlds_table)
        self.tlds_profiles_menu.pack(side="left")

        ttk.Label(top, text="Search:").pack(side="left", padx=(10, 4))
        self.tlds_search_var = tk.StringVar(value=self.store.data["ui"].get("tlds_search", ""))
        tlds_search_entry = ttk.Entry(top, textvariable=self.tlds_search_var, width=32)
        tlds_search_entry.pack(side="left")
        tlds_search_entry.bind("<KeyRelease>", lambda _: self._debounce("tlds_search", 250, self._render_tlds_table))

        ttk.Button(top, text="Refresh", command=self.refresh_tlds).pack(side="right")
        ttk.Button(top, text="Export", command=self.export_tlds).pack(side="right", padx=(6, 6))
        ttk.Button(top, text="Bulk import", command=self.bulk_import_tlds).pack(side="right")

        table_frame = ttk.Frame(tab)
        table_frame.pack(fill="both", expand=True, pady=(8, 0))

        self.tlds_table = ttk.Treeview(table_frame, columns=TLD_COLUMNS, show="headings")
        for col in TLD_COLUMNS:
            self.tlds_table.heading(col, text=col.title(), command=lambda c=col: self._sort_tree(self.tlds_table, c, False))
            self.tlds_table.column(col, width=180 if col != "tld" else 240, stretch=True)
        self.tlds_table.bind("<Button-3>", self._show_tlds_context_menu)

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tlds_table.yview)
        yscroll.pack(side="right", fill="y")
        
        self.tlds_table.pack(side="left", fill="both", expand=True)
        self.tlds_table.configure(yscrollcommand=yscroll.set)

        self.tlds_context = tk.Menu(self, tearoff=0)
        self.tlds_context.add_command(label="Block TLD", command=self._ctx_block_tld)
        self.tlds_context.add_command(label="Unblock TLD", command=self._ctx_unblock_tld)
        self.tlds_context.add_command(label="Copy TLD", command=self._ctx_copy_tld)

    def refresh_tlds(self) -> None:
        selected_ids = self.tlds_profiles_menu.values() or {p["id"] for p in self.profiles}
        selected_profiles = [p for p in self.profiles if p["id"] in selected_ids]
        if not selected_profiles:
            self._set_status("No profiles selected")
            return

        self._set_status("Loading TLDs...")

        def job() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for p in selected_profiles:
                blocked = set(self.nextdns.get_security_tlds(p["id"]))
                for tld in blocked:
                    rows.append({
                        "profile": p.get("name", p["id"]),
                        "profile_id": p["id"],
                        "tld": tld,
                        "blocked": "Yes",
                    })
            rows.sort(key=lambda r: (0 if r["blocked"] == "Yes" else 1, r["tld"]))
            return rows

        if not self.submit_job("refresh_tlds", job, self._on_tlds_loaded, exclusive=True):
            self._set_status("TLD refresh already running")

    def _on_tlds_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Failed to load TLDs: {result}")
            return
        self.tld_rows = result
        self._render_tlds_table()
        self._set_status(f"Loaded {len(self.tld_rows)} TLD rows")

    def _render_tlds_table(self) -> None:
        query = self.tlds_search_var.get().strip().lower()
        selected_profiles = self.tlds_profiles_menu.values()

        for item in self.tlds_table.get_children():
            self.tlds_table.delete(item)

        rows = []
        for row in self.tld_rows:
            if selected_profiles and row["profile_id"] not in selected_profiles:
                continue
            if query and query not in " | ".join([str(v).lower() for v in row.values()]):
                continue
            rows.append(row)

        rows.sort(key=lambda r: (0 if r["blocked"] == "Yes" else 1, r["tld"], r["profile"]))
        for i, row in enumerate(rows):
            values = [row.get(c, "") for c in TLD_COLUMNS]
            self.tlds_table.insert("", "end", iid=f"tld_{i}", values=values)

    def _show_tlds_context_menu(self, event: tk.Event) -> None:
        iid = self.tlds_table.identify_row(event.y)
        if iid:
            self.tlds_table.selection_set(iid)
            self.tlds_context.tk_popup(event.x_root, event.y_root)

    def _selected_tld_row(self) -> dict[str, str] | None:
        sel = self.tlds_table.selection()
        if not sel:
            return None
        vals = self.tlds_table.item(sel[0], "values")
        return dict(zip(TLD_COLUMNS, vals))

    def _ctx_block_tld(self) -> None:
        row = self._selected_tld_row()
        if not row:
            return
        profile_id = row.get("profile_id", "")
        tld = row.get("tld", "")

        def job() -> tuple[bool, str]:
            current = set(self.nextdns.get_security_tlds(profile_id))
            current.add(tld)
            return self.nextdns.patch_security_tlds(profile_id, sorted(current))

        self.submit_job("block_tld", job, lambda p: self._on_simple_action_result("Block TLD", p, self.refresh_tlds))

    def _ctx_unblock_tld(self) -> None:
        row = self._selected_tld_row()
        if not row:
            return
        profile_id = row.get("profile_id", "")
        tld = row.get("tld", "")

        def job() -> tuple[bool, str]:
            current = set(self.nextdns.get_security_tlds(profile_id))
            current.discard(tld)
            return self.nextdns.patch_security_tlds(profile_id, sorted(current))

        self.submit_job("unblock_tld", job, lambda p: self._on_simple_action_result("Unblock TLD", p, self.refresh_tlds))

    def _ctx_copy_tld(self) -> None:
        row = self._selected_tld_row()
        if not row:
            return
        self.clipboard_clear()
        self.clipboard_append(row.get("tld", ""))
        self._set_status("Copied TLD")

    def bulk_import_tlds(self) -> None:
        path = filedialog.askopenfilename(title="Select TLD import file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, PermissionError, UnicodeDecodeError) as exc:
            self._show_error(f"Cannot read file: {exc}")
            return

        tlds = [t for t in normalize_lines(text) if is_valid_tld(t)]
        if not tlds:
            self._show_error("Import file has no valid TLDs")
            return

        dlg = ProfilePickerDialog(self, self.profiles, "Choose profiles for TLD import")
        self.wait_window(dlg)
        if not dlg.result:
            return

        profiles = dlg.result
        self._set_status("Running smart TLD import...")

        def job() -> tuple[int, int]:
            changed = 0
            skipped = 0
            for p in profiles:
                current = set(self.nextdns.get_security_tlds(p["id"]))
                new_set = current | set(tlds)
                if new_set == current:
                    skipped += len(tlds)
                    continue
                ok, _ = self.nextdns.patch_security_tlds(p["id"], sorted(new_set))
                if ok:
                    changed += len(new_set) - len(current)
            return changed, skipped

        self.submit_job("bulk_import_tlds", job, self._on_bulk_tlds_done)

    def _on_bulk_tlds_done(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"Bulk TLD import failed: {result}")
            return
        changed, skipped = result
        self._set_status(f"TLD import done. Added: {changed}, skipped: {skipped}")
        self.refresh_tlds()

    def export_tlds(self) -> None:
        path = filedialog.asksaveasfilename(title="Export TLDs", defaultextension=".txt", filetypes=[("Text file", "*.txt"), ("CSV file", "*.csv")])
        if not path:
            return

        rows = []
        selected_profiles = self.tlds_profiles_menu.values()
        query = self.tlds_search_var.get().strip().lower()
        for row in self.tld_rows:
            if selected_profiles and row["profile_id"] not in selected_profiles:
                continue
            if query and query not in " | ".join([str(v).lower() for v in row.values()]):
                continue
            rows.append(row)

        try:
            if path.lower().endswith(".csv"):
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=TLD_COLUMNS, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(rows)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    for row in rows:
                        f.write(f"{row['tld']}\n")
            self._set_status(f"Exported {len(rows)} TLD rows")
        except (OSError, PermissionError, csv.Error) as exc:
            self._show_error(f"Export failed: {exc}")
