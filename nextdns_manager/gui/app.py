"""Main application window: state, background jobs and shared plumbing."""

from __future__ import annotations

import queue
import re
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from ..caches import EventTTLCache
from ..constants import (
    ALERT_EVENT_CACHE_MAX,
    ALERT_EVENT_CACHE_TTL_SECONDS,
    APP_STATE_FILE,
    APP_TITLE,
    LEGACY_STATE_FILE,
)
from ..nextdns_api import NextDNSService
from ..state import LegacyStateManager, PersistentStore
from ..telegram_bot import process_telegram_updates, redact_telegram_token
from ..threat_intel import ThreatIntelService
from ..utils import normalize_lines
from .alerts_tab import AlertsTabMixin
from .apis_tab import ApisTabMixin
from .denylist_tab import DenylistTabMixin
from .logs_tab import LogsTabMixin
from .settings_tab import SettingsTabMixin
from .tlds_tab import TldsTabMixin


class NextDNSManagerApp(
    LogsTabMixin,
    TldsTabMixin,
    DenylistTabMixin,
    AlertsTabMixin,
    ApisTabMixin,
    SettingsTabMixin,
    tk.Tk,
):
    def __init__(self, root_dir: Path):
        super().__init__()
        self.root_dir = root_dir
        self.title(APP_TITLE)

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.store = PersistentStore(root_dir / APP_STATE_FILE)
        geom = self.store.data.get("window", {}).get("geometry", "1360x820")
        self.geometry(self._sanitize_geometry(str(geom)))

        self.executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="nextdns-bg")
        self.results_queue: queue.Queue[tuple[str, Any, Callable[[Any], None]]] = queue.Queue()
        self.inflight_jobs: set[str] = set()

        self.profiles: list[dict[str, Any]] = []
        self.profile_map: dict[str, dict[str, Any]] = {}
        self.log_rows: list[dict[str, Any]] = []
        self.log_row_by_iid: dict[str, dict[str, Any]] = {}
        self.profile_raw_logs: dict[str, list[dict[str, Any]]] = {}
        self.tld_rows: list[dict[str, Any]] = []
        self.deny_rows: list[dict[str, Any]] = []
        self.reason_options: list[str] = []
        self.reason_label_to_id: dict[str, str] = {}
        self.autorefresh_job: str | None = None
        self.startup_alert_sent = False
        self.ti_scan_generation = 0
        self.pause_event = threading.Event()
        self.event_cache = EventTTLCache(ALERT_EVENT_CACHE_MAX, ALERT_EVENT_CACHE_TTL_SECONDS)
        self.legacy_state = LegacyStateManager(root_dir / LEGACY_STATE_FILE)
        self.telegram_update_offset = max(0, int(self.store.data.get("alerts", {}).get("telegram_update_offset", 0) or 0))
        self.telegram_poll_job: str | None = None
        self.telegram_poll_inflight = False
        self.debounce_jobs: dict[str, str] = {}

        self.nextdns = NextDNSService(
            lambda: self.store.data["api"]["nextdns_api_key"],
            on_rate_limit=self._on_nextdns_rate_limited,
        )
        self.ti = ThreatIntelService(
            lambda: self.store.data["api"].get("urlhaus_api_key", ""),
            lambda: self.store.data["api"].get("urlscan_api_key", ""),
            lambda: int(self.store.data["settings"].get("ti_cache_ttl_seconds", 1800)),
        )

        self.minsize(800, 500)

        # Pack bottom_bar FIRST so it always gets space even in small windows
        self.bottom_bar = ttk.Frame(self, padding=(10, 6))
        self.bottom_bar.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.bottom_bar, textvariable=self.status_var).pack(side="left", fill="x", expand=True)
        self.pause_btn_text = tk.StringVar(value="Pause")
        ttk.Button(self.bottom_bar, textvariable=self.pause_btn_text, command=self.toggle_pause).pack(side="right")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        self._build_logs_tab()
        self._build_tlds_tab()
        self._build_denylist_tab()
        self._build_alerts_tab()
        self._build_apis_tab()
        self._build_settings_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.after(150, self._poll_results)
        self.after(300, self.initialize_data)
        self.after(1000, self._schedule_telegram_callback_poll)

    def _sanitize_geometry(self, geometry: str) -> str:
        screen_w = max(800, int(self.winfo_screenwidth() or 0))
        screen_h = max(600, int(self.winfo_screenheight() or 0))

        default_w = min(1180, max(800, screen_w - 160))
        default_h = min(760, max(600, screen_h - 140))
        max_w = min(1280, max(900, screen_w - 120))
        max_h = min(840, max(650, screen_h - 120))
        min_w = 900 if screen_w >= 1100 else max(800, screen_w - 160)
        min_h = 600 if screen_h >= 800 else max(560, screen_h - 120)

        m = re.match(r"^(\d+)x(\d+)([+-]\d+)?([+-]\d+)?$", geometry.strip())
        if not m:
            x = max(0, (screen_w - default_w) // 2)
            y = max(0, (screen_h - default_h) // 2)
            return f"{default_w}x{default_h}+{x}+{y}"

        raw_w = int(m.group(1))
        raw_h = int(m.group(2))
        if raw_w > max_w or raw_h > max_h:
            x = max(0, (screen_w - default_w) // 2)
            y = max(0, (screen_h - default_h) // 2)
            return f"{default_w}x{default_h}+{x}+{y}"

        width = max(min_w, min(raw_w, max_w))
        height = max(min_h, min(raw_h, max_h))

        if m.group(3) and m.group(4):
            raw_x = int(m.group(3))
            raw_y = int(m.group(4))
            max_x = max(0, screen_w - width)
            max_y = max(0, screen_h - height - 40)
            x = min(max(raw_x, 0), max_x)
            y = min(max(raw_y, 0), max_y)
        else:
            x = max(0, (screen_w - width) // 2)
            y = max(0, (screen_h - height) // 2)

        return f"{width}x{height}+{x}+{y}"

    def submit_job(self, name: str, fn: Callable[[], Any], callback: Callable[[Any], None], exclusive: bool = False) -> bool:
        if exclusive:
            if name in self.inflight_jobs:
                return False
            self.inflight_jobs.add(name)

        def run() -> None:
            try:
                result = fn()
                self.results_queue.put((name, result, callback))
            except Exception as exc:
                self.results_queue.put((name, exc, callback))

        self.executor.submit(run)
        return True

    def _poll_results(self) -> None:
        while True:
            try:
                name, result, callback = self.results_queue.get_nowait()
            except queue.Empty:
                break
            if name == "__progress__":
                self._set_status(str(result))
                continue
            self.inflight_jobs.discard(name)
            try:
                callback((name, result))
            except Exception as exc:
                self._set_status(f"UI callback error: {exc}")
                print(f"[WARN] UI callback error in {name}: {exc}")
        self.after(150, self._poll_results)

    def _debounce(self, key: str, delay_ms: int, fn: Callable[[], None]) -> None:
        job = self.debounce_jobs.pop(key, None)
        if job:
            try:
                self.after_cancel(job)
            except (tk.TclError, ValueError):
                pass

        def run() -> None:
            self.debounce_jobs.pop(key, None)
            fn()

        self.debounce_jobs[key] = self.after(delay_ms, run)

    def _cancel_debounced(self) -> None:
        for job in list(self.debounce_jobs.values()):
            try:
                self.after_cancel(job)
            except (tk.TclError, ValueError):
                pass
        self.debounce_jobs.clear()

    def _schedule_store_save(self) -> None:
        self._debounce("store_save", 1000, self.store.save)

    def _publish_progress(self, text: str) -> None:
        self.results_queue.put(("__progress__", text, lambda _: None))

    def _on_nextdns_rate_limited(self, path: str, retry_after: int, attempt: int) -> None:
        self._publish_progress(f"NextDNS rate limit on {path}. Waiting {retry_after}s before retry ({attempt}/3)")

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _show_error(self, text: str) -> None:
        self._set_status(text)
        messagebox.showerror(APP_TITLE, text)

    def toggle_pause(self) -> None:
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.pause_btn_text.set("Pause")
            self._set_status("Resumed")
            self._schedule_auto_refresh()
        else:
            self.pause_event.set()
            self.pause_btn_text.set("Resume")
            if self.autorefresh_job:
                try:
                    self.after_cancel(self.autorefresh_job)
                except (tk.TclError, ValueError):
                    pass
                self.autorefresh_job = None
            self._set_status("Paused")

    def _on_tab_changed(self, _event: tk.Event) -> None:
        try:
            self.store.data["last_tab"] = self.notebook.index(self.notebook.select())
        except tk.TclError:
            return
        self._schedule_store_save()

    def initialize_data(self) -> None:
        if not self.store.data["api"].get("nextdns_api_key", "").strip():
            self._set_status("Enter NextDNS API key in APIs tab, then refresh.")
            return

        self._set_status("Loading profiles...")
        self.submit_job("load_profiles", self.nextdns.get_profiles, self._on_profiles_loaded)

    def _on_profiles_loaded(self, payload: tuple[str, Any]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(str(result))
            return

        self.profiles = result
        self.profile_map = {p["id"]: p for p in self.profiles}

        options = [(p["id"], f"{p.get('name', p['id'])} ({p['id']})") for p in self.profiles]
        selected = set(self.store.data["ui"].get("selected_profiles", []))
        selected_alerts = set(self.store.data["ui"].get("selected_alert_profiles", []))
        selected_alert_ignores = set(self.store.data["ui"].get("selected_alert_ignore_profiles", []))
        selected_ti = set(self.store.data["ui"].get("selected_ti_profiles", []))

        self.logs_profiles_menu.set_options(options, selected)
        self.tlds_profiles_menu.set_options(options, selected)
        self.deny_profiles_menu.set_options(options, selected)
        self.alert_profiles_menu.set_options(options, selected_alerts)
        if hasattr(self, "alert_ignore_profiles_menu"):
            self.alert_ignore_profiles_menu.set_options(options, selected_alert_ignores or selected_alerts)
        if hasattr(self, "settings_ti_profiles_menu"):
            self.settings_ti_profiles_menu.set_options(options, selected_ti or selected)

        last_tab = int(self.store.data.get("last_tab", 0))
        if 0 <= last_tab < self.notebook.index("end"):
            self.notebook.select(last_tab)

        self.refresh_logs()
        self.refresh_tlds()
        self.refresh_denylist()
        self.refresh_alert_reason_editor()
        self.refresh_alert_ignored_domain_editor()
        self.refresh_ti_reason_editor()
        self._schedule_auto_refresh()

        if self.telegram_enabled.get() and not self.startup_alert_sent:
            self.startup_alert_sent = True
            self._send_startup_alert()

    def _schedule_auto_refresh(self) -> None:
        if self.autorefresh_job:
            try:
                self.after_cancel(self.autorefresh_job)
            except (tk.TclError, ValueError):
                pass
            self.autorefresh_job = None

        enabled = bool(self.store.data["settings"].get("autorefresh_enabled", False))
        interval = max(5, int(self.store.data["settings"].get("poll_interval_seconds", 30)))
        if enabled:
            self.autorefresh_job = self.after(interval * 1000, self._auto_refresh_tick)

    def _auto_refresh_tick(self) -> None:
        self.refresh_logs()
        self._schedule_auto_refresh()

    def _schedule_telegram_callback_poll(self) -> None:
        if self.telegram_poll_job:
            try:
                self.after_cancel(self.telegram_poll_job)
            except (tk.TclError, ValueError):
                pass
            self.telegram_poll_job = None
        self.telegram_poll_job = self.after(4000, self._telegram_callback_poll_tick)

    def _telegram_callback_poll_tick(self) -> None:
        self.telegram_poll_job = None
        if self.telegram_poll_inflight:
            self._schedule_telegram_callback_poll()
            return

        token = str(self.store.data.get("api", {}).get("telegram_bot_token", "")).strip()
        chat_id = str(self.store.data.get("api", {}).get("telegram_chat_id", "")).strip()
        if not token or not chat_id:
            self._schedule_telegram_callback_poll()
            return

        self.telegram_poll_inflight = True
        self.submit_job(
            "telegram_updates_poll",
            lambda: process_telegram_updates(token, chat_id, self.legacy_state, self.telegram_update_offset, self.nextdns),
            self._on_telegram_callback_poll_done,
        )

    def _on_telegram_callback_poll_done(self, payload: tuple[str, Any]) -> None:
        self.telegram_poll_inflight = False
        _, result = payload
        if isinstance(result, Exception):
            token = str(self.store.data.get("api", {}).get("telegram_bot_token", ""))
            print(f"[WARN] Telegram update polling failed: {redact_telegram_token(str(result), token)}")
            self._schedule_telegram_callback_poll()
            return

        next_offset, _handled, added = result
        if next_offset != self.telegram_update_offset:
            self.telegram_update_offset = next_offset
            self.store.data.setdefault("alerts", {})["telegram_update_offset"] = next_offset
            self.store.save()

        if added > 0:
            self.refresh_alert_ignored_domain_editor()
            self._set_status(f"Applied {added} Telegram action(s)")

        self._schedule_telegram_callback_poll()

    def _on_simple_action_result(self, action: str, payload: tuple[str, Any], refresh_fn: Callable[[], None]) -> None:
        _, result = payload
        if isinstance(result, Exception):
            self._show_error(f"{action} failed: {result}")
            return

        ok, message = result
        if ok:
            self._set_status(message)
            refresh_fn()
        else:
            self._show_error(message)

    def _sort_tree(self, tree: ttk.Treeview, col: str, reverse: bool) -> None:
        data = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(item: tuple[str, str]) -> Any:
            val = item[0]
            try:
                return int(val)
            except ValueError:
                return val.lower()

        data.sort(key=key, reverse=reverse)
        for index, (_, k) in enumerate(data):
            tree.move(k, "", index)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    def _save_ui_state(self, immediate: bool = False) -> None:
        try:
            self.store.data["ui"]["selected_profiles"] = sorted(list(self.logs_profiles_menu.values()))
            if hasattr(self, "logs_devices_menu") and self.logs_devices_menu.vars:
                self.store.data["ui"]["selected_devices"] = sorted(list(self.logs_devices_menu.values()))
            self.store.data["ui"]["selected_alert_profiles"] = sorted(list(self.alert_profiles_menu.values()))
            if hasattr(self, "alert_ignore_profiles_menu"):
                self.store.data["ui"]["selected_alert_ignore_profiles"] = sorted(list(self.alert_ignore_profiles_menu.values()))
            if hasattr(self, "settings_ti_profiles_menu"):
                self.store.data["ui"]["selected_ti_profiles"] = sorted(list(self.settings_ti_profiles_menu.values()))
            self.store.data["ui"]["logs_search"] = self.logs_search_var.get()
            self.store.data["ui"]["ignored_reasons"] = sorted(list(self.reason_menu.values()))
            self.store.data["ui"]["logs_filters"] = {
                "blocked_only": self.logs_blocked_only.get(),
                "malicious_only": self.logs_malicious_only.get(),
                "unusual_tld_only": self.logs_unusual_only.get(),
                "ignore_selected_reasons": self.logs_ignore_reasons.get(),
            }
            self.store.data["ui"]["tlds_search"] = self.tlds_search_var.get()
            self.store.data["ui"]["denylist_search"] = self.deny_search_var.get()
            self.store.data["ui"]["enabled_telegram_alerts"] = self.telegram_enabled.get()
        except (AttributeError, tk.TclError) as exc:
            print(f"[WARN] Failed to collect UI state: {exc}")
            return

        if immediate:
            self.store.save()
        else:
            self._schedule_store_save()

    def _get_normal_tlds(self) -> list[str]:
        from_state = self.store.data["settings"].get("normal_tlds", [])
        if from_state:
            return list(from_state)

        tld_file = self.root_dir / "TLDs.txt"
        if tld_file.exists():
            try:
                return normalize_lines(tld_file.read_text(encoding="utf-8"))
            except (OSError, PermissionError, UnicodeDecodeError) as exc:
                print(f"[WARN] Failed to read {tld_file}: {exc}")
                return []
        return []

    def on_close(self) -> None:
        self._cancel_debounced()
        try:
            self.store.data["window"]["geometry"] = self._sanitize_geometry(self.geometry())
        except tk.TclError as exc:
            print(f"[WARN] Failed to read window geometry on close: {exc}")
        self._save_ui_state(immediate=True)
        if self.telegram_poll_job:
            try:
                self.after_cancel(self.telegram_poll_job)
            except (tk.TclError, ValueError):
                pass
            self.telegram_poll_job = None
        if self.autorefresh_job:
            try:
                self.after_cancel(self.autorefresh_job)
            except (tk.TclError, ValueError):
                pass
            self.autorefresh_job = None
        self.executor.shutdown(wait=False, cancel_futures=True)
        try:
            self.destroy()
        except tk.TclError:
            pass
