"""Pure helpers: domain parsing, timestamps, log-row predicates."""

from __future__ import annotations

import os
import re
import sys
import threading
import traceback
from datetime import datetime, timezone
from typing import Any

from .constants import ALL_LOG_COLUMNS, BLOCKED_STATUSES, DOMAIN_RE


def configure_windows_gui_console(headless: bool) -> None:
    if os.name != "nt" or headless:
        return
    try:
        import ctypes
    except ImportError:
        return

    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    SW_HIDE = 0
    SW_SHOW = 5

    def show_console() -> None:
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            kernel32.AllocConsole()
            hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            user32.ShowWindow(hwnd, SW_SHOW)

    hwnd = kernel32.GetConsoleWindow()
    if hwnd:
        user32.ShowWindow(hwnd, SW_HIDE)

    def _global_excepthook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        show_console()
        traceback.print_exception(exc_type, exc, tb)

    sys.excepthook = _global_excepthook

    if hasattr(threading, "excepthook"):
        def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
            show_console()
            traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback)

        threading.excepthook = _thread_excepthook


def normalize_lines(text: str) -> list[str]:
    items: list[str] = []
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        items.append(line)
    return sorted(set(items))


def parse_domain_tld(domain: str) -> str:
    clean = domain.strip().lower().rstrip(".")
    if "." not in clean:
        return clean
    return clean.rsplit(".", 1)[-1]


def normalize_domain(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def is_valid_domain(value: str) -> bool:
    domain = normalize_domain(value)
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_RE.fullmatch(domain))


def is_valid_domain_pattern(value: str) -> bool:
    pattern = normalize_domain(value)
    return is_valid_domain(pattern[2:] if pattern.startswith("*.") else pattern)


def is_valid_tld(tld: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", tld.strip().lower().lstrip(".")))


def row_is_blocked(row: dict[str, Any]) -> bool:
    return str(row.get("status", "")).lower() in BLOCKED_STATUSES


def build_row_search_blob(row: dict[str, Any]) -> str:
    return " | ".join(str(row.get(col, "")).lower() for col in ALL_LOG_COLUMNS)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_epoch_seconds(iso_ts: str) -> int:
    try:
        return int(datetime.fromisoformat(str(iso_ts).replace("Z", "+00:00")).timestamp())
    except (AttributeError, TypeError, ValueError):
        return 0


def format_timestamp_display(iso_ts: str) -> str:
    try:
        clean = iso_ts.replace("Z", "+00:00")
        dt_utc = datetime.fromisoformat(clean)
        dt_local = dt_utc.astimezone()
        return dt_local.strftime("%Y-%m-%d %H:%M:%S")
    except (AttributeError, TypeError, ValueError):
        return iso_ts


def format_timestamp_qp(iso_timestamp: str, include_date: bool = True) -> str:
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime("%d %b %H:%M") if include_date else dt.strftime("%H:%M")
    except (ValueError, AttributeError):
        return iso_timestamp


def format_time_range_qp(first_timestamp: str, last_timestamp: str) -> str:
    try:
        first_dt = datetime.fromisoformat(first_timestamp.replace("Z", "+00:00"))
        last_dt = datetime.fromisoformat(last_timestamp.replace("Z", "+00:00"))
        if first_dt.date() == last_dt.date():
            return f"{first_dt.strftime('%d %b %H:%M')} — {last_dt.strftime('%H:%M')}"
        return f"{first_dt.strftime('%d %b %H:%M')} — {last_dt.strftime('%d %b %H:%M')}"
    except (ValueError, AttributeError):
        return f"{first_timestamp} — {last_timestamp}"


def get_event_key_qp(event: dict[str, Any], profile_id: str) -> str:
    timestamp = event.get("timestamp", "")
    domain = event.get("domain", "")
    client_ip = event.get("clientIp", "")
    return f"{profile_id}|{timestamp}|{domain}|{client_ip}"


def domain_matches_pattern(domain: str, pattern: str) -> bool:
    domain = domain.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        base_domain = pattern[2:]
        return domain == base_domain or domain.endswith("." + base_domain)
    return domain == pattern


def extract_device_info(event: dict[str, Any]) -> tuple[str, str]:
    device_obj = event.get("device")
    if isinstance(device_obj, dict):
        device_id = str(device_obj.get("id", "") or "")
        device_name = str(device_obj.get("name", "") or "")
        return device_id, device_name

    device_id = str(event.get("deviceId", "") or event.get("clientId", "") or "")
    device_name = str(event.get("deviceName", "") or event.get("name", "") or "")
    return device_id, device_name


def collect_context_qp(logs: list[dict[str, Any]], event_index: int, event: dict[str, Any]) -> dict[str, Any]:
    device_id = (event.get("device") or {}).get("id") if isinstance(event.get("device"), dict) else event.get("device_id")
    client_ip = event.get("clientIp") or event.get("client_ip") or event.get("ip")
    identifier = device_id if device_id else client_ip
    header = "Surrounding DNS Queries (This Device):" if device_id else "Surrounding DNS Queries (This IP):"

    before: list[str] = []
    after: list[str] = []

    for i in range(max(0, event_index - 10), event_index):
        log = logs[i]
        log_device = (log.get("device") or {}).get("id") if isinstance(log.get("device"), dict) else log.get("device_id")
        log_ip = log.get("clientIp") or log.get("client_ip") or log.get("ip")
        log_identifier = log_device if log_device else log_ip
        if log_identifier == identifier:
            domain = str(log.get("domain", ""))
            if str(log.get("status", "")).lower() == "blocked":
                reasons = log.get("reasons", []) or []
                reason_names = ", ".join([str(r.get("name", "")) for r in reasons if isinstance(r, dict)])
                domain += f" (Blocked: {reason_names})"
            before.append(domain)

    for i in range(event_index + 1, min(len(logs), event_index + 11)):
        log = logs[i]
        log_device = (log.get("device") or {}).get("id") if isinstance(log.get("device"), dict) else log.get("device_id")
        log_ip = log.get("clientIp") or log.get("client_ip") or log.get("ip")
        log_identifier = log_device if log_device else log_ip
        if log_identifier == identifier:
            domain = str(log.get("domain", ""))
            if str(log.get("status", "")).lower() == "blocked":
                reasons = log.get("reasons", []) or []
                reason_names = ", ".join([str(r.get("name", "")) for r in reasons if isinstance(r, dict)])
                domain += f" (Blocked: {reason_names})"
            after.append(domain)

    return {"before": before, "after": after, "header": header}
