"""Telegram transport: menus, callbacks and alert delivery."""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from html import escape as html_escape
from typing import Any, Callable
from urllib.parse import quote

from .alerts import AlertBatchQP
from .caches import TTLCache
from .constants import (
    APP_TIMEOUT,
    BLOCKED_STATUSES,
    TELEGRAM_API_CACHE_TTL_SECONDS,
    TELEGRAM_LOG_PAGE_SIZE,
    TELEGRAM_MAX_MESSAGE_CHARS,
    TELEGRAM_PAGE_SIZE,
    TELEGRAM_SESSION_TTL_SECONDS,
)
from .deps import requests
from .state import LegacyStateManager
from .utils import (
    extract_device_info,
    format_timestamp_display,
    is_valid_domain,
    is_valid_domain_pattern,
    is_valid_tld,
    normalize_domain,
)


_TELEGRAM_TOKEN_IN_URL_RE = re.compile(r"/bot\d+:[A-Za-z0-9_-]+")


def redact_telegram_token(text: str, token: str = "") -> str:
    clean = str(token).strip()
    redacted = str(text)
    if clean:
        redacted = redacted.replace(clean, "***")
    return _TELEGRAM_TOKEN_IN_URL_RE.sub("/bot***", redacted)


def _telegram_log(logger: Callable[[str], None] | None, message: str) -> None:
    if logger:
        logger(message)
    else:
        print(message)


def _telegram_clip_lines(lines: list[str], limit: int = TELEGRAM_MAX_MESSAGE_CHARS) -> str:
    # Telegram rejects payloads over the limit, so cut on line borders to keep HTML valid.
    suffix = "…truncated"
    budget = limit - len(suffix) - 1
    out: list[str] = []
    used = 0
    for line in lines:
        cost = len(line) + (1 if out else 0)
        if used + cost > budget:
            out.append(suffix)
            break
        out.append(line)
        used += cost
    return "\n".join(out)


_TELEGRAM_API_CACHE = TTLCache(TELEGRAM_API_CACHE_TTL_SECONDS)


def _telegram_cached_denylist(nextdns: Any, profile_id: str) -> list[str]:
    return _TELEGRAM_API_CACHE.get_or_call(f"deny:{profile_id}", lambda: nextdns.get_denylist(profile_id))


def _telegram_cached_tlds(nextdns: Any, profile_id: str) -> list[str]:
    return _TELEGRAM_API_CACHE.get_or_call(f"tld:{profile_id}", lambda: nextdns.get_security_tlds(profile_id))


def _telegram_cached_logs(nextdns: Any, profile_id: str) -> list[dict[str, Any]]:
    return _TELEGRAM_API_CACHE.get_or_call(f"logs:{profile_id}", lambda: nextdns.get_logs(profile_id, limit=100))


def _telegram_cached_reasons(nextdns: Any, profile_id: str) -> list[dict[str, Any]]:
    return _TELEGRAM_API_CACHE.get_or_call(f"reasons:{profile_id}", lambda: nextdns.get_analytics_reasons(profile_id))


def _telegram_api_post(token: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/{method}",
            json=payload,
            timeout=APP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Telegram {method} failed: {redact_telegram_token(str(exc), token)}") from exc

    if resp.status_code != 200:
        raise RuntimeError(f"Telegram {method} failed ({resp.status_code})")

    try:
        data = resp.json()
    except ValueError as exc:
        raise RuntimeError(f"Telegram {method} returned invalid JSON") from exc

    if not data.get("ok"):
        desc = str(data.get("description", "unknown Telegram API error"))
        raise RuntimeError(f"Telegram {method} error: {desc}")
    return data


def _telegram_send_message(token: str, chat_id: str, text: str, keyboard: list[list[dict[str, Any]]] | None = None) -> None:
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    _telegram_api_post(token, "sendMessage", payload)


def _telegram_edit_message(
    token: str,
    chat_id: str,
    message_id: int,
    text: str,
    keyboard: list[list[dict[str, Any]]] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    _telegram_api_post(token, "editMessageText", payload)


def _telegram_answer_callback(token: str, callback_id: str, text: str = "", show_alert: bool = False) -> None:
    if not callback_id:
        return
    try:
        _telegram_api_post(
            token,
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": text, "show_alert": show_alert},
        )
    except RuntimeError:
        pass


def _telegram_is_authorized(container: dict[str, Any], allowed_chat_id: str) -> bool:
    allowed = str(allowed_chat_id).strip()
    if not allowed:
        return False
    message = container.get("message") if "message" in container else container
    chat_id = str(((message.get("chat") or {}).get("id", ""))).strip() if isinstance(message, dict) else ""
    user_id = str(((container.get("from") or {}).get("id", ""))).strip()
    return allowed in {chat_id, user_id}


def _telegram_message_target(container: dict[str, Any], fallback_chat_id: str) -> tuple[str, int | None]:
    message = container.get("message") if "message" in container else container
    if not isinstance(message, dict):
        return fallback_chat_id, None
    chat_id = str(((message.get("chat") or {}).get("id", fallback_chat_id))).strip()
    message_id_raw = message.get("message_id")
    message_id = message_id_raw if isinstance(message_id_raw, int) else None
    return chat_id or fallback_chat_id, message_id


def _telegram_profiles(legacy_state: LegacyStateManager, nextdns: Any | None = None) -> list[dict[str, Any]]:
    cached = legacy_state.state.get("profiles_cache", [])
    if isinstance(cached, list) and cached:
        return [p for p in cached if isinstance(p, dict) and str(p.get("id", "")).strip()]
    if nextdns is None:
        return []
    profiles = nextdns.get_profiles()
    legacy_state.set_state_value("profiles_cache", profiles)
    legacy_state.save()
    return profiles


def _telegram_profile_name(profiles: list[dict[str, Any]], profile_id: str) -> str:
    for profile in profiles:
        if str(profile.get("id", "")) == profile_id:
            return str(profile.get("name", profile_id))
    return profile_id


def _telegram_get_profile(profiles: list[dict[str, Any]], profile_id: str) -> dict[str, Any] | None:
    for profile in profiles:
        if str(profile.get("id", "")) == profile_id:
            return profile
    return None


def _telegram_reason_token(reason_id: str) -> str:
    return hashlib.blake2s(str(reason_id).encode("utf-8"), digest_size=2).hexdigest()


def _telegram_sessions_locked(legacy_state: LegacyStateManager) -> dict[str, Any]:
    sessions = legacy_state.state.setdefault("telegram_sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
        legacy_state.state["telegram_sessions"] = sessions
    now = time.time()
    expired = [
        sid for sid, item in sessions.items()
        if not isinstance(item, dict) or now - float(item.get("ts", 0) or 0) > TELEGRAM_SESSION_TTL_SECONDS
    ]
    for sid in expired:
        sessions.pop(sid, None)
    return sessions


def _telegram_create_session(legacy_state: LegacyStateManager, kind: str, value: str) -> str:
    with legacy_state.lock:
        sessions = _telegram_sessions_locked(legacy_state)
        sid = secrets.token_hex(4)
        sessions[sid] = {"kind": kind, "value": value, "ts": time.time()}
    legacy_state.save()
    return sid


def _telegram_get_session(legacy_state: LegacyStateManager, sid: str, kind: str) -> str | None:
    with legacy_state.lock:
        item = _telegram_sessions_locked(legacy_state).get(sid)
        if not isinstance(item, dict) or item.get("kind") != kind:
            return None
        return str(item.get("value", "")).strip()


def _telegram_paginate(items: list[Any], page: int, page_size: int = TELEGRAM_PAGE_SIZE) -> tuple[list[Any], int, int]:
    total_pages = max(1, (len(items) + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    return items[start:start + page_size], page, total_pages


def _telegram_profile_keyboard(action_prefix: str, profiles: list[dict[str, Any]], page: int = 0) -> tuple[list[list[dict[str, Any]]], int, int]:
    page_profiles, page, total_pages = _telegram_paginate(profiles, page)
    keyboard: list[list[dict[str, Any]]] = []
    for profile in page_profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        keyboard.append([{"text": f"👤 {name}"[:48], "callback_data": f"{action_prefix}:{profile_id}:{page}"}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"{action_prefix}:page:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"{action_prefix}:page:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "🏠 Menu", "callback_data": "m:home"}])
    return keyboard, page, total_pages


def _telegram_main_menu_text() -> str:
    return (
        "<b>🛠 NextDNS Telegram Control</b>\n\n"
        "/status - 📊 current state\n"
        "/profiles - 👤 monitored profiles\n"
        "/filters - 🔕 per-profile reason overrides\n"
        "/ignore domain.com - 🚫 alert ignore patterns\n"
        "/list - 📋 ignored patterns list\n"
        "/denylist domain.com - 🧱 NextDNS denylist\n"
        "/tlds ru - 🌐 blocked TLDs\n"
        "/logs - 🧾 recent profile logs"
    )


def _telegram_main_menu_keyboard() -> list[list[dict[str, Any]]]:
    return [
        [{"text": "👤 Profiles", "callback_data": "m:profiles"}, {"text": "🔕 Filters", "callback_data": "m:filters"}],
        [{"text": "🚫 Ignore List", "callback_data": "m:list"}, {"text": "🧱 Denylist", "callback_data": "m:denylist"}],
        [{"text": "🌐 TLDs", "callback_data": "m:tlds"}, {"text": "🧾 Logs", "callback_data": "m:logs"}],
        [{"text": "📊 Status", "callback_data": "m:status"}],
    ]


def _telegram_bot_commands() -> list[dict[str, str]]:
    return [
        {"command": "start", "description": "Open main menu"},
        {"command": "help", "description": "Show available commands"},
        {"command": "status", "description": "Show bot and profile status"},
        {"command": "profiles", "description": "Toggle monitored profiles"},
        {"command": "filters", "description": "Manage per-profile reason filters"},
        {"command": "ignore", "description": "Manage alert ignore patterns"},
        {"command": "list", "description": "Show ignored alert patterns"},
        {"command": "denylist", "description": "Manage NextDNS denylist"},
        {"command": "tlds", "description": "Manage blocked TLDs"},
        {"command": "logs", "description": "Show recent profile logs"},
    ]


def set_bot_commands(token: str, logger: Callable[[str], None] | None = None) -> None:
    try:
        _telegram_api_post(token.strip(), "setMyCommands", {"commands": _telegram_bot_commands()})
    except RuntimeError as exc:
        _telegram_log(logger, f"[WARN] Failed to register Telegram bot commands: {exc}")


def _telegram_reply_or_edit(
    token: str,
    target_chat_id: str,
    message_id: int | None,
    text: str,
    keyboard: list[list[dict[str, Any]]] | None = None,
    edit: bool = False,
) -> None:
    if edit and message_id is not None:
        _telegram_edit_message(token, target_chat_id, message_id, text, keyboard)
    else:
        _telegram_send_message(token, target_chat_id, text, keyboard)


def _telegram_send_status(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    enabled = 0
    custom_filters = 0
    ignored_patterns = 0
    for profile in profiles:
        cfg = legacy_state.get_profile(str(profile.get("id", "")))
        if cfg.get("enabled", True):
            enabled += 1
        if cfg.get("disabled_reasons_custom") is not None:
            custom_filters += 1
        ignored_patterns += len(cfg.get("blacklist", []) or [])
    text = (
        "<b>Status</b>\n\n"
        f"Profiles cached: {len(profiles)}\n"
        f"Alert monitoring enabled profiles: {enabled}\n"
        f"Profiles with custom reason overrides: {custom_filters}\n"
        f"Alert ignored patterns: {ignored_patterns}\n"
        f"Global ignored reasons: {len(legacy_state.state.get('disabled_reasons', []) or [])}"
    )
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, [[{"text": "🏠 Menu", "callback_data": "m:home"}]], edit)


def _telegram_show_profiles(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    page_profiles, page, total_pages = _telegram_paginate(profiles, page)
    keyboard: list[list[dict[str, Any]]] = []
    for profile in page_profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        enabled = bool(legacy_state.get_profile(profile_id).get("enabled", True))
        keyboard.append([{"text": f"{'✅' if enabled else '❌'} {name}"[:60], "callback_data": f"pr:{profile_id}:{page}"}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"pp:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"pp:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "🏠 Menu", "callback_data": "m:home"}])
    text = f"<b>👤 Profiles</b> ({page + 1}/{total_pages})\n\n✅ = alerts monitored, ❌ = skipped. Tap a profile to toggle."
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, keyboard, edit)


def _telegram_show_filters_profile_picker(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    page: int = 0,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    keyboard, page, total_pages = _telegram_profile_keyboard("fp", profiles, page)
    _telegram_reply_or_edit(
        token,
        target_chat_id,
        message_id,
        f"<b>🔕 Filters</b> ({page + 1}/{total_pages})\n\nChoose a profile for reason overrides.",
        keyboard,
        edit,
    )


def _telegram_reason_options(nextdns: Any, profile_id: str) -> list[tuple[str, str]]:
    reasons = _telegram_cached_reasons(nextdns, profile_id)
    out: list[tuple[str, str]] = []
    for reason in reasons:
        rid = str(reason.get("id", "")).strip()
        if not rid:
            continue
        out.append((rid, str(reason.get("name", rid)).strip() or rid))
    return sorted(out, key=lambda item: item[1].lower())


def _telegram_show_filters(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    nextdns: Any,
    profiles: list[dict[str, Any]],
    profile_id: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    if _telegram_get_profile(profiles, profile_id) is None:
        _telegram_reply_or_edit(token, target_chat_id, message_id, "Unknown profile.", [[{"text": "🏠 Menu", "callback_data": "m:home"}]], edit)
        return
    options = _telegram_reason_options(nextdns, profile_id)
    page_items, page, total_pages = _telegram_paginate(options, page)
    cfg = legacy_state.get_profile(profile_id)
    selected = set(legacy_state.get_disabled_reasons(profile_id))
    mode = "custom" if cfg.get("disabled_reasons_custom") is not None else "global"
    keyboard: list[list[dict[str, Any]]] = []
    start_idx = page * TELEGRAM_PAGE_SIZE
    for idx, (reason_id, name) in enumerate(page_items, start=start_idx):
        disabled = reason_id in selected
        callback = f"fr:{profile_id}:{page}:{idx}:{_telegram_reason_token(reason_id)}"
        keyboard.append([{"text": f"{'🔕 OFF' if disabled else '✅ ON'} {name}"[:60], "callback_data": callback}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"fs:{profile_id}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"fs:{profile_id}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([
        {"text": "🌍 Use global", "callback_data": f"fg:{profile_id}:{page}"},
        {"text": "📋 Copy global", "callback_data": f"fc:{profile_id}:{page}"},
    ])
    keyboard.append([{"text": "⬅️ Back", "callback_data": "m:filters"}, {"text": "🏠 Menu", "callback_data": "m:home"}])
    text = (
        f"<b>🔕 Filters: {html_escape(_telegram_profile_name(profiles, profile_id))}</b> ({page + 1}/{total_pages}, {len(options)} reasons)\n"
        f"Mode: <b>{mode}</b>. Alert is muted only when all event reasons are 🔕 OFF.\n"
        "Toggling creates/updates this profile override only."
    )
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, keyboard, edit)


def _telegram_show_ignore_list(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    grouped: dict[str, list[str]] = {}
    for profile in profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        for pattern in legacy_state.get_ignore_patterns(profile_id):
            grouped.setdefault(pattern, []).append(name)
    if not grouped:
        text = "<b>🚫 Ignore List</b>\n\nNo ignored alert patterns.\nUse <code>/ignore domain.com</code>."
    else:
        lines = ["<b>🚫 Ignore List</b>"]
        for pattern, names in sorted(grouped.items()):
            lines.append(f"<code>{html_escape(pattern)}</code> - {html_escape(', '.join(sorted(set(names))))}")
        text = _telegram_clip_lines(lines)
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, [[{"text": "🏠 Menu", "callback_data": "m:home"}]], edit)


def _telegram_show_ignore_profile_picker(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    sid: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    pattern = _telegram_get_session(legacy_state, sid, "ignore")
    if not pattern:
        _telegram_reply_or_edit(token, target_chat_id, message_id, "Ignore session expired. Use /ignore domain.com again.", None, edit)
        return
    page_profiles, page, total_pages = _telegram_paginate(profiles, page)
    keyboard: list[list[dict[str, Any]]] = []
    for profile in page_profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        current = legacy_state.get_ignore_patterns(profile_id)
        keyboard.append([{"text": f"{'✅ IGNORED' if pattern in current else '➕ NOT IGNORED'} {name}"[:60], "callback_data": f"ic:{sid}:{profile_id}:{page}"}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"ip:{sid}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"ip:{sid}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "🏠 Menu", "callback_data": "m:home"}])
    text = f"<b>🚫 Ignore Pattern</b>\n<code>{html_escape(pattern)}</code>\n\nTap profiles to toggle alert ignore."
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, keyboard, edit)


def _telegram_show_nextdns_domain_picker(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    nextdns: Any,
    sid: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    domain = _telegram_get_session(legacy_state, sid, "deny")
    if not domain:
        _telegram_reply_or_edit(token, target_chat_id, message_id, "Denylist session expired. Use /denylist domain.com again.", None, edit)
        return
    page_profiles, page, total_pages = _telegram_paginate(profiles, page)
    keyboard: list[list[dict[str, Any]]] = []
    for profile in page_profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        in_denylist = domain in set(_telegram_cached_denylist(nextdns, profile_id))
        action = "dr" if in_denylist else "da"
        keyboard.append([{"text": f"{'🗑 REMOVE' if in_denylist else '➕ ADD'} {name}"[:60], "callback_data": f"{action}:{sid}:{profile_id}:{page}"}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"dp:{sid}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"dp:{sid}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "🏠 Menu", "callback_data": "m:home"}])
    text = f"<b>🧱 Denylist Domain</b>\n<code>{html_escape(domain)}</code>\n\n➕ ADD / 🗑 REMOVE uses the selected NextDNS profile denylist."
    _telegram_reply_or_edit(token, target_chat_id, message_id, text, keyboard, edit)


def _telegram_show_denylist_profile_picker(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    page: int = 0,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    keyboard, page, total_pages = _telegram_profile_keyboard("dl", profiles, page)
    _telegram_reply_or_edit(token, target_chat_id, message_id, f"<b>🧱 Denylist</b> ({page + 1}/{total_pages})\n\nChoose a profile to list.", keyboard, edit)


def _telegram_show_denylist(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    nextdns: Any,
    profile_id: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    domains = _telegram_cached_denylist(nextdns, profile_id)
    page_items, page, total_pages = _telegram_paginate(domains, page, 20)
    name = _telegram_profile_name(profiles, profile_id)
    lines = [f"<b>🧱 Denylist: {html_escape(name)}</b> ({page + 1}/{total_pages})"]
    if page_items:
        lines.extend([f"<code>{html_escape(item)}</code>" for item in page_items])
    else:
        lines.append("No denylist domains.")
    keyboard: list[list[dict[str, Any]]] = []
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"dl:{profile_id}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"dl:{profile_id}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "⬅️ Back", "callback_data": "m:denylist"}, {"text": "🏠 Menu", "callback_data": "m:home"}])
    _telegram_reply_or_edit(token, target_chat_id, message_id, _telegram_clip_lines(lines), keyboard, edit)


def _telegram_show_tld_picker(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    page: int = 0,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    keyboard, page, total_pages = _telegram_profile_keyboard("tl", profiles, page)
    _telegram_reply_or_edit(token, target_chat_id, message_id, f"<b>🌐 TLDs</b> ({page + 1}/{total_pages})\n\nChoose a profile to list.", keyboard, edit)


def _telegram_show_tld_profile_action(
    token: str,
    target_chat_id: str,
    legacy_state: LegacyStateManager,
    profiles: list[dict[str, Any]],
    nextdns: Any,
    sid: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    tld = _telegram_get_session(legacy_state, sid, "tld")
    if not tld:
        _telegram_reply_or_edit(token, target_chat_id, message_id, "TLD session expired. Use /tlds ru again.", None, edit)
        return
    page_profiles, page, total_pages = _telegram_paginate(profiles, page)
    keyboard: list[list[dict[str, Any]]] = []
    for profile in page_profiles:
        profile_id = str(profile.get("id", "")).strip()
        name = str(profile.get("name", profile_id))
        blocked = tld in set(_telegram_cached_tlds(nextdns, profile_id))
        action = "tr" if blocked else "ta"
        keyboard.append([{"text": f"{'✅ UNBLOCK' if blocked else '🚫 BLOCK'} {name}"[:60], "callback_data": f"{action}:{sid}:{profile_id}:{page}"}])
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"tp:{sid}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"tp:{sid}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "🏠 Menu", "callback_data": "m:home"}])
    _telegram_reply_or_edit(token, target_chat_id, message_id, f"<b>🌐 TLD</b>\n<code>{html_escape(tld)}</code>\n\nChoose a profile.", keyboard, edit)


def _telegram_show_tlds(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    nextdns: Any,
    profile_id: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    tlds = _telegram_cached_tlds(nextdns, profile_id)
    page_items, page, total_pages = _telegram_paginate(tlds, page, 30)
    name = _telegram_profile_name(profiles, profile_id)
    lines = [f"<b>🌐 Blocked TLDs: {html_escape(name)}</b> ({page + 1}/{total_pages})"]
    lines.append(", ".join([html_escape(item) for item in page_items]) if page_items else "No blocked TLDs.")
    keyboard: list[list[dict[str, Any]]] = []
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"tl:{profile_id}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"tl:{profile_id}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    keyboard.append([{"text": "⬅️ Back", "callback_data": "m:tlds"}, {"text": "🏠 Menu", "callback_data": "m:home"}])
    _telegram_reply_or_edit(token, target_chat_id, message_id, _telegram_clip_lines(lines), keyboard, edit)


def _telegram_show_logs_profile_picker(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    page: int = 0,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    keyboard, page, total_pages = _telegram_profile_keyboard("lp", profiles, page)
    _telegram_reply_or_edit(token, target_chat_id, message_id, f"<b>🧾 Logs</b> ({page + 1}/{total_pages})\n\nChoose a profile.", keyboard, edit)


def _telegram_show_logs(
    token: str,
    target_chat_id: str,
    profiles: list[dict[str, Any]],
    nextdns: Any,
    profile_id: str,
    mode: str,
    page: int,
    message_id: int | None = None,
    edit: bool = False,
) -> None:
    mode = "a" if mode == "a" else "b"
    logs = _telegram_cached_logs(nextdns, profile_id)
    if mode == "b":
        logs = [item for item in logs if str(item.get("status", "")).lower() in BLOCKED_STATUSES]
    page_items, page, total_pages = _telegram_paginate(logs, page, TELEGRAM_LOG_PAGE_SIZE)
    name = _telegram_profile_name(profiles, profile_id)
    lines = [f"<b>🧾 Logs: {html_escape(name)}</b> ({'blocked' if mode == 'b' else 'all'}, {page + 1}/{total_pages})"]
    for item in page_items:
        ts = format_timestamp_display(str(item.get("timestamp", "")))
        domain = html_escape(str(item.get("domain", "")))
        status = html_escape(str(item.get("status", "")))
        client_ip = html_escape(str(item.get("clientIp", "") or "unknown-ip"))
        _device_id, device_name = extract_device_info(item)
        device_text = html_escape(device_name or "Unknown device")
        reasons = ", ".join([str(r.get("name", r.get("id", ""))) for r in item.get("reasons", []) if isinstance(r, dict)])
        reason_text = f" | {html_escape(reasons)}" if reasons else ""
        lines.append(f"{html_escape(ts)} | <code>{domain}</code> | {status}{reason_text}\n📱 {device_text} | 🌐 <code>{client_ip}</code>")
    if not page_items:
        lines.append("No logs.")
    keyboard: list[list[dict[str, Any]]] = []
    nav: list[dict[str, Any]] = []
    if page > 0:
        nav.append({"text": "⬅️ Prev", "callback_data": f"lg:{profile_id}:{mode}:{page - 1}"})
    if page < total_pages - 1:
        nav.append({"text": "➡️ Next", "callback_data": f"lg:{profile_id}:{mode}:{page + 1}"})
    if nav:
        keyboard.append(nav)
    other_mode = "a" if mode == "b" else "b"
    keyboard.append([{"text": "📜 Show all" if mode == "b" else "🛡 Blocked only", "callback_data": f"lg:{profile_id}:{other_mode}:0"}])
    keyboard.append([{"text": "⬅️ Back", "callback_data": "m:logs"}, {"text": "🏠 Menu", "callback_data": "m:home"}])
    _telegram_reply_or_edit(token, target_chat_id, message_id, _telegram_clip_lines(lines), keyboard, edit)


def process_telegram_updates(
    token: str,
    chat_id: str,
    legacy_state: LegacyStateManager,
    offset: int,
    nextdns: Any | None = None,
    logger: Callable[[str], None] | None = None,
) -> tuple[int, int, int]:
    token_clean = token.strip()
    chat_id_clean = chat_id.strip()
    if not token_clean or not chat_id_clean:
        return max(0, int(offset or 0)), 0, 0

    current_offset = max(0, int(offset or 0))
    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{token_clean}/getUpdates",
            params={"offset": current_offset, "limit": 100, "timeout": 0},
            timeout=APP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Telegram getUpdates failed: {redact_telegram_token(str(exc), token_clean)}") from exc

    if resp.status_code == 409:
        raise RuntimeError(
            "Telegram getUpdates failed (409). Another bot process or webhook may be active; "
            "check getWebhookInfo and ensure only one process polls this token."
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Telegram getUpdates failed ({resp.status_code})")

    payload = resp.json()
    if not payload.get("ok"):
        desc = str(payload.get("description", "unknown Telegram API error"))
        raise RuntimeError(f"Telegram getUpdates error: {desc}")

    updates = payload.get("result", [])
    next_offset = current_offset
    handled_updates = 0
    changed_actions = 0
    state_changed = False

    def profiles() -> list[dict[str, Any]]:
        return _telegram_profiles(legacy_state, nextdns)

    def require_nextdns(target_chat_id: str, message_id: int | None = None, edit: bool = False) -> bool:
        if nextdns is not None:
            return True
        _telegram_reply_or_edit(token_clean, target_chat_id, message_id, "NextDNS API is not available for this command.", None, edit)
        return False

    def show_home(target_chat_id: str, message_id: int | None = None, edit: bool = False) -> None:
        _telegram_reply_or_edit(token_clean, target_chat_id, message_id, _telegram_main_menu_text(), _telegram_main_menu_keyboard(), edit)

    def handle_command(message: dict[str, Any]) -> None:
        nonlocal changed_actions
        target_chat_id, _message_id = _telegram_message_target(message, chat_id_clean)
        text = str(message.get("text", "")).strip()
        if not text.startswith("/"):
            return
        parts = text.split()
        command = parts[0].split("@", 1)[0].lower()
        args = parts[1:]
        current_profiles = profiles()

        if command in {"/start", "/help", "/menu"}:
            show_home(target_chat_id)
        elif command == "/status":
            _telegram_send_status(token_clean, target_chat_id, legacy_state, current_profiles)
        elif command == "/profiles":
            _telegram_show_profiles(token_clean, target_chat_id, legacy_state, current_profiles, 0)
        elif command == "/filters":
            if require_nextdns(target_chat_id):
                _telegram_show_filters_profile_picker(token_clean, target_chat_id, current_profiles)
        elif command in {"/list", "/ignorelist"}:
            _telegram_show_ignore_list(token_clean, target_chat_id, legacy_state, current_profiles)
        elif command == "/ignore":
            if not args:
                _telegram_show_ignore_list(token_clean, target_chat_id, legacy_state, current_profiles)
                return
            pattern = normalize_domain(args[0])
            if not is_valid_domain_pattern(pattern):
                _telegram_send_message(token_clean, target_chat_id, "Invalid domain pattern. Use domain.com or *.domain.com.")
                return
            sid = _telegram_create_session(legacy_state, "ignore", pattern)
            _telegram_show_ignore_profile_picker(token_clean, target_chat_id, legacy_state, current_profiles, sid, 0)
        elif command == "/denylist":
            if not require_nextdns(target_chat_id):
                return
            if not args:
                _telegram_show_denylist_profile_picker(token_clean, target_chat_id, current_profiles)
                return
            domain = normalize_domain(args[0])
            if not is_valid_domain(domain):
                _telegram_send_message(token_clean, target_chat_id, "Invalid domain. Denylist accepts domain.com, not wildcard patterns.")
                return
            sid = _telegram_create_session(legacy_state, "deny", domain)
            _telegram_show_nextdns_domain_picker(token_clean, target_chat_id, legacy_state, current_profiles, nextdns, sid, 0)
        elif command == "/tlds":
            if not require_nextdns(target_chat_id):
                return
            if not args:
                _telegram_show_tld_picker(token_clean, target_chat_id, current_profiles)
                return
            tld = args[0].strip().lower().lstrip(".")
            if not is_valid_tld(tld):
                _telegram_send_message(token_clean, target_chat_id, "Invalid TLD. Use ru, cn, zip, etc.")
                return
            sid = _telegram_create_session(legacy_state, "tld", tld)
            _telegram_show_tld_profile_action(token_clean, target_chat_id, legacy_state, current_profiles, nextdns, sid, 0)
        elif command == "/logs":
            if require_nextdns(target_chat_id):
                _telegram_show_logs_profile_picker(token_clean, target_chat_id, current_profiles)
        else:
            show_home(target_chat_id)

    def handle_callback(callback: dict[str, Any]) -> None:
        nonlocal changed_actions, state_changed
        callback_id = str(callback.get("id", "")).strip()
        target_chat_id, message_id = _telegram_message_target(callback, chat_id_clean)
        data = str(callback.get("data", "")).strip()
        current_profiles = profiles()

        if not data:
            _telegram_answer_callback(token_clean, callback_id, "Unsupported action")
            return

        try:
            if data.startswith("qi:"):
                parts = data.split(":", 2)
                if len(parts) != 3:
                    _telegram_answer_callback(token_clean, callback_id, "Invalid ignore payload")
                    return
                domain = _telegram_get_session(legacy_state, parts[1], "ignore") or ""
                profile_id = parts[2].strip()
                if _telegram_get_profile(current_profiles, profile_id) is None or not is_valid_domain_pattern(domain):
                    _telegram_answer_callback(token_clean, callback_id, "Ignore session expired")
                    return
                with legacy_state.lock:
                    current = legacy_state.get_ignore_patterns(profile_id)
                    already_ignored = domain in current
                    if not already_ignored:
                        legacy_state.set_ignore_patterns(profile_id, current | {domain})
                if already_ignored:
                    _telegram_answer_callback(token_clean, callback_id, f"Already ignored: {domain}")
                else:
                    legacy_state.save()
                    changed_actions += 1
                    state_changed = True
                    _telegram_answer_callback(token_clean, callback_id, f"Ignored: {domain}")
                return

            _telegram_answer_callback(token_clean, callback_id)

            if data == "m:home":
                show_home(target_chat_id, message_id, True)
            elif data == "m:status":
                _telegram_send_status(token_clean, target_chat_id, legacy_state, current_profiles, message_id, True)
            elif data == "m:profiles":
                _telegram_show_profiles(token_clean, target_chat_id, legacy_state, current_profiles, 0, message_id, True)
            elif data == "m:filters":
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_filters_profile_picker(token_clean, target_chat_id, current_profiles, 0, message_id, True)
            elif data == "m:list":
                _telegram_show_ignore_list(token_clean, target_chat_id, legacy_state, current_profiles, message_id, True)
            elif data == "m:denylist":
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_denylist_profile_picker(token_clean, target_chat_id, current_profiles, 0, message_id, True)
            elif data == "m:tlds":
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_tld_picker(token_clean, target_chat_id, current_profiles, 0, message_id, True)
            elif data == "m:logs":
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_logs_profile_picker(token_clean, target_chat_id, current_profiles, 0, message_id, True)
            elif data.startswith("pp:"):
                _telegram_show_profiles(token_clean, target_chat_id, legacy_state, current_profiles, int(data.split(":")[1]), message_id, True)
            elif data.startswith("pr:"):
                _, profile_id, page_raw = data.split(":", 2)
                if _telegram_get_profile(current_profiles, profile_id) is None:
                    raise ValueError("Unknown profile")
                with legacy_state.lock:
                    enabled = bool(legacy_state.get_profile(profile_id).get("enabled", True))
                    legacy_state.update_profile(profile_id, enabled=not enabled)
                legacy_state.save()
                changed_actions += 1
                state_changed = True
                _telegram_show_profiles(token_clean, target_chat_id, legacy_state, current_profiles, int(page_raw), message_id, True)
            elif data.startswith("fp:"):
                parts = data.split(":")
                if parts[1] == "page":
                    _telegram_show_filters_profile_picker(token_clean, target_chat_id, current_profiles, int(parts[2]), message_id, True)
                elif require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_filters(token_clean, target_chat_id, legacy_state, nextdns, current_profiles, parts[1], 0, message_id, True)
            elif data.startswith("fs:"):
                _, profile_id, page_raw = data.split(":", 2)
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_filters(token_clean, target_chat_id, legacy_state, nextdns, current_profiles, profile_id, int(page_raw), message_id, True)
            elif data.startswith("fr:"):
                _, profile_id, page_raw, idx_raw, reason_token = data.split(":", 4)
                if require_nextdns(target_chat_id, message_id, True):
                    options = _telegram_reason_options(nextdns, profile_id)
                    idx = int(idx_raw)
                    if idx < 0 or idx >= len(options):
                        raise ValueError("Reason index out of range")
                    reason_id = options[idx][0]
                    if _telegram_reason_token(reason_id) != reason_token:
                        raise ValueError("Reason list changed, reopen /filters")
                    with legacy_state.lock:
                        current = set(legacy_state.get_disabled_reasons(profile_id))
                        current.symmetric_difference_update({reason_id})
                        legacy_state.update_profile(profile_id, disabled_reasons_custom=sorted(current))
                    legacy_state.save()
                    changed_actions += 1
                    state_changed = True
                    _telegram_show_filters(token_clean, target_chat_id, legacy_state, nextdns, current_profiles, profile_id, int(page_raw), message_id, True)
            elif data.startswith("fg:"):
                _, profile_id, page_raw = data.split(":", 2)
                legacy_state.clear_disabled_reasons_override([profile_id])
                legacy_state.save()
                changed_actions += 1
                state_changed = True
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_filters(token_clean, target_chat_id, legacy_state, nextdns, current_profiles, profile_id, int(page_raw), message_id, True)
            elif data.startswith("fc:"):
                _, profile_id, page_raw = data.split(":", 2)
                with legacy_state.lock:
                    global_reasons = list(legacy_state.state.get("disabled_reasons", []) or [])
                    legacy_state.set_disabled_reasons([profile_id], global_reasons)
                legacy_state.save()
                changed_actions += 1
                state_changed = True
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_filters(token_clean, target_chat_id, legacy_state, nextdns, current_profiles, profile_id, int(page_raw), message_id, True)
            elif data.startswith("ip:"):
                _, sid, page_raw = data.split(":", 2)
                _telegram_show_ignore_profile_picker(token_clean, target_chat_id, legacy_state, current_profiles, sid, int(page_raw), message_id, True)
            elif data.startswith("ic:"):
                _, sid, profile_id, page_raw = data.split(":", 3)
                pattern = _telegram_get_session(legacy_state, sid, "ignore")
                if not pattern or _telegram_get_profile(current_profiles, profile_id) is None:
                    raise ValueError("Invalid ignore session")
                with legacy_state.lock:
                    current = legacy_state.get_ignore_patterns(profile_id)
                    current.symmetric_difference_update({pattern})
                    legacy_state.set_ignore_patterns(profile_id, current)
                legacy_state.save()
                changed_actions += 1
                state_changed = True
                _telegram_show_ignore_profile_picker(token_clean, target_chat_id, legacy_state, current_profiles, sid, int(page_raw), message_id, True)
            elif data.startswith("dp:"):
                _, sid, page_raw = data.split(":", 2)
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_nextdns_domain_picker(token_clean, target_chat_id, legacy_state, current_profiles, nextdns, sid, int(page_raw), message_id, True)
            elif data.startswith("da:") or data.startswith("dr:"):
                op, sid, profile_id, page_raw = data.split(":", 3)
                domain = _telegram_get_session(legacy_state, sid, "deny")
                if not domain:
                    raise ValueError("Denylist session expired")
                action = "add" if op == "da" else "remove"
                text = f"⚠️ Confirm {action} <code>{html_escape(domain)}</code> for {html_escape(_telegram_profile_name(current_profiles, profile_id))}?"
                keyboard = [[
                    {"text": "✅ Confirm", "callback_data": f"dc:{op[-1]}:{sid}:{profile_id}:{page_raw}"},
                    {"text": "↩️ Cancel", "callback_data": f"dp:{sid}:{page_raw}"},
                ]]
                _telegram_reply_or_edit(token_clean, target_chat_id, message_id, text, keyboard, True)
            elif data.startswith("dc:"):
                _, op, sid, profile_id, page_raw = data.split(":", 4)
                domain = _telegram_get_session(legacy_state, sid, "deny")
                if not domain or not require_nextdns(target_chat_id, message_id, True):
                    return
                ok, msg = nextdns.add_deny_domain(profile_id, domain) if op == "a" else nextdns.remove_deny_domain(profile_id, domain)
                _TELEGRAM_API_CACHE.invalidate(f"deny:{profile_id}")
                changed_actions += 1 if ok else 0
                _telegram_reply_or_edit(token_clean, target_chat_id, message_id, html_escape(msg), [[{"text": "⬅️ Back", "callback_data": f"dp:{sid}:{page_raw}"}]], True)
            elif data.startswith("dl:"):
                parts = data.split(":")
                if parts[1] == "page":
                    _telegram_show_denylist_profile_picker(token_clean, target_chat_id, current_profiles, int(parts[2]), message_id, True)
                elif require_nextdns(target_chat_id, message_id, True):
                    # parts[2] is the profile-picker page, not a denylist page.
                    _telegram_show_denylist(token_clean, target_chat_id, current_profiles, nextdns, parts[1], 0, message_id, True)
            elif data.startswith("tp:"):
                _, sid, page_raw = data.split(":", 2)
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_tld_profile_action(token_clean, target_chat_id, legacy_state, current_profiles, nextdns, sid, int(page_raw), message_id, True)
            elif data.startswith("ta:") or data.startswith("tr:"):
                op, sid, profile_id, page_raw = data.split(":", 3)
                tld = _telegram_get_session(legacy_state, sid, "tld")
                if not tld:
                    raise ValueError("TLD session expired")
                action = "block" if op == "ta" else "unblock"
                text = f"⚠️ Confirm {action} TLD <code>{html_escape(tld)}</code> for {html_escape(_telegram_profile_name(current_profiles, profile_id))}?"
                keyboard = [[
                    {"text": "✅ Confirm", "callback_data": f"tc:{op[-1]}:{sid}:{profile_id}:{page_raw}"},
                    {"text": "↩️ Cancel", "callback_data": f"tp:{sid}:{page_raw}"},
                ]]
                _telegram_reply_or_edit(token_clean, target_chat_id, message_id, text, keyboard, True)
            elif data.startswith("tc:"):
                _, op, sid, profile_id, page_raw = data.split(":", 4)
                tld = _telegram_get_session(legacy_state, sid, "tld")
                if not tld or not require_nextdns(target_chat_id, message_id, True):
                    return
                current = set(nextdns.get_security_tlds(profile_id))
                if op == "a":
                    current.add(tld)
                else:
                    current.discard(tld)
                ok, msg = nextdns.patch_security_tlds(profile_id, sorted(current))
                _TELEGRAM_API_CACHE.invalidate(f"tld:{profile_id}")
                changed_actions += 1 if ok else 0
                _telegram_reply_or_edit(token_clean, target_chat_id, message_id, html_escape(msg), [[{"text": "⬅️ Back", "callback_data": f"tp:{sid}:{page_raw}"}]], True)
            elif data.startswith("tl:"):
                parts = data.split(":")
                if parts[1] == "page":
                    _telegram_show_tld_picker(token_clean, target_chat_id, current_profiles, int(parts[2]), message_id, True)
                elif require_nextdns(target_chat_id, message_id, True):
                    # parts[2] is the profile-picker page, not a TLD page.
                    _telegram_show_tlds(token_clean, target_chat_id, current_profiles, nextdns, parts[1], 0, message_id, True)
            elif data.startswith("lp:"):
                parts = data.split(":")
                if parts[1] == "page":
                    _telegram_show_logs_profile_picker(token_clean, target_chat_id, current_profiles, int(parts[2]), message_id, True)
                elif require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_logs(token_clean, target_chat_id, current_profiles, nextdns, parts[1], "b", 0, message_id, True)
            elif data.startswith("lg:"):
                _, profile_id, mode, page_raw = data.split(":", 3)
                if require_nextdns(target_chat_id, message_id, True):
                    _telegram_show_logs(token_clean, target_chat_id, current_profiles, nextdns, profile_id, mode, int(page_raw), message_id, True)
            else:
                show_home(target_chat_id, message_id, True)
        except (ValueError, KeyError, TypeError, RuntimeError) as exc:
            reported = redact_telegram_token(str(exc), token_clean)
            _telegram_log(logger, f"[WARN] Telegram action failed: {reported}")
            _telegram_reply_or_edit(token_clean, target_chat_id, message_id, f"Action failed: {html_escape(reported)}", [[{"text": "🏠 Menu", "callback_data": "m:home"}]], True)

    def handle_update(update: dict[str, Any]) -> None:
        nonlocal handled_updates
        callback = update.get("callback_query")
        message = update.get("message")
        if isinstance(callback, dict):
            if not _telegram_is_authorized(callback, chat_id_clean):
                _telegram_answer_callback(token_clean, str(callback.get("id", "")), "Not authorized")
                return
            handled_updates += 1
            handle_callback(callback)
        elif isinstance(message, dict):
            if not _telegram_is_authorized(message, chat_id_clean):
                return
            handled_updates += 1
            try:
                handle_command(message)
            except (ValueError, KeyError, TypeError, RuntimeError) as exc:
                reported = redact_telegram_token(str(exc), token_clean)
                _telegram_log(logger, f"[WARN] Telegram command failed: {reported}")
                target_chat_id, _message_id = _telegram_message_target(message, chat_id_clean)
                _telegram_send_message(token_clean, target_chat_id, f"Command failed: {html_escape(reported)}")

    for update in updates:
        update_id = update.get("update_id")
        if isinstance(update_id, int):
            next_offset = max(next_offset, update_id + 1)
        # Never abort the batch: a lost offset makes Telegram replay handled updates.
        try:
            handle_update(update)
        except (ValueError, KeyError, TypeError, RuntimeError, requests.RequestException) as exc:
            _telegram_log(logger, f"[WARN] Telegram update {update_id} failed: {redact_telegram_token(str(exc), token_clean)}")

    if state_changed:
        try:
            legacy_state.save()
        except (OSError, PermissionError, TypeError, ValueError) as exc:
            _telegram_log(logger, f"[WARN] Failed to save Telegram state: {exc}")

    return next_offset, handled_updates, changed_actions


def send_alert_message(
    token: str,
    chat_id: str,
    legacy_state: LegacyStateManager,
    batch: AlertBatchQP,
    text: str,
    logger: Callable[[str], None] | None = None,
) -> bool:
    ignore_sid = _telegram_create_session(legacy_state, "ignore", batch.domain)
    encoded_domain = quote(batch.domain, safe="")
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {
            "inline_keyboard": [
                [
                    {"text": "🔍 URLHaus", "url": f"https://urlhaus.abuse.ch/host/{encoded_domain}/"},
                    {"text": "🔎 URLScan", "url": f"https://urlscan.io/search/#{encoded_domain}"},
                ],
                [
                    {"text": "🚫 Ignore", "callback_data": f"qi:{ignore_sid}:{batch.profile_id}"}
                ],
            ]
        },
    }
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=APP_TIMEOUT,
        )
    except requests.RequestException as exc:
        _telegram_log(logger, f"[WARN] Telegram alert send failed: {redact_telegram_token(str(exc), token)}")
        return False

    if resp.status_code != 200:
        _telegram_log(logger, f"[WARN] Telegram alert rejected ({resp.status_code}) for {batch.domain}")
        return False
    return True
