"""Headless polling loop: no GUI, alerts straight to Telegram."""

from __future__ import annotations

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .alerts import AlertBatchQP, format_batch_message_qp
from .caches import EventTTLCache
from .constants import (
    ALERT_EVENT_CACHE_MAX,
    ALERT_EVENT_CACHE_TTL_SECONDS,
    APP_STATE_FILE,
    BLOCKED_STATUSES,
    HEADLESS_FRESH_START_SECONDS,
    LEGACY_STATE_FILE,
    TELEGRAM_SEND_INTERVAL_SECONDS,
)
from .deps import requests
from .nextdns_api import NextDNSService
from .state import LegacyStateManager, PersistentStore
from .telegram_bot import (
    process_telegram_updates,
    redact_telegram_token,
    send_alert_message,
    set_bot_commands,
)
from .threat_intel import queryparser_enrichment_sync
from .utils import (
    collect_context_qp,
    domain_matches_pattern,
    extract_device_info,
    get_event_key_qp,
    parse_epoch_seconds,
)


def run_headless(root_dir: Path) -> None:
    progress_width = 0

    def clear_progress() -> None:
        nonlocal progress_width
        if progress_width <= 0:
            return
        sys.stdout.write("\r" + (" " * progress_width) + "\r")
        sys.stdout.flush()
        progress_width = 0

    def log(message: str) -> None:
        clear_progress()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} | Headless | {message}", flush=True)

    def progress(message: str) -> None:
        nonlocal progress_width
        if not sys.stdout.isatty():
            return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{timestamp} | Headless | {message}"
        progress_width = max(progress_width, len(line))
        sys.stdout.write("\r" + line.ljust(progress_width))
        sys.stdout.flush()

    store = PersistentStore(root_dir / APP_STATE_FILE)
    legacy = LegacyStateManager(root_dir / LEGACY_STATE_FILE)
    svc = NextDNSService(
        lambda: store.data["api"].get("nextdns_api_key", ""),
        on_rate_limit=lambda path, wait_s, attempt: log(
            f"NextDNS rate limit on {path}. Waiting {wait_s}s before retry ({attempt}/3)"
        ),
    )
    cache = EventTTLCache(ALERT_EVENT_CACHE_MAX, ALERT_EVENT_CACHE_TTL_SECONDS)

    token = store.data["api"].get("telegram_bot_token", "").strip()
    chat_id = store.data["api"].get("telegram_chat_id", "").strip()
    telegram_update_offset = max(0, int(store.data.get("alerts", {}).get("telegram_update_offset", 0) or 0))
    if not store.data["api"].get("nextdns_api_key", "").strip():
        log("NextDNS API key is required. Headless mode stopped.")
        return
    if not token or not chat_id:
        log("Telegram token/chat_id is required. Headless mode stopped.")
        return

    set_bot_commands(token, log)

    def poll_telegram_updates() -> int:
        nonlocal telegram_update_offset
        try:
            next_offset, _handled, added = process_telegram_updates(token, chat_id, legacy, telegram_update_offset, svc, log)
            if next_offset != telegram_update_offset:
                telegram_update_offset = next_offset
                store.data.setdefault("alerts", {})["telegram_update_offset"] = next_offset
                store.save()
            if added > 0:
                log(f"Applied {added} Telegram action(s)")
            return added
        except requests.RequestException as exc:
            log(f"[WARN] Telegram update polling failed: {redact_telegram_token(str(exc), token)}")
        except (RuntimeError, OSError, PermissionError, ValueError, KeyError, TypeError) as exc:
            log(f"[WARN] Telegram update processing failed: {redact_telegram_token(str(exc), token)}")
        return 0

    def wait_with_telegram_polling(wait_seconds: int) -> None:
        deadline = time.monotonic() + max(0, wait_seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(5, remaining))
            poll_telegram_updates()

    def enrichment_for(domain: str) -> str:
        return queryparser_enrichment_sync(
            domain,
            store.data["api"].get("urlhaus_api_key", "").strip(),
            store.data["api"].get("urlscan_api_key", "").strip(),
        )

    def send_batch_message(batch: AlertBatchQP, context: dict[str, Any]) -> bool:
        msg = format_batch_message_qp(batch, enrichment_for(batch.domain), context)
        return send_alert_message(token, chat_id, legacy, batch, msg, log)

    def one_cycle() -> None:
        nonlocal telegram_update_offset
        cycle_started = time.monotonic()
        cycle_profiles = 0
        cycle_logs = 0
        cycle_blocked = 0
        cycle_alerts = 0
        cycle_sent = 0
        log("Polling cycle started")

        poll_telegram_updates()

        profiles = svc.get_profiles()
        legacy.set_state_value("profiles_cache", profiles)
        log(f"Loaded {len(profiles)} profile(s)")
        legacy.save()

        for profile in profiles:
            profile_id = profile["id"]
            profile_name = profile.get("name", profile_id)
            cfg = legacy.get_profile(profile_id)
            if not cfg.get("enabled", True):
                log(f"Profile {profile_name} ({profile_id}): disabled, skipped")
                continue
            cycle_profiles += 1
            log(f"Profile {profile_name} ({profile_id}): fetching logs")

            current_cursor = str(cfg.get("cursor", "") or "").strip() or None
            last_success_ts = int(cfg.get("last_success_ts") or 0)
            cursor_mode_ready = bool(cfg.get("headless_cursor_mode_ready", False))
            ignore_patterns = legacy.get_ignore_patterns(profile_id)
            disabled_reasons = set(legacy.get_disabled_reasons(profile_id))
            batches: dict[str, AlertBatchQP] = {}
            batch_event_keys: dict[str, list[str]] = {}
            seen_keys: set[str] = set()
            all_logs: list[dict[str, Any]] = []
            latest_ts = last_success_ts
            profile_blocked = 0
            if last_success_ts > 0 and not cursor_mode_ready:
                current_cursor = None
                fresh_from = last_success_ts + 1
                log(f"Profile {profile_name}: migrating timestamp checkpoint to cursor")
            else:
                fresh_from = None if current_cursor else int(time.time()) - HEADLESS_FRESH_START_SECONDS
            page_num = 0

            while True:
                try:
                    logs, new_cursor = svc.get_logs_cursor(profile_id, cursor=current_cursor, from_ts=fresh_from)
                except RuntimeError as exc:
                    log(f"[WARN] Profile {profile_name}: failed to fetch cursor logs: {exc}")
                    break

                page_num += 1
                progress(f"Profile {profile_name}: page {page_num}, {len(logs)} log(s), {len(all_logs) + len(logs)} total")

                base_idx = len(all_logs)
                all_logs.extend(logs)
                for idx, event in enumerate(logs):
                    latest_ts = max(latest_ts, parse_epoch_seconds(str(event.get("timestamp", ""))))

                    if str(event.get("status", "")).lower() not in BLOCKED_STATUSES:
                        continue
                    profile_blocked += 1
                    domain = event.get("domain", "")
                    if any(domain_matches_pattern(domain, p) for p in ignore_patterns):
                        continue

                    reason_ids = [r.get("id", "") for r in event.get("reasons", []) if isinstance(r, dict)]
                    if reason_ids and all(rid in disabled_reasons for rid in reason_ids):
                        continue

                    ekey = get_event_key_qp(event, profile_id)
                    if ekey in seen_keys or cache.contains(ekey):
                        continue
                    seen_keys.add(ekey)

                    bkey = f"{profile_id}|{domain}"
                    batch_event_keys.setdefault(bkey, []).append(ekey)
                    _device_id, device_name = extract_device_info(event)
                    device_name = device_name or "Unknown"
                    ts = str(event.get("timestamp", ""))
                    reason_names = [r.get("name", "") for r in event.get("reasons", []) if isinstance(r, dict)]

                    if bkey in batches:
                        b = batches[bkey]
                        b.count += 1
                        b.last_timestamp = ts
                        b.devices.add(device_name)
                        b.reasons.update(reason_names)
                        b.reason_ids.update(reason_ids)
                    else:
                        batches[bkey] = AlertBatchQP(
                            domain=domain,
                            profile_id=profile_id,
                            profile_name=profile_name,
                            first_event_index=base_idx + idx,
                            first_timestamp=ts,
                            last_timestamp=ts,
                            devices={device_name},
                            reasons=set(reason_names),
                            reason_ids=set(reason_ids),
                        )

                cursor_advanced = bool(new_cursor) and new_cursor != current_cursor
                if cursor_advanced:
                    current_cursor = new_cursor
                    legacy.update_profile(profile_id, cursor=new_cursor, headless_cursor_mode_ready=True)
                    if latest_ts > 0:
                        legacy.update_profile(profile_id, last_success_ts=latest_ts)
                    legacy.save()

                fresh_from = None
                if not logs or len(logs) < 1000:
                    break
                if not cursor_advanced:
                    # Full page without a new cursor would refetch the same window forever.
                    log(f"[WARN] Profile {profile_name}: cursor did not advance, stopping pagination")
                    break

            if latest_ts > 0 and latest_ts != last_success_ts:
                legacy.update_profile(profile_id, last_success_ts=latest_ts)
                legacy.save()

            cycle_logs += len(all_logs)
            cycle_blocked += profile_blocked
            cycle_alerts += len(batches)
            log(
                f"Profile {profile_name}: {len(all_logs)} new log(s), "
                f"{profile_blocked} blocked, {len(batches)} alert batch(es)"
            )

            sent_for_profile = 0
            for idx, (bkey, batch) in enumerate(batches.items(), start=1):
                progress(f"Profile {profile_name}: sending Telegram alerts {idx}/{len(batches)}")
                context = collect_context_qp(all_logs, batch.first_event_index, all_logs[batch.first_event_index]) if 0 <= batch.first_event_index < len(all_logs) else {"before": [], "after": [], "header": "Surrounding DNS Queries:"}
                if send_batch_message(batch, context):
                    sent_for_profile += 1
                    # Dedupe only after delivery, so a failed send can retry next cycle.
                    for ekey in batch_event_keys.get(bkey, []):
                        cache.add(ekey)
                time.sleep(TELEGRAM_SEND_INTERVAL_SECONDS)
            cycle_sent += sent_for_profile
            if batches:
                log(f"Profile {profile_name}: Telegram alerts sent {sent_for_profile}/{len(batches)}")

        elapsed = time.monotonic() - cycle_started
        log(
            f"Polling cycle completed in {elapsed:.1f}s: {cycle_profiles} profile(s), "
            f"{cycle_logs} new log(s), {cycle_blocked} blocked, {cycle_sent}/{cycle_alerts} alert batch(es) sent"
        )

    continuous = bool(store.data["settings"].get("headless_continuous", True))
    interval = max(5, int(store.data["settings"].get("poll_interval_seconds", 30)))
    mode = "continuous" if continuous else "single run"
    log(f"Started ({mode}, interval {interval}s, cursor polling, page size 1000)")
    def run_one_cycle_guarded() -> None:
        try:
            one_cycle()
        except requests.RequestException as exc:
            log(f"[WARN] Network error in polling cycle: {redact_telegram_token(str(exc), token)}")
        except (RuntimeError, OSError, PermissionError, ValueError, KeyError, TypeError) as exc:
            log(f"[WARN] Polling cycle failed: {redact_telegram_token(str(exc), token)}")

    if continuous:
        try:
            while True:
                run_one_cycle_guarded()
                log(f"Waiting {interval}s before next cycle")
                wait_with_telegram_polling(interval)
        except KeyboardInterrupt:
            log("Stopped by user")
    else:
        run_one_cycle_guarded()
