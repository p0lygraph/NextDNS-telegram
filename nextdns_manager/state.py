"""Persisted state: the GUI store and the shared per-profile state file."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .constants import DEFAULT_LOG_COLUMNS
from .utils import normalize_domain


API_ENV_VARS = {
    "nextdns_api_key": "NEXTDNS_API_KEY",
    "urlhaus_api_key": "URLHAUS_API_KEY",
    "urlscan_api_key": "URLSCAN_API_KEY",
    "telegram_bot_token": "TELEGRAM_BOT_TOKEN",
    "telegram_chat_id": "TELEGRAM_USER_ID",
}


class PersistentStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._env_api: dict[str, tuple[str, Any]] = {}
        self.data = self._load()
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        api = self.data.get("api")
        if not isinstance(api, dict):
            api = self.data["api"] = dict.fromkeys(API_ENV_VARS, "")
        for key, env_name in API_ENV_VARS.items():
            value = os.getenv(env_name, "").strip()
            if not value:
                continue
            stored = api.get(key, "")
            # Stored copy of an env secret is a leak from older versions.
            is_leak = isinstance(stored, str) and stored.strip() == value
            self._env_api[key] = (value, "" if is_leak else stored)
            api[key] = value

    def _persistable(self) -> dict[str, Any]:
        api = self.data.get("api")
        if not self._env_api or not isinstance(api, dict):
            return self.data
        api = dict(api)
        for key, (env_value, stored) in self._env_api.items():
            if api.get(key) == env_value:
                api[key] = stored
            else:
                self._env_api[key] = (env_value, api.get(key))
        return {**self.data, "api": api}

    def _load(self) -> dict[str, Any]:
        defaults = {
            "version": 1,
            "last_tab": 0,
            "window": {"geometry": "1360x820"},
            "api": {
                "nextdns_api_key": "",
                "urlhaus_api_key": "",
                "urlscan_api_key": "",
                "telegram_bot_token": "",
                "telegram_chat_id": "",
            },
            "settings": {
                "poll_interval_seconds": 30,
                "autorefresh_enabled": False,
                "headless_continuous": True,
                "log_limit_per_profile": 500,
                "log_lookback_hours": 3,
                "ti_enabled": True,
                "ti_only_blocked_domains": True,
                "ti_skip_reason_ids": [],
                "ti_max_domains_per_refresh": 80,
                "ti_cache_ttl_seconds": 1800,
                "include_unblocked_logs": True,
                "blocked_row_color_mode": "default",
                "blocked_row_custom_color": "#ffd6d6",
                "normal_tlds": [
                    "com", "net", "org", "edu", "gov", "mil", "int", "co", "io", "ai",
                    "de", "uk", "fr", "it", "es", "nl", "ru", "ua", "pl", "cz", "at",
                    "ch", "se", "no", "fi", "dk", "jp", "kr", "cn", "in", "au", "ca",
                    "br", "mx", "tr", "id", "sg", "hk", "xyz", "me", "tv", "app", "dev"
                ],
            },
            "ui": {
                "selected_profiles": [],
                "selected_devices": [],
                "selected_alert_profiles": [],
                "selected_alert_ignore_profiles": [],
                "selected_ti_profiles": [],
                "selected_log_columns": DEFAULT_LOG_COLUMNS,
                "logs_search": "",
                "logs_filters": {
                    "blocked_only": False,
                    "malicious_only": False,
                    "unusual_tld_only": False,
                    "ignore_selected_reasons": True,
                },
                "ignored_reasons": [],
                "tlds_search": "",
                "denylist_search": "",
                "enabled_telegram_alerts": False,
            },
            "alerts": {
                "telegram_update_offset": 0,
            },
        }

        if not self.path.exists():
            return defaults

        try:
            with self.path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, PermissionError) as exc:
            print(f"[WARN] Failed to load state from {self.path}: {exc}")
            return defaults
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"[WARN] State at {self.path} is corrupt: {exc}")
            try:
                self.path.replace(self.path.with_suffix(".corrupt.json"))
            except (OSError, PermissionError):
                pass
            return defaults

        if not isinstance(loaded, dict):
            print(f"[WARN] State at {self.path} is not an object, using defaults")
            return defaults

        merged = self._deep_merge(defaults, loaded)
        merged.get("alerts", {}).pop("seen_event_keys", None)
        return merged

    def _deep_merge(self, base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        out = dict(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = self._deep_merge(out[k], v)
            else:
                out[k] = v
        return out

    def save(self) -> None:
        with self._lock:
            try:
                payload = json.dumps(self._persistable(), indent=2, ensure_ascii=True)
            except (TypeError, ValueError) as exc:
                print(f"[WARN] Failed to serialize state for {self.path}: {exc}")
                return
            try:
                tmp = self.path.with_suffix(".tmp")
                with tmp.open("w", encoding="utf-8") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                tmp.replace(self.path)
            except (OSError, PermissionError) as exc:
                print(f"[WARN] Failed to save state to {self.path}: {exc}")


class LegacyStateManager:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        defaults: dict[str, Any] = {
            "disabled_reasons": [],
            "profiles_cache": [],
            "profiles": {},
        }
        if not self.path.exists():
            return defaults
        try:
            with self.path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, PermissionError) as exc:
            print(f"[WARN] Failed to load legacy state from {self.path}: {exc}")
            return defaults
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"[WARN] Legacy state at {self.path} is corrupt: {exc}")
            self._backup_corrupt()
            return defaults

        if not isinstance(loaded, dict):
            print(f"[WARN] Legacy state at {self.path} is not an object, using defaults")
            self._backup_corrupt()
            return defaults

        defaults.update(loaded)
        return defaults

    def _backup_corrupt(self) -> None:
        # Keep the unreadable file so the next save cannot silently destroy user data.
        try:
            self.path.replace(self.path.with_suffix(".corrupt.json"))
        except (OSError, PermissionError) as exc:
            print(f"[WARN] Failed to back up corrupt legacy state: {exc}")

    def save(self) -> None:
        # Write and replace stay locked: concurrent savers share one tmp path.
        with self.lock:
            try:
                payload = json.dumps(self.state, indent=2, ensure_ascii=True)
            except (TypeError, ValueError) as exc:
                print(f"[WARN] Failed to serialize legacy state: {exc}")
                return

            tmp = self.path.with_suffix(".tmp")
            try:
                with tmp.open("w", encoding="utf-8") as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                tmp.replace(self.path)
            except (OSError, PermissionError) as exc:
                print(f"[WARN] Failed to save legacy state to {self.path}: {exc}")

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            profiles = self.state.setdefault("profiles", {})
            if profile_id not in profiles:
                profiles[profile_id] = {
                    "cursor": None,
                    "last_success_ts": None,
                    "enabled": True,
                    "blacklist": [],
                    "disabled_reasons_custom": None,
                }
            return profiles[profile_id]

    def update_profile(self, profile_id: str, **fields: Any) -> None:
        with self.lock:
            self.get_profile(profile_id).update(fields)

    def set_state_value(self, key: str, value: Any) -> None:
        with self.lock:
            self.state[key] = value

    def get_ignore_patterns(self, profile_id: str) -> set[str]:
        with self.lock:
            raw = self.get_profile(profile_id).get("blacklist", []) or []
            return {normalize_domain(str(p)) for p in raw if str(p).strip()}

    def set_ignore_patterns(self, profile_id: str, patterns: set[str]) -> None:
        self.update_profile(profile_id, blacklist=sorted(patterns))

    def get_disabled_reasons(self, profile_id: str) -> list[str]:
        with self.lock:
            profile = self.get_profile(profile_id)
            custom = profile.get("disabled_reasons_custom")
            if custom is not None:
                return list(custom)
            return list(self.state.get("disabled_reasons", []))

    def set_disabled_reasons(self, profile_ids: list[str], reason_ids: list[str]) -> None:
        with self.lock:
            for profile_id in profile_ids:
                self.get_profile(profile_id)["disabled_reasons_custom"] = sorted(set(reason_ids))

    def clear_disabled_reasons_override(self, profile_ids: list[str]) -> None:
        with self.lock:
            for profile_id in profile_ids:
                self.get_profile(profile_id)["disabled_reasons_custom"] = None
