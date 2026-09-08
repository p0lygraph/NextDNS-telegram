"""Application-wide constants."""

from __future__ import annotations

import re


APP_TITLE = "NextDNS Manager"
APP_STATE_FILE = "gui_state.json"
LEGACY_STATE_FILE = "state.json"
APP_TIMEOUT = 15
NEXTDNS_BASE_URL = "https://api.nextdns.io"
ALERT_EVENT_CACHE_TTL_SECONDS = 600
ALERT_EVENT_CACHE_MAX = 10000
HEADLESS_FRESH_START_SECONDS = 60

BLOCKED_STATUSES = frozenset({"blocked", "deny", "sinkhole", "refused"})
DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*")
MAX_LOG_ROWS_IN_MEMORY = 10000

DEFAULT_LOG_COLUMNS = [
    "timestamp",
    "profile",
    "device_id",
    "device_name",
    "domain",
    "query_type",
    "status",
    "reason",
    "ti_score",
    "ti_details",
]

ALL_LOG_COLUMNS = [
    "timestamp",
    "timestamp_raw",
    "profile",
    "profile_id",
    "device_id",
    "device_name",
    "ip",
    "domain",
    "query_type",
    "status",
    "reason",
    "reason_ids",
    "matched_name",
    "protocol",
    "ti_score",
    "ti_details",
]

TLD_COLUMNS = ["profile", "profile_id", "tld", "blocked"]
DENYLIST_COLUMNS = ["profile", "profile_id", "domain", "source"]


TELEGRAM_PAGE_SIZE = 5
TELEGRAM_LOG_PAGE_SIZE = 8
TELEGRAM_SESSION_TTL_SECONDS = 3600
TELEGRAM_MAX_MESSAGE_CHARS = 4096
TELEGRAM_API_CACHE_TTL_SECONDS = 30
