"""NextDNS REST client."""

from __future__ import annotations

import time
from typing import Any, Callable
from urllib.parse import quote

from .constants import APP_TIMEOUT, NEXTDNS_BASE_URL
from .deps import requests


class NextDNSService:
    def __init__(self, api_key_getter: Callable[[], str], on_rate_limit: Callable[[str, int, int], None] | None = None):
        self.api_key_getter = api_key_getter
        self.on_rate_limit = on_rate_limit

    def _headers(self) -> dict[str, str]:
        key = self.api_key_getter().strip()
        return {"X-Api-Key": key} if key else {}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{NEXTDNS_BASE_URL}{path}"
        headers = kwargs.pop("headers", {})
        all_headers = self._headers()
        all_headers.update(headers)
        last_error: Exception | None = None

        for attempt in range(3):
            try:
                resp = requests.request(
                    method,
                    url,
                    headers=all_headers,
                    timeout=APP_TIMEOUT,
                    **kwargs,
                )
                if resp.status_code == 429 and attempt < 2:
                    retry_after_raw = str(resp.headers.get("Retry-After", "")).strip()
                    retry_after = int(retry_after_raw) if retry_after_raw.isdigit() else (3 + attempt * 3)
                    if self.on_rate_limit:
                        self.on_rate_limit(path, retry_after, attempt + 1)
                    time.sleep(max(1, retry_after))
                    continue
                return resp
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(1 + attempt)

        raise RuntimeError(f"Request failed: {last_error}")

    def get_profiles(self) -> list[dict[str, Any]]:
        resp = self._request("GET", "/profiles")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch profiles ({resp.status_code})")
        return resp.json().get("data", [])

    def get_logs(self, profile_id: str, limit: int = 500) -> list[dict[str, Any]]:
        params = {"sort": "desc", "limit": max(1, min(limit, 1000))}
        resp = self._request("GET", f"/profiles/{profile_id}/logs", params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch logs for {profile_id} ({resp.status_code})")
        return resp.json().get("data", [])

    def get_logs_since(self, profile_id: str, from_ts: int, limit: int = 1000) -> list[dict[str, Any]]:
        params = {"sort": "asc", "limit": max(1, min(limit, 1000)), "from": int(from_ts)}
        resp = self._request("GET", f"/profiles/{profile_id}/logs", params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch logs for {profile_id} ({resp.status_code})")
        return resp.json().get("data", [])

    def get_logs_cursor(self, profile_id: str, cursor: str | None = None, from_ts: int | None = None) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, Any] = {"sort": "asc", "limit": 1000}
        if cursor:
            params["cursor"] = cursor
        elif from_ts is not None:
            params["from"] = max(0, int(from_ts))
        resp = self._request("GET", f"/profiles/{profile_id}/logs", params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch cursor logs for {profile_id} ({resp.status_code})")
        payload = resp.json()
        logs = payload.get("data", [])
        new_cursor = payload.get("meta", {}).get("pagination", {}).get("cursor")
        return logs, new_cursor

    def get_analytics_reasons(self, profile_id: str) -> list[dict[str, Any]]:
        resp = self._request("GET", f"/profiles/{profile_id}/analytics/reasons")
        if resp.status_code != 200:
            return []
        return resp.json().get("data", [])

    def get_denylist(self, profile_id: str) -> list[str]:
        resp = self._request("GET", f"/profiles/{profile_id}/denylist")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch denylist for {profile_id} ({resp.status_code})")
        data = resp.json().get("data", [])
        return sorted({(item.get("id") or "").strip().lower() for item in data if item.get("id")})

    def add_deny_domain(self, profile_id: str, domain: str) -> tuple[bool, str]:
        payload = {"id": domain.strip().lower()}
        resp = self._request("POST", f"/profiles/{profile_id}/denylist", json=payload)
        if resp.status_code in (200, 201):
            return True, "Domain blocked"
        if resp.status_code == 409:
            return True, "Domain already blocked"
        return False, f"Failed to block ({resp.status_code})"

    def remove_deny_domain(self, profile_id: str, domain: str) -> tuple[bool, str]:
        encoded = quote(domain.strip().lower(), safe="")
        resp = self._request("DELETE", f"/profiles/{profile_id}/denylist/{encoded}")
        if resp.status_code in (200, 204):
            return True, "Domain unblocked"
        if resp.status_code == 404:
            return True, "Domain was not blocked"
        return False, f"Failed to unblock ({resp.status_code})"

    def get_security_tlds(self, profile_id: str) -> list[str]:
        resp = self._request("GET", f"/profiles/{profile_id}/security")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch TLDs for {profile_id} ({resp.status_code})")
        data = resp.json().get("data", {})
        tlds = data.get("tlds", [])
        return sorted({(item.get("id") or "").strip().lower() for item in tlds if item.get("id")})

    def patch_security_tlds(self, profile_id: str, tlds: list[str]) -> tuple[bool, str]:
        payload = {"tlds": [{"id": tld.strip().lower()} for tld in sorted(set(tlds)) if tld.strip()]}
        resp = self._request("PATCH", f"/profiles/{profile_id}/security", json=payload)
        if resp.status_code in (200, 204):
            return True, "TLD list updated"
        return False, f"Failed to update TLD list ({resp.status_code})"
