"""URLHaus and URLScan lookups."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .constants import APP_TIMEOUT
from .deps import requests


class ThreatIntelService:
    def __init__(self, urlhaus_getter: Callable[[], str], urlscan_getter: Callable[[], str], cache_ttl_getter: Callable[[], int]):
        self.urlhaus_getter = urlhaus_getter
        self.urlscan_getter = urlscan_getter
        self.cache_ttl_getter = cache_ttl_getter
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.lock = threading.Lock()

    def _get_cached(self, domain: str) -> dict[str, Any] | None:
        with self.lock:
            item = self.cache.get(domain)
            if not item:
                return None
            ts, value = item
            if time.time() - ts > max(30, self.cache_ttl_getter()):
                self.cache.pop(domain, None)
                return None
            return value

    def _set_cached(self, domain: str, value: dict[str, Any]) -> None:
        with self.lock:
            self.cache[domain] = (time.time(), value)

    def score_domain(self, domain: str) -> dict[str, Any]:
        domain = domain.strip().lower()
        cached = self._get_cached(domain)
        if cached is not None:
            return cached

        score = 0
        details: list[str] = []

        urlhaus_key = self.urlhaus_getter().strip()
        if urlhaus_key:
            try:
                resp = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    headers={"Auth-Key": urlhaus_key},
                    data={"host": domain},
                    timeout=APP_TIMEOUT,
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    if payload.get("query_status") == "ok":
                        score += 50
                        details.append("URLHaus listed")
                elif resp.status_code == 429:
                    details.append("URLHaus rate-limited")
            except requests.RequestException:
                details.append("URLHaus unavailable")

        urlscan_key = self.urlscan_getter().strip()
        if urlscan_key:
            try:
                resp = requests.get(
                    "https://urlscan.io/api/v1/search/",
                    headers={"API-Key": urlscan_key},
                    params={"q": f"domain:{domain}", "size": 1},
                    timeout=APP_TIMEOUT,
                )
                if resp.status_code == 200:
                    payload = resp.json()
                    results = payload.get("results", [])
                    if results:
                        verdicts = (results[0].get("verdicts") or {}).get("urlscan", {})
                        if verdicts.get("malicious"):
                            score += 50
                            details.append(f"URLScan malicious score={verdicts.get('score', 0)}")
                        else:
                            details.append(f"URLScan clean score={verdicts.get('score', 0)}")
                elif resp.status_code == 429:
                    details.append("URLScan rate-limited")
            except requests.RequestException:
                details.append("URLScan unavailable")

        result = {
            "score": min(score, 100),
            "label": "high" if score >= 80 else "medium" if score >= 40 else "low" if score > 0 else "none",
            "details": "; ".join(details) if details else "No TI data",
        }
        self._set_cached(domain, result)
        return result


def queryparser_enrichment_sync(domain: str, urlhaus_key: str, urlscan_key: str) -> str:
    spamhaus_map = {
        "spammer_domain": "known spammer domain",
        "phishing_domain": "known phishing domain",
        "botnet_cc_domain": "known botnet C&C domain",
        "abused_legit_spam": "known compromised website used for spammer hosting",
        "abused_legit_malware": "known compromised website used for malware distribution",
        "abused_legit_phishing": "known compromised website used for phishing hosting",
        "abused_legit_botnetcc": "known compromised website used for botnet C&C hosting",
        "abused_redirector": "known abused redirector or URL shortener",
    }

    urlhaus_result = "<b>URLHaus:</b> Error"
    urlscan_result = "<b>URLScan:</b> Error"

    if urlhaus_key:
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers={"Auth-Key": urlhaus_key},
                data={"host": domain},
                timeout=APP_TIMEOUT,
            )
            if resp.status_code == 200:
                payload = resp.json()
                if payload.get("query_status") == "ok":
                    blacklists = payload.get("blacklists", {})
                    surbl = blacklists.get("surbl", "not listed")
                    spamhaus = blacklists.get("spamhaus_dbl", "not listed")
                    if spamhaus != "not listed":
                        desc = spamhaus_map.get(spamhaus, spamhaus)
                        urlhaus_result = f"<b>URLHaus:</b> ⚠️ URL is a {desc}"
                    elif surbl != "not listed":
                        urlhaus_result = "<b>URLHaus:</b> ⚠️ URL is listed on SURBL"
                    else:
                        urlhaus_result = "<b>URLHaus:</b> No threats found"
                else:
                    urlhaus_result = "<b>URLHaus:</b> No threats found"
            elif resp.status_code == 429:
                urlhaus_result = "<b>URLHaus:</b> Rate limit exceeded"
            else:
                urlhaus_result = f"<b>URLHaus:</b> Check failed (Code: {resp.status_code})"
        except (requests.RequestException, ValueError, KeyError, TypeError):
            urlhaus_result = "<b>URLHaus:</b> Error"

    if urlscan_key:
        try:
            resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                headers={"API-Key": urlscan_key},
                params={"q": f"page.domain:{domain}"},
                timeout=APP_TIMEOUT,
            )
            if resp.status_code == 200:
                payload = resp.json()
                results = payload.get("results", [])
                if not results:
                    urlscan_result = "<b>URLScan:</b> No scans found"
                else:
                    verdicts = (results[0].get("verdicts") or {}).get("urlscan", {})
                    malicious = verdicts.get("malicious", False)
                    score = verdicts.get("score", 0)
                    if malicious:
                        urlscan_result = f"<b>URLScan:</b> ⚠️ Malicious (score: {score})"
                    else:
                        urlscan_result = f"<b>URLScan:</b> Clean (score: {score})"
            elif resp.status_code == 429:
                urlscan_result = "<b>URLScan:</b> Rate limit exceeded"
            else:
                urlscan_result = "<b>URLScan:</b> Check failed"
        except (requests.RequestException, ValueError, KeyError, TypeError):
            urlscan_result = "<b>URLScan:</b> Error"

    urlhaus_has_threat = "⚠️" in urlhaus_result
    urlscan_has_threat = "⚠️" in urlscan_result
    if urlhaus_has_threat and urlscan_has_threat:
        return f"\n{urlhaus_result}\n{urlscan_result}"
    if urlhaus_has_threat:
        return f"\n{urlhaus_result}"
    if urlscan_has_threat:
        return f"\n{urlscan_result}"
    return "\n<b>Threat Intel:</b> Domain not found in connected threat databases"
