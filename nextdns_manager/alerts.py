"""Alert batching and message rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape as html_escape
from typing import Any

from .utils import format_time_range_qp, format_timestamp_qp


@dataclass
class AlertBatchQP:
    domain: str
    profile_id: str
    profile_name: str
    first_event_index: int
    first_timestamp: str
    last_timestamp: str
    count: int = 1
    devices: set[str] = field(default_factory=set)
    reasons: set[str] = field(default_factory=set)
    reason_ids: set[str] = field(default_factory=set)


def format_batch_message_qp(batch: AlertBatchQP, enrichment: str, context: dict[str, Any] | None = None) -> str:
    domain = batch.domain
    if any("threat" in rid or "malware" in rid for rid in batch.reason_ids):
        header = "☣️ Malicious Domain Blocked"
    elif any("blocklist" in rid for rid in batch.reason_ids):
        header = "🛡️ Blocklist Match"
    else:
        header = "⚠️ Domain Blocked"

    if batch.count > 1:
        header += f" (×{batch.count})"

    reason_text = ", ".join(sorted(batch.reasons))
    devices_list = sorted(batch.devices)

    if len(devices_list) == 1:
        devices_text = devices_list[0]
    elif len(devices_list) <= 3:
        devices_text = ", ".join(devices_list)
    else:
        devices_text = f"{', '.join(devices_list[:3])} (+{len(devices_list) - 3} more)"

    msg = f"<b>{header}</b>\n\n"
    msg += f"<b>Domain:</b> <code>{html_escape(domain)}</code>\n"
    msg += f"<b>Reason:</b> {html_escape(reason_text)}\n"
    msg += f"<b>Profile:</b> {html_escape(batch.profile_name)}\n"
    msg += f"<b>Device{'s' if len(devices_list) > 1 else ''}:</b> {html_escape(devices_text)}\n"
    if batch.count > 1:
        msg += f"<b>Period:</b> {format_time_range_qp(batch.first_timestamp, batch.last_timestamp)}\n"
    else:
        msg += f"<b>Time:</b> {format_timestamp_qp(batch.first_timestamp)}\n"
    if context and (context.get("before") or context.get("after")):
        ctx_text = f"<b>{context['header']}</b>\n"
        if context.get("before"):
            ctx_text += "\n".join([f"⬆️ {html_escape(str(d))}" for d in context["before"][-5:]]) + "\n"
        ctx_text += f"🎯 <b>{html_escape(domain)}</b> (BLOCKED)\n"
        if context.get("after"):
            ctx_text += "\n".join([f"⬇️ {html_escape(str(d))}" for d in context["after"][:5]])
        msg += f"\n<blockquote expandable>{ctx_text}</blockquote>"
    msg += enrichment
    return msg
