from __future__ import annotations

from html import escape
from typing import Sequence

from app.models import AlertIn, AlertSummary, ServiceState, ServiceStatus, StatusSnapshot
from app.utils import format_timestamp, truncate


def _enum_value(value: object) -> str:
    if hasattr(value, "value"):
        return str(getattr(value, "value"))
    return str(value)


def format_alert_message(alert: AlertIn) -> str:
    lines = [
        "<b>ALERT: Suspicious Event Detected</b>",
        "",
        f"<b>ID:</b> <code>{escape(alert.id)}</code>",
        f"<b>Time:</b> {escape(format_timestamp(alert.timestamp))}",
        f"<b>Source:</b> {escape(alert.source)}",
        f"<b>IP:</b> {escape(alert.source_ip or 'n/a')}",
        f"<b>Type:</b> {escape(alert.event_type)}",
        f"<b>Severity:</b> {escape(_enum_value(alert.severity).upper())}",
        f"<b>Category:</b> {escape(alert.category or 'uncategorized')}",
        f"<b>Score:</b> {alert.score:.2f}",
    ]

    if alert.explanation:
        lines.extend(["", "<b>Reason:</b>", escape(alert.explanation)])

    if alert.recommended_action:
        lines.extend(["", "<b>Recommended action:</b>", escape(alert.recommended_action)])

    return "\n".join(lines)


def format_recent_alerts(alerts: Sequence[AlertIn]) -> str:
    if not alerts:
        return "<b>Recent Alerts</b>\n\nNo alerts have been received yet."

    lines = ["<b>Recent Alerts</b>", ""]
    for alert in alerts:
        summary = truncate(alert.explanation or alert.raw_line or "No explanation provided", limit=54)
        lines.append(
            " | ".join(
                [
                    f"<code>{escape(alert.id)}</code>",
                    escape(format_timestamp(alert.timestamp)),
                    escape(_enum_value(alert.severity).upper()),
                    escape(alert.category or "uncategorized"),
                    escape(alert.source_ip or "n/a"),
                    escape(summary),
                ]
            )
        )
    return "\n".join(lines)


def format_summary(summary: AlertSummary, demo_mode: bool) -> str:
    severity_text = (
        ", ".join(f"{escape(name)}={count}" for name, count in summary.by_severity.items())
        if summary.by_severity
        else "none"
    )
    category_text = (
        ", ".join(f"{escape(name)}={count}" for name, count in summary.by_category.items())
        if summary.by_category
        else "none"
    )

    lines = [
        "<b>Alert Summary</b>",
        "",
        f"<b>Total alerts:</b> {summary.total_alerts}",
        f"<b>High severity:</b> {summary.high_severity_alerts}",
        f"<b>By severity:</b> {severity_text}",
        f"<b>By category:</b> {category_text}",
        f"<b>Latest activity window:</b> {escape(format_timestamp(summary.latest_window_start))} -> {escape(format_timestamp(summary.latest_window_end))}",
        f"<b>Demo mode:</b> {'ON' if demo_mode else 'OFF'}",
        "",
        "<b>Top suspicious source IPs:</b>",
    ]

    if summary.top_source_ips:
        for index, item in enumerate(summary.top_source_ips, start=1):
            lines.append(f"{index}. {escape(item.source_ip)} ({item.count})")
    else:
        lines.append("No source IPs recorded yet.")

    return "\n".join(lines)


def format_status(snapshot: StatusSnapshot) -> str:
    lines = [
        "<b>System Status</b>",
        "",
        f"<b>Bot:</b> {escape(_enum_value(snapshot.bot_status).upper())}",
        f"<b>Ingestion API:</b> {escape(_enum_value(snapshot.api_status).upper())}",
        f"<b>Parser:</b> {_render_service_status(snapshot.parser)}",
        f"<b>Detector:</b> {_render_service_status(snapshot.detector)}",
        f"<b>Total alerts received:</b> {snapshot.total_alerts}",
        f"<b>Total high severity alerts:</b> {snapshot.high_severity_alerts}",
        f"<b>Last alert timestamp:</b> {escape(format_timestamp(snapshot.last_alert_timestamp))}",
        f"<b>Demo mode:</b> {'ON' if snapshot.demo_mode else 'OFF'}",
    ]
    return "\n".join(lines)


def format_anomaly_details(alert: AlertIn | None) -> str:
    if alert is None:
        return "<b>Anomaly Lookup</b>\n\nNo alert was found for that ID."

    lines = [
        "<b>Anomaly Detail</b>",
        "",
        f"<b>ID:</b> <code>{escape(alert.id)}</code>",
        f"<b>Time:</b> {escape(format_timestamp(alert.timestamp))}",
        f"<b>Source:</b> {escape(alert.source)}",
        f"<b>IP:</b> {escape(alert.source_ip or 'n/a')}",
        f"<b>Type:</b> {escape(alert.event_type)}",
        f"<b>Severity:</b> {escape(_enum_value(alert.severity).upper())}",
        f"<b>Category:</b> {escape(alert.category or 'uncategorized')}",
        f"<b>Score:</b> {alert.score:.2f}",
        "",
        "<b>Explanation:</b>",
        escape(alert.explanation or "No explanation provided."),
        "",
        "<b>Recommended action:</b>",
        escape(alert.recommended_action or "No recommendation provided."),
        "",
        "<b>Raw log line:</b>",
        f"<code>{escape(alert.raw_line or 'n/a')}</code>",
    ]
    return "\n".join(lines)


def _render_service_status(service_status: ServiceStatus) -> str:
    state = _enum_value(service_status.status).upper()
    if service_status.status == ServiceState.unknown:
        return "UNKNOWN"

    details: list[str] = [state]
    if service_status.last_seen:
        details.append(f"last seen {format_timestamp(service_status.last_seen)}")
    if service_status.age_seconds is not None:
        details.append(f"{service_status.age_seconds}s ago")
    return " | ".join(details)
