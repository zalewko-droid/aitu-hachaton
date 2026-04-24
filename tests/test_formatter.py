from datetime import datetime

from app.formatter import format_alert_message, format_anomaly_details, format_recent_alerts, format_status, format_summary
from app.models import AlertIn, AlertSummary, ServiceName, ServiceState, ServiceStatus, Severity, StatusSnapshot


def build_alert() -> AlertIn:
    return AlertIn(
        id="evt_00124",
        timestamp=datetime(2026, 4, 24, 14, 21, 3),
        source="nginx",
        source_ip="192.168.43.25",
        event_type="http_request",
        raw_line='GET /admin/login HTTP/1.1" 403 "-" "curl/8.0"',
        score=0.91,
        severity=Severity.high,
        category="web",
        explanation="Repeated suspicious requests with SQL injection patterns and denied responses.",
        recommended_action="investigate",
    )


def test_format_alert_message_contains_core_fields() -> None:
    message = format_alert_message(build_alert())
    assert "ALERT: Suspicious Event Detected" in message
    assert "evt_00124" in message
    assert "HIGH" in message
    assert "0.91" in message


def test_format_summary_handles_empty_state() -> None:
    message = format_summary(AlertSummary(), demo_mode=False)
    assert "Total alerts:" in message
    assert "No source IPs recorded yet." in message


def test_format_recent_alerts_and_detail() -> None:
    recent = format_recent_alerts([build_alert()])
    detail = format_anomaly_details(build_alert())
    assert "Recent Alerts" in recent
    assert "evt_00124" in recent
    assert "Anomaly Detail" in detail
    assert "Raw log line" in detail


def test_format_status_includes_service_health() -> None:
    snapshot = StatusSnapshot(
        bot_status=ServiceState.online,
        api_status=ServiceState.online,
        parser=ServiceStatus(
            service=ServiceName.parser,
            status=ServiceState.stale,
            last_seen=datetime(2026, 4, 24, 14, 20, 0),
            age_seconds=63,
        ),
        detector=ServiceStatus(
            service=ServiceName.detector,
            status=ServiceState.online,
            last_seen=datetime(2026, 4, 24, 14, 21, 0),
            age_seconds=3,
        ),
        total_alerts=7,
        high_severity_alerts=4,
        last_alert_timestamp=datetime(2026, 4, 24, 14, 21, 3),
        demo_mode=True,
    )

    text = format_status(snapshot)
    assert "System Status" in text
    assert "STALE" in text
    assert "Demo mode" in text
