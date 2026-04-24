from datetime import datetime

import pytest

from app.models import AlertIn, Severity
from app.storage import SQLiteStorage


@pytest.mark.asyncio
async def test_storage_save_get_summary_and_heartbeats(tmp_path) -> None:
    storage = SQLiteStorage(str(tmp_path / "alerts.db"))
    await storage.initialize()

    first_alert = AlertIn(
        id="evt_00001",
        timestamp=datetime(2026, 4, 24, 14, 21, 3),
        source="nginx",
        source_ip="192.168.43.25",
        event_type="http_request",
        raw_line="GET /admin/login HTTP/1.1",
        score=0.91,
        severity=Severity.high,
        category="web",
        explanation="Repeated suspicious requests.",
        recommended_action="investigate",
    )
    second_alert = AlertIn(
        id="evt_00002",
        timestamp=datetime(2026, 4, 24, 14, 22, 3),
        source="auth-service",
        source_ip="10.10.0.21",
        event_type="failed_login",
        raw_line="POST /login 401 user=admin",
        score=0.81,
        severity=Severity.medium,
        category="auth",
        explanation="Repeated failed login attempts.",
        recommended_action="check account activity",
    )

    assert await storage.save_alert(first_alert) is True
    assert await storage.save_alert(first_alert) is False
    assert await storage.save_alert(second_alert) is True

    recent_alerts = await storage.get_recent_alerts(limit=5)
    assert len(recent_alerts) == 2
    assert recent_alerts[0].id == "evt_00002"

    fetched = await storage.get_alert_by_id("evt_00001")
    assert fetched is not None
    assert fetched.source == "nginx"

    summary = await storage.get_summary()
    assert summary.total_alerts == 2
    assert summary.high_severity_alerts == 1
    assert summary.by_severity["high"] == 1
    assert summary.by_category["web"] == 1
    assert summary.top_source_ips[0].count >= 1

    await storage.update_heartbeat("parser", datetime(2026, 4, 24, 14, 21, 3), "online")
    service_status = await storage.get_service_status(stale_seconds=10_000_000)
    assert service_status["parser"].status.value == "online"
