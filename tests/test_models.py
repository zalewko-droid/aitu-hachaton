from datetime import datetime

import pytest
from pydantic import ValidationError

from app.models import AlertIn, HeartbeatPayload, Severity


def test_alert_model_normalizes_strings_and_timestamp() -> None:
    alert = AlertIn(
        id="  evt_00124  ",
        timestamp="2026-04-24T14:21:03",
        source=" nginx ",
        source_ip=" 192.168.43.25 ",
        event_type=" http_request ",
        raw_line=" GET /admin/login HTTP/1.1 ",
        score=0.91,
        severity="high",
        category=" web ",
        explanation=" suspicious payload ",
        recommended_action=" investigate ",
    )

    assert alert.id == "evt_00124"
    assert alert.timestamp == datetime(2026, 4, 24, 14, 21, 3)
    assert alert.source == "nginx"
    assert alert.source_ip == "192.168.43.25"
    assert alert.event_type == "http_request"
    assert alert.severity == Severity.high


def test_alert_model_rejects_invalid_score() -> None:
    with pytest.raises(ValidationError):
        AlertIn(
            id="evt_00124",
            timestamp="2026-04-24T14:21:03",
            source="nginx",
            event_type="http_request",
            score=1.5,
            severity="high",
        )


def test_heartbeat_payload_accepts_online_status() -> None:
    heartbeat = HeartbeatPayload(
        service="parser",
        timestamp="2026-04-24T14:21:03",
        status="online",
    )

    assert heartbeat.service.value == "parser"
    assert heartbeat.timestamp == datetime(2026, 4, 24, 14, 21, 3)
    assert heartbeat.status == "online"
