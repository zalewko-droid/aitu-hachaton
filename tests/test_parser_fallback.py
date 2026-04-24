import pytest

from parser_service.config import ParserConfig
from parser_service.models import NormalizedEvent, RawLogLineIn
from parser_service.service import ParserService


class UnavailableAIClient:
    def __init__(self) -> None:
        self.sent_alerts: list[dict[str, object]] = []

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def analyze_event(self, ai_service_url: str, event: NormalizedEvent):
        return None, "Request to AI failed"

    async def send_alert(self, main_api_url: str, payload: dict[str, object]):
        self.sent_alerts.append(payload)
        return True, None

    async def send_parser_heartbeat(self, main_api_url: str, status: str = "online"):
        return True, None


@pytest.mark.asyncio
async def test_parser_uses_fallback_analysis_when_ai_is_unavailable() -> None:
    config = ParserConfig(
        parser_host="0.0.0.0",
        parser_port=9001,
        main_api_url="http://127.0.0.1:8000",
        ai_service_url="http://192.168.1.50:9000/analyze",
        network_server_name="victim-laptop",
        heartbeat_interval_seconds=12,
        request_timeout_seconds=5.0,
        fallback_analysis_enabled=True,
        recent_events_limit=100,
        log_level="INFO",
    )
    client = UnavailableAIClient()
    service = ParserService(config=config, client=client)  # type: ignore[arg-type]

    await service.start()
    result = await service.process_log_line(
        RawLogLineIn(
            source="nginx",
            raw_line='192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
        )
    )
    await service.stop()

    assert result.analysis_source == "fallback"
    assert result.alert_forwarded is True
    assert result.analysis is not None
    assert result.analysis.recommended_action in {
        "investigate",
        "monitor",
        "review_access",
        "reset_credentials",
        "check_system",
        "escalate",
    }
    assert service.get_health().last_ai_error == "Request to AI failed"
    assert len(client.sent_alerts) == 1
