from fastapi.testclient import TestClient

from parser_service.api import create_parser_api
from parser_service.config import ParserConfig
from parser_service.models import AIAnalysisResult, NormalizedEvent
from parser_service.service import ParserService


class FakeParserClient:
    def __init__(self) -> None:
        self.sent_alerts: list[dict[str, object]] = []
        self.heartbeats: list[str] = []
        self.opened = False
        self.closed = False

    async def open(self) -> None:
        self.opened = True

    async def close(self) -> None:
        self.closed = True

    async def analyze_event(self, ai_service_url: str, event: NormalizedEvent):
        assert ai_service_url == "http://192.168.1.50:9000/analyze"
        return (
            AIAnalysisResult(
                score=0.91,
                severity="high",
                category="web",
                explanation="AI said suspicious admin probing.",
                recommended_action="investigate",
            ),
            None,
        )

    async def send_alert(self, main_api_url: str, payload: dict[str, object]):
        assert main_api_url == "http://127.0.0.1:8000"
        self.sent_alerts.append(payload)
        return True, None

    async def send_parser_heartbeat(self, main_api_url: str, status: str = "online"):
        assert main_api_url == "http://127.0.0.1:8000"
        self.heartbeats.append(status)
        return True, None


def test_parser_api_endpoints_work_and_use_recent_events() -> None:
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
    client_stub = FakeParserClient()
    service = ParserService(config=config, client=client_stub)  # type: ignore[arg-type]
    app = create_parser_api(service)

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        assert health.json()["network_server_name"] == "victim-laptop"
        assert health.json()["api_key_enabled"] is False

        ingest = client.post(
            "/ingest-log-line",
            json={
                "source": "nginx",
                "raw_line": '192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
            },
        )
        assert ingest.status_code == 200
        assert ingest.json()["status"] == "processed"
        assert ingest.json()["analysis_source"] == "ai"
        assert ingest.json()["normalized_event"]["metadata"]["hostname"] == "victim-laptop"

        recent = client.get("/recent-events?limit=5")
        assert recent.status_code == 200
        assert recent.json()["count"] == 1
        assert recent.json()["events"][0]["source_ip"] == "192.168.43.25"

    assert client_stub.opened is True
    assert client_stub.closed is True
    assert len(client_stub.sent_alerts) == 1
    assert len(client_stub.heartbeats) >= 2


def test_parser_api_optional_api_key_protection() -> None:
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
        shared_api_key="team-secret",
        log_level="INFO",
    )
    client_stub = FakeParserClient()
    service = ParserService(config=config, client=client_stub)  # type: ignore[arg-type]
    app = create_parser_api(service)

    with TestClient(app) as client:
        blocked = client.post(
            "/ingest-log-line",
            json={
                "source": "nginx",
                "raw_line": '192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
            },
        )
        assert blocked.status_code == 401

        allowed = client.post(
            "/ingest-log-line",
            headers={"X-API-Key": "team-secret"},
            json={
                "source": "nginx",
                "raw_line": '192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
            },
        )
        assert allowed.status_code == 200
        assert allowed.json()["status"] == "processed"
