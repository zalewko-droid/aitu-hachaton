import asyncio
from datetime import datetime

from fastapi.testclient import TestClient

from app.api import create_api
from app.config import AppConfig
from app.services import ApplicationService
from app.storage import SQLiteStorage


class FakeBot:
    def __init__(self) -> None:
        self.messages: list[tuple[int, str]] = []

    async def send_message(self, chat_id: int, text: str) -> None:
        self.messages.append((chat_id, text))


def test_main_api_endpoints_work_with_shared_service_state(tmp_path) -> None:
    config = AppConfig(
        bot_token="test-token",
        admin_chat_id=123456789,
        api_host="0.0.0.0",
        api_port=8000,
        sqlite_path=str(tmp_path / "alerts.db"),
        demo_mode_default=False,
        heartbeat_stale_seconds=60,
        log_level="INFO",
    )
    storage = SQLiteStorage(config.sqlite_path)
    bot = FakeBot()
    service = ApplicationService(config=config, storage=storage, bot=bot)  # type: ignore[arg-type]
    asyncio.run(service.initialize())

    app = create_api(service)

    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        parser_heartbeat = client.post(
            "/heartbeat/parser",
            json={
                "service": "parser",
                "timestamp": datetime.now().replace(microsecond=0).isoformat(),
                "status": "online",
            },
        )
        assert parser_heartbeat.status_code == 200
        assert parser_heartbeat.json()["service"] == "parser"

        detector_heartbeat = client.post(
            "/heartbeat/detector",
            json={
                "service": "detector",
                "timestamp": datetime.now().replace(microsecond=0).isoformat(),
                "status": "online",
            },
        )
        assert detector_heartbeat.status_code == 200
        assert detector_heartbeat.json()["service"] == "detector"

        alert_payload = {
            "id": "evt_10001",
            "timestamp": "2026-04-24T14:21:03",
            "source": "nginx",
            "source_ip": "192.168.43.25",
            "event_type": "http_request",
            "raw_line": "GET /admin/login HTTP/1.1",
            "score": 0.91,
            "severity": "high",
            "category": "web",
            "explanation": "Repeated suspicious requests with denied responses.",
            "recommended_action": "investigate",
        }

        ingest = client.post("/ingest-alert", json=alert_payload)
        assert ingest.status_code == 200
        assert ingest.json()["status"] == "accepted"
        assert ingest.json()["stored"] is True

        duplicate = client.post("/ingest-alert", json=alert_payload)
        assert duplicate.status_code == 200
        assert duplicate.json()["status"] == "duplicate"
        assert duplicate.json()["stored"] is False

        recent = client.get("/recent-alerts?limit=5")
        assert recent.status_code == 200
        assert recent.json()["count"] == 1
        assert recent.json()["alerts"][0]["id"] == "evt_10001"

        health_after = client.get("/health")
        assert health_after.status_code == 200
        data = health_after.json()
        assert data["total_alerts"] == 1
        assert data["parser"]["status"] == "online"
        assert data["detector"]["status"] == "online"

    assert len(bot.messages) == 1

