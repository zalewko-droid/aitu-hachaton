import asyncio

import pytest
from aiohttp import web

from parser_service.config import ParserConfig
from parser_service.forwarder import ParserHttpClient
from parser_service.models import RawLogLineIn
from parser_service.service import ParserService


@pytest.mark.asyncio
async def test_parser_service_forwards_to_ai_and_main_api() -> None:
    state = {
        "alerts": [],
        "heartbeats": [],
        "analyze_calls": 0,
    }

    async def analyze(request: web.Request) -> web.Response:
        payload = await request.json()
        assert payload["event_type"] == "admin_access"
        state["analyze_calls"] += 1
        return web.json_response(
            {
                "score": 0.91,
                "severity": "high",
                "category": "web",
                "explanation": "AI said suspicious admin probing.",
                "recommended_action": "investigate",
            }
        )

    async def ingest_alert(request: web.Request) -> web.Response:
        state["alerts"].append(await request.json())
        return web.json_response({"status": "accepted"})

    async def heartbeat_parser(request: web.Request) -> web.Response:
        state["heartbeats"].append(await request.json())
        return web.json_response({"status": "ok"})

    ai_app = web.Application()
    ai_app.router.add_post("/analyze", analyze)
    ai_runner = web.AppRunner(ai_app)
    await ai_runner.setup()
    ai_site = web.TCPSite(ai_runner, "127.0.0.1", 19000)
    await ai_site.start()

    main_app = web.Application()
    main_app.router.add_post("/ingest-alert", ingest_alert)
    main_app.router.add_post("/heartbeat/parser", heartbeat_parser)
    main_runner = web.AppRunner(main_app)
    await main_runner.setup()
    main_site = web.TCPSite(main_runner, "127.0.0.1", 18000)
    await main_site.start()

    config = ParserConfig(
        parser_host="127.0.0.1",
        parser_port=9001,
        main_api_url="http://127.0.0.1:18000",
        ai_service_url="http://127.0.0.1:19000/analyze",
        network_server_name="victim-laptop",
        heartbeat_interval_seconds=60,
        request_timeout_seconds=5.0,
        fallback_analysis_enabled=True,
        recent_events_limit=100,
        log_level="INFO",
    )

    client = ParserHttpClient(timeout_seconds=5.0)
    service = ParserService(config=config, client=client)

    try:
        await service.start()
        result = await service.process_log_line(
            RawLogLineIn(
                source="nginx",
                raw_line='192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
            )
        )
        await asyncio.sleep(0.05)
        await service.stop()
    finally:
        await ai_runner.cleanup()
        await main_runner.cleanup()

    assert result.status == "processed"
    assert result.analysis_source == "ai"
    assert result.alert_forwarded is True
    assert state["analyze_calls"] == 1
    assert len(state["alerts"]) == 1
    assert len(state["heartbeats"]) >= 1
    assert state["alerts"][0]["severity"] == "high"
    assert state["alerts"][0]["source_ip"] == "192.168.43.25"
    assert state["alerts"][0]["category"] == "web"
