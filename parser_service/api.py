from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Query

from parser_service.models import ParserHealthResponse, ParserIngestResponse, RawLogLineIn
from parser_service.service import ParserService


def create_parser_api(service: ParserService) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await service.start()
        yield
        await service.stop()

    app = FastAPI(
        title="Log Parser Service",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.post("/ingest-log-line", response_model=ParserIngestResponse)
    async def ingest_log_line(payload: RawLogLineIn) -> ParserIngestResponse:
        return await service.process_log_line(payload)

    @app.get("/health", response_model=ParserHealthResponse)
    async def health() -> ParserHealthResponse:
        return service.get_health()

    @app.get("/recent-events")
    async def recent_events(limit: int = Query(default=10, ge=1, le=100)) -> dict[str, object]:
        events = service.get_recent_events(limit=limit)
        return {"count": len(events), "events": events}

    return app
