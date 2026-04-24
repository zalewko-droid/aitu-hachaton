from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from app.models import AlertIn, HeartbeatPayload, IngestResult
from app.services import ApplicationService
from app.utils import api_key_matches


def create_api(service: ApplicationService) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await service.mark_api_online(True)
        yield
        await service.mark_api_online(False)

    app = FastAPI(
        title="AI Log Anomaly Detector Bot API",
        version="1.0.0",
        lifespan=lifespan,
    )

    async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
        if api_key_matches(service.config.shared_api_key, x_api_key):
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )

    @app.post("/ingest-alert", response_model=IngestResult)
    async def ingest_alert(alert: AlertIn, _: None = Depends(require_api_key)) -> IngestResult:
        return await service.ingest_alert(alert)

    @app.post("/heartbeat/parser")
    async def parser_heartbeat(payload: HeartbeatPayload, _: None = Depends(require_api_key)) -> dict[str, object]:
        if payload.service.value != "parser":
            raise HTTPException(status_code=400, detail="Payload service must be 'parser' for this endpoint.")
        await service.update_heartbeat(payload)
        return {"status": "ok", "service": "parser", "timestamp": payload.timestamp}

    @app.post("/heartbeat/detector")
    async def detector_heartbeat(payload: HeartbeatPayload, _: None = Depends(require_api_key)) -> dict[str, object]:
        if payload.service.value != "detector":
            raise HTTPException(status_code=400, detail="Payload service must be 'detector' for this endpoint.")
        await service.update_heartbeat(payload)
        return {"status": "ok", "service": "detector", "timestamp": payload.timestamp}

    @app.get("/health")
    async def health() -> dict[str, object]:
        return await service.get_health_payload()

    @app.get("/recent-alerts")
    async def recent_alerts(limit: int = Query(default=10, ge=1, le=100)) -> dict[str, object]:
        alerts = await service.get_recent_alerts(limit=limit)
        return {
            "count": len(alerts),
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
        }

    return app
