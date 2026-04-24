from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime

from app.models import AlertIn
from app.utils import is_api_key_configured
from parser_service.config import ParserConfig
from parser_service.forwarder import ParserHttpClient
from parser_service.models import AIAnalysisResult, ParserHealthResponse, ParserIngestResponse, RawLogLineIn
from parser_service.parsers import (
    default_category_for_event,
    default_explanation_for_event,
    default_recommended_action_for_event,
    derive_fallback_analysis,
    normalize_log_line,
)


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ParserRuntimeStats:
    total_received: int = 0
    total_ai_success: int = 0
    total_fallback_analysis: int = 0
    total_alerts_forwarded: int = 0
    last_received_at: datetime | None = None
    last_processed_at: datetime | None = None
    last_alert_id: str | None = None
    last_ai_error: str | None = None
    last_alert_delivery_error: str | None = None
    last_heartbeat_error: str | None = None
    last_error: str | None = None


class ParserService:
    def __init__(self, config: ParserConfig, client: ParserHttpClient) -> None:
        self.config = config
        self.client = client
        self.stats = ParserRuntimeStats()
        self._recent_events = deque(maxlen=config.recent_events_limit)
        self._stop_event = asyncio.Event()
        self._heartbeat_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        await self.client.open()
        await self._safe_send_heartbeat(status="online")
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="parser-heartbeat")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            await asyncio.gather(self._heartbeat_task, return_exceptions=True)
        await self._safe_send_heartbeat(status="offline")
        await self.client.close()

    async def process_log_line(self, payload: RawLogLineIn) -> ParserIngestResponse:
        self.stats.total_received += 1
        self.stats.last_received_at = datetime.now().replace(microsecond=0)

        payload = self._enrich_payload(payload)
        normalized_event = normalize_log_line(payload)
        self._recent_events.appendleft(normalized_event)
        logger.info(
            "Accepted raw log %s from source=%s ip=%s event_type=%s",
            normalized_event.id,
            normalized_event.source,
            normalized_event.source_ip or "unknown",
            normalized_event.event_type,
        )

        errors: list[str] = []
        analysis_source = "ai"
        ai_forwarded = False
        self.stats.last_ai_error = None
        self.stats.last_alert_delivery_error = None

        analysis, ai_error = await self.client.analyze_event(self.config.ai_service_url, normalized_event)
        if analysis is not None:
            ai_forwarded = True
            self.stats.total_ai_success += 1
            logger.info(
                "AI analysis succeeded for %s with severity=%s score=%.2f",
                normalized_event.id,
                analysis.severity.value,
                analysis.score,
            )
        elif self.config.fallback_analysis_enabled:
            analysis = derive_fallback_analysis(normalized_event)
            analysis_source = "fallback"
            self.stats.total_fallback_analysis += 1
            if ai_error is not None:
                self.stats.last_ai_error = ai_error
                errors.append(ai_error)
                logger.warning("AI service unavailable, using parser fallback analysis: %s", ai_error)
        else:
            analysis_source = "none"
            if ai_error is not None:
                self.stats.last_ai_error = ai_error
                errors.append(ai_error)
                logger.warning("AI service unavailable and fallback disabled: %s", ai_error)

            self.stats.last_error = errors[-1] if errors else None
            self.stats.last_processed_at = datetime.now().replace(microsecond=0)
            return ParserIngestResponse(
                status="normalized_only",
                alert_id=normalized_event.id,
                normalized_event=normalized_event,
                analysis_source=analysis_source,
                analysis=None,
                ai_forwarded=ai_forwarded,
                alert_forwarded=False,
                errors=errors,
            )

        assert analysis is not None

        final_alert = build_final_alert(normalized_event, analysis)
        alert_forwarded, alert_error = await self.client.send_alert(
            self.config.main_api_url,
            final_alert.model_dump(mode="json"),
        )
        if alert_forwarded:
            self.stats.total_alerts_forwarded += 1
            self.stats.last_alert_id = final_alert.id
            logger.info("Forwarded final alert %s to main API", final_alert.id)
        elif alert_error is not None:
            self.stats.last_alert_delivery_error = alert_error
            errors.append(alert_error)
            logger.warning("Failed to forward final alert to main API: %s", alert_error)

        self.stats.last_error = errors[-1] if errors else None
        self.stats.last_processed_at = datetime.now().replace(microsecond=0)

        if analysis_source == "fallback":
            status = "processed_with_fallback_analysis" if alert_forwarded else "fallback_analysis_ready_but_alert_delivery_failed"
        else:
            status = "processed" if alert_forwarded else "analysis_ready_but_alert_delivery_failed"

        return ParserIngestResponse(
            status=status,
            alert_id=final_alert.id,
            normalized_event=normalized_event,
            analysis_source=analysis_source,
            analysis=analysis,
            ai_forwarded=ai_forwarded,
            alert_forwarded=alert_forwarded,
            errors=errors,
        )

    def get_recent_events(self, limit: int = 20) -> list[dict[str, object]]:
        events = list(self._recent_events)[:limit]
        return [event.model_dump(mode="json") for event in events]

    def get_health(self) -> ParserHealthResponse:
        return ParserHealthResponse(
            status="ok",
            parser_host=self.config.parser_host,
            parser_port=self.config.parser_port,
            main_api_url=self.config.main_api_url,
            ai_service_url=self.config.ai_service_url,
            network_server_name=self.config.network_server_name,
            heartbeat_interval_seconds=self.config.heartbeat_interval_seconds,
            fallback_analysis_enabled=self.config.fallback_analysis_enabled,
            api_key_enabled=is_api_key_configured(self.config.shared_api_key),
            total_received=self.stats.total_received,
            total_ai_success=self.stats.total_ai_success,
            total_fallback_analysis=self.stats.total_fallback_analysis,
            total_alerts_forwarded=self.stats.total_alerts_forwarded,
            recent_events_count=len(self._recent_events),
            last_received_at=self.stats.last_received_at,
            last_processed_at=self.stats.last_processed_at,
            last_alert_id=self.stats.last_alert_id,
            last_ai_error=self.stats.last_ai_error,
            last_alert_delivery_error=self.stats.last_alert_delivery_error,
            last_heartbeat_error=self.stats.last_heartbeat_error,
            last_error=self.stats.last_error,
        )

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self.config.heartbeat_interval_seconds)
                except TimeoutError:
                    await self._safe_send_heartbeat(status="online")
        except asyncio.CancelledError:
            raise

    async def _safe_send_heartbeat(self, status: str) -> None:
        ok, error = await self.client.send_parser_heartbeat(self.config.main_api_url, status=status)
        if not ok and error is not None:
            self.stats.last_heartbeat_error = error
            self.stats.last_error = error
            logger.warning("Parser heartbeat failed: %s", error)
        else:
            self.stats.last_heartbeat_error = None

    def _enrich_payload(self, payload: RawLogLineIn) -> RawLogLineIn:
        metadata = dict(payload.metadata)
        metadata.setdefault("hostname", self.config.network_server_name)
        return payload.model_copy(update={"metadata": metadata})


def build_final_alert(normalized_event, analysis: AIAnalysisResult) -> AlertIn:
    category = analysis.category or default_category_for_event(normalized_event.event_type)
    explanation = analysis.explanation or default_explanation_for_event(normalized_event)
    recommended_action = analysis.recommended_action or default_recommended_action_for_event(normalized_event)
    return normalized_event.to_alert(
        score=analysis.score,
        severity=analysis.severity,
        category=category,
        explanation=explanation,
        recommended_action=recommended_action,
    )
