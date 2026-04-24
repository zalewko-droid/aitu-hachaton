from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import AlertIn, Severity
from app.utils import parse_datetime


class RawLogLineIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    timestamp: datetime | None = None
    source: str | None = None
    source_ip: str | None = None
    raw_line: str = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _normalize_timestamp(cls, value: datetime | str | None) -> datetime | None:
        return parse_datetime(value)

    @field_validator("id", "source", "source_ip", "raw_line", mode="before")
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        if value is None or not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None

    @field_validator("raw_line")
    @classmethod
    def _ensure_raw_line(cls, value: str | None) -> str:
        if not value:
            raise ValueError("raw_line cannot be blank")
        return value


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    timestamp: datetime
    source: str
    source_ip: str | None = None
    event_type: str
    raw_line: str
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_alert(self, score: float, severity: Severity, category: str, explanation: str, recommended_action: str) -> AlertIn:
        return AlertIn(
            id=self.id,
            timestamp=self.timestamp,
            source=self.source,
            source_ip=self.source_ip,
            event_type=self.event_type,
            raw_line=self.raw_line,
            score=score,
            severity=severity,
            category=category,
            explanation=explanation,
            recommended_action=recommended_action,
        )


class AIAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    category: str | None = None
    explanation: str | None = None
    recommended_action: str | None = None

    @field_validator("category", "explanation", "recommended_action", mode="before")
    @classmethod
    def _strip_optional_strings(cls, value: object) -> object:
        if value is None or not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None


class ParserIngestResponse(BaseModel):
    status: str
    alert_id: str
    normalized_event: NormalizedEvent
    analysis_source: str
    analysis: AIAnalysisResult | None = None
    ai_forwarded: bool
    alert_forwarded: bool
    errors: list[str] = Field(default_factory=list)


class ParserHealthResponse(BaseModel):
    status: str
    parser_host: str
    parser_port: int
    main_api_url: str
    ai_service_url: str
    heartbeat_interval_seconds: int
    fallback_analysis_enabled: bool
    total_received: int
    total_ai_success: int
    total_fallback_analysis: int
    total_alerts_forwarded: int
    recent_events_count: int
    last_received_at: datetime | None = None
    last_processed_at: datetime | None = None
    last_alert_id: str | None = None
    last_error: str | None = None
