from __future__ import annotations

from collections.abc import Iterable
from collections import deque
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import AlertIn, Severity
from app.utils import extract_json_like_mapping, parse_datetime


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

    @classmethod
    def from_ai_payload(cls, payload: object) -> "AIAnalysisResult":
        normalized_payload = _extract_ai_payload(payload)
        if normalized_payload is None:
            raise ValueError("AI response did not contain a usable analysis payload.")
        return cls.model_validate(normalized_payload)

    @field_validator("score", mode="before")
    @classmethod
    def _normalize_score(cls, value: object) -> float:
        if value is None:
            raise ValueError("score is required")
        if isinstance(value, str):
            cleaned = value.strip().replace(",", ".")
            if cleaned.endswith("%"):
                cleaned = cleaned[:-1].strip()
                numeric = float(cleaned) / 100.0
            else:
                numeric = float(cleaned)
        else:
            numeric = float(value)
        if numeric > 1.0 and numeric <= 100.0:
            numeric /= 100.0
        return max(0.0, min(numeric, 1.0))

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, value: object) -> str:
        if isinstance(value, Severity):
            return value.value
        cleaned = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
        mapping = {
            "info": "low",
            "informational": "low",
            "notice": "low",
            "low": "low",
            "minor": "low",
            "medium": "medium",
            "med": "medium",
            "moderate": "medium",
            "warning": "medium",
            "high": "high",
            "major": "high",
            "elevated": "high",
            "critical": "critical",
            "crit": "critical",
            "severe": "critical",
            "urgent": "critical",
        }
        return mapping.get(cleaned, "medium")

    @field_validator("category", mode="before")
    @classmethod
    def _normalize_category(cls, value: object) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        if not cleaned:
            return None
        mapping = {
            "web": "web",
            "http": "web",
            "http_request": "web",
            "application": "web",
            "auth": "auth",
            "authentication": "auth",
            "identity": "auth",
            "access": "access",
            "authorization": "access",
            "permission": "access",
            "system": "system",
            "host": "system",
            "os": "system",
            "network": "network",
            "net": "network",
            "general": "general",
            "generic": "general",
            "other": "general",
        }
        return mapping.get(cleaned, "general")

    @field_validator("category", "explanation", "recommended_action", mode="before")
    @classmethod
    def _strip_optional_strings(cls, value: object) -> object:
        if value is None or not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None

    @field_validator("recommended_action", mode="before")
    @classmethod
    def _normalize_recommended_action(cls, value: object) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        if not cleaned:
            return None
        if any(token in cleaned for token in ("access", "auth", "permission", "login")):
            return "review_access"
        if any(token in cleaned for token in ("credential", "password", "secret", "reset")):
            return "reset_credentials"
        if any(token in cleaned for token in ("system", "service", "restart", "kernel", "host")):
            return "check_system"
        if any(token in cleaned for token in ("escalat", "incident", "urgent", "soc")):
            return "escalate"
        if any(token in cleaned for token in ("monitor", "watch", "observe", "track")):
            return "monitor"
        if any(token in cleaned for token in ("investigat", "inspect", "review", "triage", "analy")):
            return "investigate"
        return "investigate"


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
    network_server_name: str
    heartbeat_interval_seconds: int
    fallback_analysis_enabled: bool
    api_key_enabled: bool
    total_received: int
    total_ai_success: int
    total_fallback_analysis: int
    total_alerts_forwarded: int
    recent_events_count: int
    last_received_at: datetime | None = None
    last_processed_at: datetime | None = None
    last_alert_id: str | None = None
    last_ai_error: str | None = None
    last_alert_delivery_error: str | None = None
    last_heartbeat_error: str | None = None
    last_error: str | None = None


def _extract_ai_payload(payload: object) -> dict[str, Any] | None:
    queue: deque[object] = deque([payload])
    visited: set[int] = set()

    while queue:
        current = queue.popleft()
        if isinstance(current, AIAnalysisResult):
            return current.model_dump(mode="python")
        if isinstance(current, dict):
            current_id = id(current)
            if current_id in visited:
                continue
            visited.add(current_id)
            if {"score", "severity"}.issubset(current.keys()):
                return current
            if {"score", "severity", "category", "explanation", "recommended_action"}.intersection(current.keys()):
                return current
            queue.extend(current.values())
            continue
        if isinstance(current, str):
            parsed = extract_json_like_mapping(current)
            if parsed is not None:
                queue.append(parsed)
            continue
        if isinstance(current, Iterable) and not isinstance(current, (bytes, bytearray)):
            current_id = id(current)
            if current_id in visited:
                continue
            visited.add(current_id)
            queue.extend(current)

    return None
