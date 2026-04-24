from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils import parse_datetime


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ServiceName(str, Enum):
    parser = "parser"
    detector = "detector"


class ServiceState(str, Enum):
    online = "online"
    offline = "offline"
    stale = "stale"
    unknown = "unknown"


class AlertIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1)
    timestamp: datetime
    source: str = Field(min_length=1)
    source_ip: str | None = None
    event_type: str = Field(min_length=1)
    raw_line: str | None = None
    score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    category: str | None = None
    explanation: str | None = None
    recommended_action: str | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def _normalize_timestamp(cls, value: datetime | str) -> datetime:
        parsed = parse_datetime(value)
        if parsed is None:
            raise ValueError("timestamp is required")
        return parsed

    @field_validator(
        "id",
        "source",
        "source_ip",
        "event_type",
        "raw_line",
        "category",
        "explanation",
        "recommended_action",
        mode="before",
    )
    @classmethod
    def _strip_strings(cls, value: object) -> object:
        if value is None or not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None

    @field_validator("id", "source", "event_type")
    @classmethod
    def _required_strings(cls, value: str | None) -> str:
        if not value:
            raise ValueError("field cannot be blank")
        return value


class HeartbeatPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    service: ServiceName
    timestamp: datetime
    status: str = Field(default="online", min_length=1)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _normalize_timestamp(cls, value: datetime | str) -> datetime:
        parsed = parse_datetime(value)
        if parsed is None:
            raise ValueError("timestamp is required")
        return parsed

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status(cls, value: object) -> str:
        if value is None:
            return "online"
        if not isinstance(value, str):
            raise ValueError("status must be a string")
        cleaned = value.strip().lower()
        if cleaned not in {"online", "offline"}:
            raise ValueError("status must be 'online' or 'offline'")
        return cleaned


class TopSourceIP(BaseModel):
    source_ip: str
    count: int


class AlertSummary(BaseModel):
    total_alerts: int = 0
    high_severity_alerts: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    top_source_ips: list[TopSourceIP] = Field(default_factory=list)
    latest_window_start: datetime | None = None
    latest_window_end: datetime | None = None


class ServiceStatus(BaseModel):
    service: ServiceName
    status: ServiceState
    last_seen: datetime | None = None
    age_seconds: int | None = None


class StatusSnapshot(BaseModel):
    bot_status: ServiceState
    api_status: ServiceState
    parser: ServiceStatus
    detector: ServiceStatus
    total_alerts: int = 0
    high_severity_alerts: int = 0
    last_alert_timestamp: datetime | None = None
    demo_mode: bool = False


class IngestResult(BaseModel):
    alert_id: str
    status: str
    stored: bool
    notified: bool = False
