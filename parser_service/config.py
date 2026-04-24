from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from app.utils import bool_from_text


@dataclass(slots=True)
class ParserConfig:
    parser_host: str
    parser_port: int
    main_api_url: str
    ai_service_url: str
    heartbeat_interval_seconds: int
    request_timeout_seconds: float
    fallback_analysis_enabled: bool
    recent_events_limit: int
    log_level: str = "INFO"


def load_parser_config(env_file: str | None = None) -> ParserConfig:
    load_dotenv(env_file or ".env")

    parser_host = os.getenv("PARSER_HOST", "0.0.0.0").strip() or "0.0.0.0"
    parser_port = int(os.getenv("PARSER_PORT", "9001"))
    main_api_url = os.getenv("PARSER_MAIN_API_URL", "http://127.0.0.1:8000").strip().rstrip("/")
    ai_service_url = os.getenv("PARSER_AI_URL", "http://127.0.0.1:9000/analyze").strip()
    heartbeat_interval_seconds = int(os.getenv("PARSER_HEARTBEAT_INTERVAL_SECONDS", "15"))
    request_timeout_seconds = float(os.getenv("PARSER_REQUEST_TIMEOUT_SECONDS", "8"))
    fallback_analysis_enabled = bool_from_text(
        os.getenv("PARSER_FALLBACK_ANALYSIS_ENABLED"),
        default=True,
    )
    recent_events_limit = int(os.getenv("PARSER_RECENT_EVENTS_LIMIT", "100"))
    log_level = os.getenv("LOG_LEVEL", "INFO").strip() or "INFO"

    if not ai_service_url:
        raise RuntimeError("PARSER_AI_URL is required for the parser service.")

    return ParserConfig(
        parser_host=parser_host,
        parser_port=parser_port,
        main_api_url=main_api_url,
        ai_service_url=ai_service_url,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        request_timeout_seconds=request_timeout_seconds,
        fallback_analysis_enabled=fallback_analysis_enabled,
        recent_events_limit=recent_events_limit,
        log_level=log_level,
    )
