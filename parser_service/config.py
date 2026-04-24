from __future__ import annotations

import os
from dataclasses import dataclass

from app.utils import bool_from_text
from app.utils import derive_internal_url
from app.utils import load_root_dotenv


@dataclass(slots=True)
class ParserConfig:
    parser_host: str
    parser_port: int
    main_api_url: str
    ai_service_url: str
    network_server_name: str
    heartbeat_interval_seconds: int
    request_timeout_seconds: float
    fallback_analysis_enabled: bool
    recent_events_limit: int
    shared_api_key: str | None = None
    log_level: str = "INFO"


def load_parser_config(env_file: str | None = None) -> ParserConfig:
    load_root_dotenv(env_file)

    parser_host = _env_value("PARSER_HOST", default="0.0.0.0")
    parser_port = int(_env_value("PARSER_PORT", default="9001"))
    main_api_host = _env_value("MAIN_API_HOST", "API_HOST", default="0.0.0.0")
    main_api_port = int(_env_value("MAIN_API_PORT", "API_PORT", default="8000"))
    main_api_url = derive_internal_url(main_api_host, main_api_port)
    ai_service_url = _env_value("AI_ANALYZE_URL", "PARSER_AI_URL", default="http://127.0.0.1:9000/analyze")
    network_server_name = _env_value("NETWORK_SERVER_NAME", default="victim-laptop")
    heartbeat_interval_seconds = int(_env_value("PARSER_HEARTBEAT_INTERVAL_SECONDS", default="12"))
    request_timeout_seconds = float(
        _env_value("PARSER_HTTP_TIMEOUT_SECONDS", "PARSER_REQUEST_TIMEOUT_SECONDS", default="5")
    )
    fallback_analysis_enabled = bool_from_text(
        os.getenv("PARSER_FALLBACK_ANALYSIS_ENABLED"),
        default=True,
    )
    recent_events_limit = int(os.getenv("PARSER_RECENT_EVENTS_LIMIT", "100"))
    shared_api_key = _env_value("SHARED_API_KEY", default="") or None
    log_level = _env_value("PARSER_LOG_LEVEL", "LOG_LEVEL", default="INFO")

    if not ai_service_url:
        raise RuntimeError("AI_ANALYZE_URL is required for the parser service.")

    return ParserConfig(
        parser_host=parser_host,
        parser_port=parser_port,
        main_api_url=main_api_url,
        ai_service_url=ai_service_url,
        network_server_name=network_server_name,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        request_timeout_seconds=request_timeout_seconds,
        fallback_analysis_enabled=fallback_analysis_enabled,
        recent_events_limit=recent_events_limit,
        shared_api_key=shared_api_key,
        log_level=log_level,
    )


def _env_value(primary: str, legacy: str | None = None, default: str = "") -> str:
    if primary in os.environ and os.environ[primary].strip():
        return os.environ[primary].strip()
    if legacy and legacy in os.environ and os.environ[legacy].strip():
        return os.environ[legacy].strip()
    return default
