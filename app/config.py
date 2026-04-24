from __future__ import annotations

import os
from dataclasses import dataclass

from app.utils import bool_from_text
from app.utils import load_root_dotenv
from app.utils import resolve_repo_path


@dataclass(slots=True)
class AppConfig:
    bot_token: str
    admin_chat_id: int
    api_host: str
    api_port: int
    sqlite_path: str
    demo_mode_default: bool
    heartbeat_stale_seconds: int
    log_level: str = "INFO"

    @property
    def api_base_url(self) -> str:
        return f"http://{self.api_host}:{self.api_port}"


def load_config(env_file: str | None = None) -> AppConfig:
    load_root_dotenv(env_file)

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    admin_chat_id_raw = os.getenv("ADMIN_CHAT_ID", "").strip()

    if not bot_token:
        raise RuntimeError("BOT_TOKEN is required. Add it to your environment or .env file.")
    if not admin_chat_id_raw:
        raise RuntimeError("ADMIN_CHAT_ID is required. Add it to your environment or .env file.")

    api_host = _env_value("MAIN_API_HOST", "API_HOST", default="0.0.0.0")
    api_port = int(_env_value("MAIN_API_PORT", "API_PORT", default="8000"))
    sqlite_path = str(resolve_repo_path(_env_value("MAIN_SQLITE_PATH", "SQLITE_PATH", default="alerts.db")))
    demo_mode_default = bool_from_text(_env_value("MAIN_DEMO_MODE_DEFAULT", "DEMO_MODE_DEFAULT"), default=False)
    heartbeat_stale_seconds = int(
        _env_value("MAIN_HEARTBEAT_STALE_SECONDS", "HEARTBEAT_STALE_SECONDS", default="60")
    )
    log_level = _env_value("MAIN_LOG_LEVEL", "LOG_LEVEL", default="INFO")

    return AppConfig(
        bot_token=bot_token,
        admin_chat_id=int(admin_chat_id_raw),
        api_host=api_host,
        api_port=api_port,
        sqlite_path=sqlite_path,
        demo_mode_default=demo_mode_default,
        heartbeat_stale_seconds=heartbeat_stale_seconds,
        log_level=log_level,
    )


def _env_value(primary: str, legacy: str | None = None, default: str = "") -> str:
    if primary in os.environ and os.environ[primary].strip():
        return os.environ[primary].strip()
    if legacy and legacy in os.environ and os.environ[legacy].strip():
        return os.environ[legacy].strip()
    return default
