from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from app.utils import bool_from_text


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
    load_dotenv(env_file or ".env")

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    admin_chat_id_raw = os.getenv("ADMIN_CHAT_ID", "").strip()

    if not bot_token:
        raise RuntimeError("BOT_TOKEN is required. Add it to your environment or .env file.")
    if not admin_chat_id_raw:
        raise RuntimeError("ADMIN_CHAT_ID is required. Add it to your environment or .env file.")

    api_host = os.getenv("API_HOST", "0.0.0.0").strip() or "0.0.0.0"
    api_port = int(os.getenv("API_PORT", "8000"))
    sqlite_path = str(Path(os.getenv("SQLITE_PATH", "alerts.db")).expanduser())
    demo_mode_default = bool_from_text(os.getenv("DEMO_MODE_DEFAULT"), default=False)
    heartbeat_stale_seconds = int(os.getenv("HEARTBEAT_STALE_SECONDS", "60"))
    log_level = os.getenv("LOG_LEVEL", "INFO").strip() or "INFO"

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
