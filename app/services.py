from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aiogram import Bot

from app.config import AppConfig
from app.formatter import format_alert_message
from app.models import (
    AlertIn,
    AlertSummary,
    HeartbeatPayload,
    IngestResult,
    ServiceName,
    ServiceState,
    ServiceStatus,
    StatusSnapshot,
)
from app.storage import SQLiteStorage
from app.utils import bool_from_text, bool_to_text, is_api_key_configured

if TYPE_CHECKING:
    from app.demo import DemoController


logger = logging.getLogger(__name__)


class TelegramNotifier:
    def __init__(self, bot: Bot, admin_chat_id: int) -> None:
        self.bot = bot
        self.admin_chat_id = admin_chat_id

    async def send_alert(self, alert: AlertIn) -> bool:
        try:
            await self.bot.send_message(self.admin_chat_id, format_alert_message(alert))
            return True
        except Exception:
            logger.exception("Failed to send Telegram alert for %s", alert.id)
            return False


class ApplicationService:
    def __init__(self, config: AppConfig, storage: SQLiteStorage, bot: Bot) -> None:
        self.config = config
        self.storage = storage
        self.notifier = TelegramNotifier(bot=bot, admin_chat_id=config.admin_chat_id)
        self._api_online = False
        self._bot_online = False
        self._demo_controller: DemoController | None = None

    async def initialize(self) -> None:
        await self.storage.initialize()
        if await self.storage.get_setting("demo_mode") is None:
            await self.storage.set_setting("demo_mode", bool_to_text(self.config.demo_mode_default))

    def attach_demo_controller(self, demo_controller: DemoController) -> None:
        self._demo_controller = demo_controller

    async def mark_api_online(self, is_online: bool) -> None:
        self._api_online = is_online

    async def mark_bot_online(self, is_online: bool) -> None:
        self._bot_online = is_online

    async def ingest_alert(self, alert: AlertIn, notify: bool = True) -> IngestResult:
        try:
            stored = await self.storage.save_alert(alert)
        except Exception:
            logger.exception("Storage failed while saving alert %s", alert.id)
            return IngestResult(alert_id=alert.id, status="storage_error", stored=False, notified=False)

        if not stored:
            return IngestResult(alert_id=alert.id, status="duplicate", stored=False, notified=False)

        notified = False
        if notify:
            notified = await self.notifier.send_alert(alert)

        return IngestResult(alert_id=alert.id, status="accepted", stored=True, notified=notified)

    async def update_heartbeat(self, heartbeat: HeartbeatPayload) -> None:
        try:
            await self.storage.update_heartbeat(
                service=heartbeat.service.value,
                timestamp=heartbeat.timestamp,
                status=heartbeat.status,
            )
        except Exception:
            logger.exception("Failed to update heartbeat for %s", heartbeat.service.value)

    async def get_recent_alerts(self, limit: int = 5) -> list[AlertIn]:
        try:
            return await self.storage.get_recent_alerts(limit)
        except Exception:
            logger.exception("Failed to fetch recent alerts")
            return []

    async def get_alert(self, alert_id: str) -> AlertIn | None:
        try:
            return await self.storage.get_alert_by_id(alert_id)
        except Exception:
            logger.exception("Failed to fetch alert %s", alert_id)
            return None

    async def get_summary(self) -> AlertSummary:
        try:
            return await self.storage.get_summary()
        except Exception:
            logger.exception("Failed to build alert summary")
            return AlertSummary()

    async def get_status_snapshot(self) -> StatusSnapshot:
        try:
            service_status = await self.storage.get_service_status(self.config.heartbeat_stale_seconds)
        except Exception:
            logger.exception("Failed to fetch service status")
            service_status = {
                ServiceName.parser.value: ServiceStatus(
                    service=ServiceName.parser,
                    status=ServiceState.unknown,
                ),
                ServiceName.detector.value: ServiceStatus(
                    service=ServiceName.detector,
                    status=ServiceState.unknown,
                ),
            }

        summary = await self.get_summary()
        demo_mode = await self.is_demo_mode_enabled()

        return StatusSnapshot(
            bot_status=ServiceState.online if self._bot_online else ServiceState.offline,
            api_status=ServiceState.online if self._api_online else ServiceState.offline,
            parser=service_status[ServiceName.parser.value],
            detector=service_status[ServiceName.detector.value],
            total_alerts=summary.total_alerts,
            high_severity_alerts=summary.high_severity_alerts,
            last_alert_timestamp=summary.latest_window_end,
            demo_mode=demo_mode,
        )

    async def get_health_payload(self) -> dict[str, object]:
        snapshot = await self.get_status_snapshot()
        return {
            "status": "ok",
            "bot_status": snapshot.bot_status.value,
            "api_status": snapshot.api_status.value,
            "parser_status": snapshot.parser.status.value,
            "detector_status": snapshot.detector.status.value,
            "parser": snapshot.parser.model_dump(mode="json"),
            "detector": snapshot.detector.model_dump(mode="json"),
            "total_alerts": snapshot.total_alerts,
            "high_severity_alerts": snapshot.high_severity_alerts,
            "last_alert_timestamp": snapshot.last_alert_timestamp,
            "demo_mode": snapshot.demo_mode,
            "heartbeat_stale_seconds": self.config.heartbeat_stale_seconds,
            "api_key_enabled": is_api_key_configured(self.config.shared_api_key),
        }

    async def set_demo_mode(self, enabled: bool) -> bool:
        await self.storage.set_setting("demo_mode", bool_to_text(enabled))
        if self._demo_controller is not None:
            await self._demo_controller.set_enabled(enabled)
        return enabled

    async def is_demo_mode_enabled(self) -> bool:
        value = await self.storage.get_setting("demo_mode")
        return bool_from_text(value, default=self.config.demo_mode_default)
