from __future__ import annotations

from aiogram import Bot, Dispatcher, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import Message

from app.config import AppConfig
from app.formatter import format_anomaly_details, format_recent_alerts, format_status, format_summary
from app.services import ApplicationService


def create_bot(config: AppConfig) -> Bot:
    return Bot(
        token=config.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True),
    )


def create_dispatcher(service: ApplicationService, config: AppConfig) -> Dispatcher:
    router = Router()

    async def ensure_admin(message: Message) -> bool:
        if message.chat.id != config.admin_chat_id:
            await message.answer("Access denied. This bot is restricted to the configured admin chat.")
            return False
        return True

    @router.message(CommandStart())
    async def start_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        await message.answer(
            "\n".join(
                [
                    "<b>AI Log Anomaly Detector</b>",
                    "",
                    "This bot is the Telegram UI for anomaly alerts, summaries, and service health.",
                    "Use /help to see commands and the local demo workflow.",
                ]
            )
        )

    @router.message(Command("help"))
    async def help_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        await message.answer(
            "\n".join(
                [
                    "<b>Available Commands</b>",
                    "",
                    "/start - intro to the bot",
                    "/help - command list and demo workflow",
                    "/status - health, heartbeat, and alert counters",
                    "/alerts - last 5 alerts in compact format",
                    "/summary - severity, category, and top IP summary",
                    "/anomaly &lt;id&gt; - full details for one alert",
                    "/demo_on - enable automatic fake anomaly generation",
                    "/demo_off - disable automatic fake anomaly generation",
                    "",
                    "<b>Demo workflow</b>",
                    "1. Run the project locally.",
                    "2. Open Telegram and send /demo_on.",
                    "3. Watch alerts arrive automatically.",
                    "4. Use /alerts, /summary, and /anomaly to walk through the story.",
                    "5. Use the local API to inject teammate events whenever they are ready.",
                ]
            )
        )

    @router.message(Command("status"))
    async def status_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        snapshot = await service.get_status_snapshot()
        await message.answer(format_status(snapshot))

    @router.message(Command("alerts"))
    async def alerts_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        alerts = await service.get_recent_alerts(limit=5)
        await message.answer(format_recent_alerts(alerts))

    @router.message(Command("summary"))
    async def summary_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        summary = await service.get_summary()
        demo_mode = await service.is_demo_mode_enabled()
        await message.answer(format_summary(summary, demo_mode=demo_mode))

    @router.message(Command("anomaly"))
    async def anomaly_command(message: Message, command: CommandObject) -> None:
        if not await ensure_admin(message):
            return
        if not command.args:
            await message.answer("Usage: /anomaly <alert_id>")
            return

        alert = await service.get_alert(command.args.strip())
        await message.answer(format_anomaly_details(alert))

    @router.message(Command("demo_on"))
    async def demo_on_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        already_enabled = await service.is_demo_mode_enabled()
        await service.set_demo_mode(True)
        if already_enabled:
            await message.answer("Demo mode is already ON.")
        else:
            await message.answer("Demo mode is now ON. Fake anomaly alerts will start arriving shortly.")

    @router.message(Command("demo_off"))
    async def demo_off_command(message: Message) -> None:
        if not await ensure_admin(message):
            return
        already_enabled = await service.is_demo_mode_enabled()
        await service.set_demo_mode(False)
        if already_enabled:
            await message.answer("Demo mode is now OFF.")
        else:
            await message.answer("Demo mode is already OFF.")

    dispatcher = Dispatcher()
    dispatcher.include_router(router)
    return dispatcher
