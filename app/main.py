from __future__ import annotations

import asyncio
import contextlib
import logging

import uvicorn

from app.api import create_api
from app.bot import create_bot, create_dispatcher
from app.config import load_config
from app.demo import DemoController
from app.services import ApplicationService
from app.storage import SQLiteStorage
from app.utils import configure_logging


logger = logging.getLogger(__name__)


async def _run_bot(dispatcher, bot, service: ApplicationService) -> None:
    await service.mark_bot_online(True)
    try:
        await dispatcher.start_polling(bot, allowed_updates=dispatcher.resolve_used_update_types())
    finally:
        await service.mark_bot_online(False)


async def run() -> None:
    config = load_config()
    configure_logging(config.log_level)

    storage = SQLiteStorage(config.sqlite_path)
    bot = create_bot(config)
    service = ApplicationService(config=config, storage=storage, bot=bot)
    await service.initialize()

    demo_controller = DemoController(service)
    service.attach_demo_controller(demo_controller)

    dispatcher = create_dispatcher(service, config)
    api = create_api(service)
    server = uvicorn.Server(
        uvicorn.Config(
            app=api,
            host=config.api_host,
            port=config.api_port,
            log_level=config.log_level.lower(),
        )
    )

    api_task = asyncio.create_task(server.serve(), name="api")
    bot_task = asyncio.create_task(_run_bot(dispatcher, bot, service), name="bot")
    demo_task = asyncio.create_task(demo_controller.run(), name="demo")
    tasks = [api_task, bot_task, demo_task]

    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            exception = task.exception()
            if exception:
                raise exception
            logger.warning("Task %s exited. Shutting down remaining services.", task.get_name())
    finally:
        await demo_controller.stop()
        server.should_exit = True
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        with contextlib.suppress(Exception):
            await bot.session.close()


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
