from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import uvicorn

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils import configure_logging
from parser_service.api import create_parser_api
from parser_service.config import load_parser_config
from parser_service.forwarder import ParserHttpClient
from parser_service.service import ParserService


async def run() -> None:
    config = load_parser_config()
    configure_logging(config.log_level)

    client = ParserHttpClient(
        timeout_seconds=config.request_timeout_seconds,
        shared_api_key=config.shared_api_key,
    )
    service = ParserService(config=config, client=client)
    api = create_parser_api(service)
    server = uvicorn.Server(
        uvicorn.Config(
            app=api,
            host=config.parser_host,
            port=config.parser_port,
            log_level=config.log_level.lower(),
        )
    )
    await server.serve()


def main() -> None:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
