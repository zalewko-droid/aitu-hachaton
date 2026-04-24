from __future__ import annotations

import json
from datetime import datetime

import aiohttp
from pydantic import ValidationError

from parser_service.models import AIAnalysisResult, NormalizedEvent
from app.utils import build_api_headers


class ParserHttpClient:
    def __init__(self, timeout_seconds: float, shared_api_key: str | None = None) -> None:
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session: aiohttp.ClientSession | None = None
        self._shared_api_key = shared_api_key

    async def open(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def analyze_event(self, ai_service_url: str, event: NormalizedEvent) -> tuple[AIAnalysisResult | None, str | None]:
        response_data, error = await self._post_json(ai_service_url, event.model_dump(mode="json"))
        if error is not None:
            return None, error

        try:
            return AIAnalysisResult.from_ai_payload(response_data or {}), None
        except (ValidationError, ValueError, TypeError) as exc:
            return None, f"AI response validation failed: {exc}"

    async def send_alert(self, main_api_url: str, payload: dict[str, object]) -> tuple[bool, str | None]:
        _, error = await self._post_json(
            f"{main_api_url}/ingest-alert",
            payload,
            headers=build_api_headers(self._shared_api_key),
        )
        if error is not None:
            return False, error
        return True, None

    async def send_parser_heartbeat(self, main_api_url: str, status: str = "online") -> tuple[bool, str | None]:
        payload = {
            "service": "parser",
            "timestamp": datetime.now().replace(microsecond=0).isoformat(),
            "status": status,
        }
        _, error = await self._post_json(
            f"{main_api_url}/heartbeat/parser",
            payload,
            headers=build_api_headers(self._shared_api_key),
        )
        if error is not None:
            return False, error
        return True, None

    async def _post_json(
        self,
        url: str,
        payload: dict[str, object],
        headers: dict[str, str] | None = None,
    ) -> tuple[object | None, str | None]:
        if self._session is None or self._session.closed:
            await self.open()

        assert self._session is not None

        try:
            async with self._session.post(url, json=payload, headers=headers) as response:
                text = await response.text()
                data: object | None = None
                if text:
                    try:
                        data = json.loads(text)
                    except json.JSONDecodeError:
                        data = {"raw_text": text}

                if response.status >= 400:
                    detail = data if data is not None else {"raw_text": text}
                    return None, f"HTTP {response.status} from {url}: {detail}"
                return data, None
        except Exception as exc:
            return None, f"Request to {url} failed: {exc}"
