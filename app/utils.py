from __future__ import annotations

import logging
from datetime import datetime
from typing import Any


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def parse_datetime(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def to_storage_timestamp(value: datetime | str | None) -> str | None:
    dt = parse_datetime(value)
    if dt is None:
        return None
    return dt.isoformat(timespec="seconds")


def format_timestamp(value: datetime | str | None) -> str:
    dt = parse_datetime(value)
    if dt is None:
        return "n/a"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def age_seconds(value: datetime | str | None) -> int | None:
    dt = parse_datetime(value)
    if dt is None:
        return None
    delta = datetime.now() - dt
    return max(int(delta.total_seconds()), 0)


def bool_from_text(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def bool_to_text(value: bool) -> str:
    return "1" if value else "0"


def truncate(text: Any, limit: int = 72) -> str:
    if text is None:
        return "n/a"
    value = str(text).strip()
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."
