from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from secrets import compare_digest
from typing import Any

from dotenv import load_dotenv


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_root_dotenv(env_file: str | Path | None = None) -> Path:
    if env_file is None:
        path = get_repo_root() / ".env"
    else:
        path = Path(env_file).expanduser()
        if not path.is_absolute():
            path = get_repo_root() / path
    path = path.resolve()
    load_dotenv(path)
    return path


def resolve_repo_path(path_text: str) -> Path:
    path = Path(path_text).expanduser()
    if path.is_absolute():
        return path
    return (get_repo_root() / path).resolve()


def derive_internal_url(host: str, port: int) -> str:
    normalized_host = host.strip() or "127.0.0.1"
    if normalized_host in {"0.0.0.0", "::", "[::]"}:
        normalized_host = "127.0.0.1"
    return f"http://{normalized_host}:{port}"


def build_api_headers(api_key: str | None = None) -> dict[str, str]:
    if not api_key:
        return {}
    return {"X-API-Key": api_key}


def is_api_key_configured(api_key: str | None) -> bool:
    return bool(api_key and api_key.strip())


def api_key_matches(expected_api_key: str | None, provided_api_key: str | None) -> bool:
    if not is_api_key_configured(expected_api_key):
        return True
    if not provided_api_key:
        return False
    return compare_digest(expected_api_key.strip(), provided_api_key.strip())


def extract_json_like_mapping(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    candidates = [text]
    fence_matches = re.findall(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    candidates.extend(match.strip() for match in fence_matches if match.strip())

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        candidates.append(text[first_brace : last_brace + 1].strip())

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


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
