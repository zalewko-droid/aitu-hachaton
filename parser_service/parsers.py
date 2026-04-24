from __future__ import annotations

import re
from datetime import datetime
from uuid import uuid4

from app.models import Severity
from app.utils import parse_datetime
from parser_service.models import AIAnalysisResult, NormalizedEvent, RawLogLineIn


HTTP_ACCESS_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/(?P<protocol>[0-9.]+))?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)
HTTP_REQUEST_RE = re.compile(r'(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?P<path>\S+)', re.IGNORECASE)
FAILED_LOGIN_RE = re.compile(r"(failed password|failed login|authentication failure)", re.IGNORECASE)
STATUS_CODE_RE = re.compile(r"\b(?P<status>[1-5]\d{2})\b")
IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
SYSLOG_TIMESTAMP_RE = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
USER_RE = re.compile(r"(?:user=|for invalid user |for )(?P<user>[A-Za-z0-9_.-]+)", re.IGNORECASE)

SQLI_MARKERS = (
    "sqlmap",
    "union select",
    " or 1=1",
    "%27",
    "' or ",
    "information_schema",
)
PATH_TRAVERSAL_MARKERS = ("../", "..%2f", "%2e%2e%2f")


def normalize_log_line(payload: RawLogLineIn) -> NormalizedEvent:
    raw_line = payload.raw_line.strip()
    event_id = payload.id or f"evt_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}"
    source = payload.source or infer_source(raw_line)
    source_ip = payload.source_ip
    timestamp = payload.timestamp or datetime.now().replace(microsecond=0)
    normalized_fields: dict[str, object] = {}
    event_type = "generic_log"

    access_match = HTTP_ACCESS_RE.search(raw_line)
    if access_match:
        groups = access_match.groupdict()
        timestamp = payload.timestamp or parse_access_timestamp(groups["timestamp"]) or timestamp
        source = payload.source or "nginx"
        source_ip = payload.source_ip or groups["ip"]
        path = groups["path"]
        status_code = safe_int(groups["status"])
        suspicious_tokens = extract_suspicious_tokens(path)
        normalized_fields = {
            "method": groups["method"],
            "path": path,
            "protocol": groups.get("protocol"),
            "status_code": status_code,
            "response_bytes": None if groups["bytes"] == "-" else safe_int(groups["bytes"]),
            "suspicious_tokens": suspicious_tokens,
        }
        event_type = infer_http_event_type(path=path, status_code=status_code, raw_text=raw_line, suspicious_tokens=suspicious_tokens)
    elif FAILED_LOGIN_RE.search(raw_line):
        timestamp = payload.timestamp or parse_syslog_timestamp(raw_line) or timestamp
        source = payload.source or infer_source(raw_line)
        source_ip = payload.source_ip or extract_first_ip(raw_line)
        user_match = USER_RE.search(raw_line)
        normalized_fields = {
            "username": user_match.group("user") if user_match else None,
            "status_code": extract_status_code(raw_line),
            "suspicious_tokens": extract_suspicious_tokens(raw_line),
        }
        event_type = "failed_login"
    else:
        timestamp = payload.timestamp or parse_syslog_timestamp(raw_line) or timestamp
        source_ip = payload.source_ip or extract_first_ip(raw_line)
        request_match = HTTP_REQUEST_RE.search(raw_line)
        status_code = extract_status_code(raw_line)
        suspicious_tokens = extract_suspicious_tokens(raw_line)
        if request_match:
            normalized_fields["method"] = request_match.group("method").upper()
            normalized_fields["path"] = request_match.group("path")
        normalized_fields["status_code"] = status_code
        normalized_fields["suspicious_tokens"] = suspicious_tokens
        event_type = infer_generic_event_type(raw_line, normalized_fields)

    if payload.metadata:
        normalized_fields["metadata"] = payload.metadata

    return NormalizedEvent(
        id=event_id,
        timestamp=timestamp,
        source=source,
        source_ip=source_ip,
        event_type=event_type,
        raw_line=raw_line,
        normalized_fields=normalized_fields,
        metadata=payload.metadata,
    )


def derive_fallback_analysis(event: NormalizedEvent) -> AIAnalysisResult:
    raw_text = event.raw_line.lower()
    path = str(event.normalized_fields.get("path") or "").lower()
    status_code = event.normalized_fields.get("status_code")
    suspicious_tokens = {str(item).lower() for item in event.normalized_fields.get("suspicious_tokens", [])}

    if suspicious_tokens.intersection({"sql_injection", "sqlmap"}):
        return AIAnalysisResult(
            score=0.97,
            severity=Severity.critical,
            category="web",
            explanation="Parser fallback flagged a likely SQL injection pattern in an HTTP request.",
            recommended_action="investigate the source IP, review WAF behavior, and inspect the targeted endpoint",
        )

    if suspicious_tokens.intersection({"path_traversal"}) or any(marker in path for marker in PATH_TRAVERSAL_MARKERS):
        return AIAnalysisResult(
            score=0.93,
            severity=Severity.high,
            category="web",
            explanation="Parser fallback detected a path traversal-like request pattern.",
            recommended_action="inspect the requested path, validate input handling, and review file access logs",
        )

    if event.event_type == "admin_access":
        return AIAnalysisResult(
            score=0.90 if status_code in {401, 403} else 0.82,
            severity=Severity.high if status_code in {401, 403} else Severity.medium,
            category="web",
            explanation="Parser fallback detected suspicious access to an admin endpoint.",
            recommended_action="verify whether the request was expected and review access control for admin routes",
        )

    if event.event_type == "failed_login":
        return AIAnalysisResult(
            score=0.84,
            severity=Severity.medium if status_code not in {401, 403} else Severity.high,
            category="auth",
            explanation="Parser fallback detected a failed login event with signs of unauthorized access attempts.",
            recommended_action="review account activity and confirm whether the login attempts were legitimate",
        )

    if event.event_type == "access_denied":
        return AIAnalysisResult(
            score=0.79,
            severity=Severity.medium,
            category="access",
            explanation="Parser fallback detected a denied access event that may indicate probing or misuse.",
            recommended_action="review authorization failures and inspect the source host for repeated attempts",
        )

    if event.event_type == "system_anomaly":
        return AIAnalysisResult(
            score=0.72,
            severity=Severity.medium,
            category="system",
            explanation="Parser fallback detected a system anomaly pattern in the incoming log line.",
            recommended_action="inspect service health, restart patterns, and recent system changes",
        )

    return AIAnalysisResult(
        score=0.61,
        severity=Severity.low,
        category=default_category_for_event(event.event_type),
        explanation="Parser fallback produced a best-effort low-confidence analysis because the AI service was unavailable.",
        recommended_action="review the normalized event manually if the source appears suspicious",
    )


def default_category_for_event(event_type: str) -> str:
    if event_type in {"http_request", "admin_access"}:
        return "web"
    if event_type == "failed_login":
        return "auth"
    if event_type == "access_denied":
        return "access"
    if event_type == "system_anomaly":
        return "system"
    return "general"


def default_explanation_for_event(event: NormalizedEvent) -> str:
    return f"Best-effort parser normalization produced event type '{event.event_type}' from the raw log line."


def default_recommended_action_for_event(event: NormalizedEvent) -> str:
    if event.event_type in {"http_request", "admin_access"}:
        return "investigate the request path and validate the source IP"
    if event.event_type == "failed_login":
        return "review authentication attempts for the affected account"
    if event.event_type == "access_denied":
        return "inspect repeated authorization failures from the source"
    if event.event_type == "system_anomaly":
        return "review system logs and recent service activity"
    return "inspect the raw event manually"


def infer_source(raw_line: str) -> str:
    text = raw_line.lower()
    if HTTP_ACCESS_RE.search(raw_line):
        return "nginx"
    if "sshd" in text or FAILED_LOGIN_RE.search(raw_line):
        return "auth-service"
    if "systemd" in text or "kernel" in text:
        return "systemd"
    if "nginx" in text:
        return "nginx"
    return "unknown"


def infer_http_event_type(path: str, status_code: int | None, raw_text: str, suspicious_tokens: list[str]) -> str:
    lower_path = path.lower()
    lower_text = raw_text.lower()
    if "sql_injection" in suspicious_tokens or "sqlmap" in suspicious_tokens:
        return "http_request"
    if "/admin" in lower_path or "/wp-admin" in lower_path:
        return "admin_access"
    if status_code in {401, 403}:
        return "access_denied"
    if any(marker in lower_text for marker in ("exception", "error", "restart")):
        return "system_anomaly"
    return "http_request"


def infer_generic_event_type(raw_line: str, normalized_fields: dict[str, object]) -> str:
    lower_text = raw_line.lower()
    path = str(normalized_fields.get("path") or "").lower()
    suspicious_tokens = {str(item).lower() for item in normalized_fields.get("suspicious_tokens", [])}
    status_code = normalized_fields.get("status_code")

    if FAILED_LOGIN_RE.search(raw_line):
        return "failed_login"
    if suspicious_tokens.intersection({"sql_injection", "sqlmap"}):
        return "http_request"
    if "/admin" in path:
        return "admin_access"
    if status_code in {401, 403}:
        return "access_denied"
    if any(marker in lower_text for marker in ("kernel", "systemd", "restart", "panic", "exception", "traceback")):
        return "system_anomaly"
    return "generic_log"


def extract_suspicious_tokens(text: str) -> list[str]:
    lower_text = text.lower()
    tokens: list[str] = []
    if any(marker in lower_text for marker in SQLI_MARKERS):
        tokens.append("sql_injection")
    if "sqlmap" in lower_text:
        tokens.append("sqlmap")
    if any(marker in lower_text for marker in PATH_TRAVERSAL_MARKERS):
        tokens.append("path_traversal")
    if "/admin" in lower_text or "/wp-admin" in lower_text:
        tokens.append("admin_path")
    return tokens


def extract_first_ip(text: str) -> str | None:
    match = IP_RE.search(text)
    return match.group("ip") if match else None


def extract_status_code(text: str) -> int | None:
    match = STATUS_CODE_RE.search(text)
    if match is None:
        return None
    return safe_int(match.group("status"))


def parse_access_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.astimezone().replace(tzinfo=None)
    except ValueError:
        return parse_datetime(value)


def parse_syslog_timestamp(raw_line: str) -> datetime | None:
    match = SYSLOG_TIMESTAMP_RE.search(raw_line)
    if match is None:
        return None
    stamp = match.group("stamp")
    try:
        return datetime.strptime(f"{datetime.now().year} {stamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def safe_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
