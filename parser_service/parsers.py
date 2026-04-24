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
SUSPICIOUS_PATH_WEIGHTS = {
    "/.env": 0.22,
    "/wp-login.php": 0.18,
    "/phpmyadmin": 0.20,
    "/etc/passwd": 0.24,
    "/wp-admin": 0.10,
    "/admin": 0.08,
}
DANGEROUS_RAW_MARKER_WEIGHTS = {
    "union select": 0.18,
    "' or ": 0.14,
    " or 1=1": 0.16,
    "or%201%3d1": 0.16,
    "<script>": 0.14,
    "../": 0.16,
    "sqlmap": 0.12,
    "failed password": 0.10,
    "failed login": 0.10,
    "authentication failure": 0.10,
    "forbidden": 0.06,
    "unauthorized": 0.06,
    "denied": 0.06,
    "panic": 0.14,
    "traceback": 0.14,
    "exception": 0.10,
    "restart": 0.08,
    "kernel": 0.08,
}
FALLBACK_ACTIONS = {
    "web": "investigate",
    "auth": "review_access",
    "access": "review_access",
    "system": "check_system",
    "general": "monitor",
}


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
    suspicious_tokens = {str(item).lower() for item in event.normalized_fields.get("suspicious_tokens", [])}
    score = compute_fallback_score(event)
    severity = severity_from_score(score)
    category = default_category_for_event(event.event_type)

    if suspicious_tokens.intersection({"sql_injection", "sqlmap"}):
        category = "web"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback flagged a likely SQL injection pattern in an HTTP request.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    if suspicious_tokens.intersection({"path_traversal"}) or any(marker in path for marker in PATH_TRAVERSAL_MARKERS):
        category = "web"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback detected a path traversal-like request pattern.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    if event.event_type == "admin_access":
        category = "web"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback detected suspicious access to an admin endpoint.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    if event.event_type == "failed_login":
        category = "auth"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback detected a failed login event with signs of unauthorized access attempts.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    if event.event_type == "access_denied":
        category = "access"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback detected a denied access event that may indicate probing or misuse.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    if event.event_type == "system_anomaly":
        category = "system"
        return AIAnalysisResult(
            score=score,
            severity=severity,
            category=category,
            explanation="Parser fallback detected a system anomaly pattern in the incoming log line.",
            recommended_action=FALLBACK_ACTIONS[category],
        )

    return AIAnalysisResult(
        score=score,
        severity=severity,
        category=category,
        explanation="Parser fallback produced a best-effort low-confidence analysis because the AI service was unavailable.",
        recommended_action=FALLBACK_ACTIONS[category],
    )


def compute_fallback_score(event: NormalizedEvent) -> float:
    score = 0.10
    raw_text = event.raw_line.lower()
    path = str(event.normalized_fields.get("path") or "").lower()
    method = str(event.normalized_fields.get("method") or "").upper()
    status_code = event.normalized_fields.get("status_code")
    suspicious_tokens = {str(item).lower() for item in event.normalized_fields.get("suspicious_tokens", [])}

    score += {
        "http_request": 0.10,
        "admin_access": 0.22,
        "failed_login": 0.20,
        "access_denied": 0.16,
        "system_anomaly": 0.18,
        "generic_log": 0.04,
    }.get(event.event_type, 0.05)

    if status_code in {401, 403}:
        score += 0.14
    elif status_code == 404:
        score += 0.06
    elif isinstance(status_code, int) and 500 <= status_code <= 599:
        score += 0.12
    elif isinstance(status_code, int) and 400 <= status_code <= 499:
        score += 0.08

    if method == "POST":
        score += 0.05

    score += 0.34 if "sql_injection" in suspicious_tokens else 0.0
    score += 0.20 if "sqlmap" in suspicious_tokens else 0.0
    score += 0.28 if "path_traversal" in suspicious_tokens else 0.0
    score += 0.08 if "admin_path" in suspicious_tokens else 0.0

    for marker, weight in SUSPICIOUS_PATH_WEIGHTS.items():
        if marker in path:
            score += weight

    for marker, weight in DANGEROUS_RAW_MARKER_WEIGHTS.items():
        if marker in raw_text:
            score += weight

    if event.event_type == "failed_login" and event.normalized_fields.get("username"):
        score += 0.05

    return max(0.0, min(score, 1.0))


def severity_from_score(score: float) -> Severity:
    if score >= 0.90:
        return Severity.critical
    if score >= 0.70:
        return Severity.high
    if score >= 0.45:
        return Severity.medium
    return Severity.low


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
    return FALLBACK_ACTIONS[default_category_for_event(event.event_type)]


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
