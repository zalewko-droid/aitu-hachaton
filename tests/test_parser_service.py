from datetime import datetime

from parser_service.models import RawLogLineIn
from parser_service.parsers import (
    compute_fallback_score,
    derive_fallback_analysis,
    normalize_log_line,
    severity_from_score,
)


def test_normalize_nginx_access_log_line() -> None:
    payload = RawLogLineIn(
        source="nginx",
        raw_line='192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET /admin/login HTTP/1.1" 403 512',
    )

    event = normalize_log_line(payload)

    assert event.source == "nginx"
    assert event.source_ip == "192.168.43.25"
    assert event.event_type == "admin_access"
    assert event.normalized_fields["method"] == "GET"
    assert event.normalized_fields["status_code"] == 403


def test_normalize_malformed_log_line_returns_best_effort_event() -> None:
    payload = RawLogLineIn(
        raw_line="weird malformed line with kernel restart and 10.0.0.8 but no strict format",
        metadata={"hostname": "victim-laptop"},
    )

    event = normalize_log_line(payload)

    assert event.source_ip == "10.0.0.8"
    assert event.event_type == "system_anomaly"
    assert event.normalized_fields["metadata"] == {"hostname": "victim-laptop"}


def test_fallback_analysis_handles_sqli_like_request() -> None:
    payload = RawLogLineIn(
        timestamp=datetime(2026, 4, 24, 14, 21, 3),
        raw_line='172.16.4.9 - - [24/Apr/2026:14:21:03 +0500] "GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 403 12',
    )

    event = normalize_log_line(payload)
    analysis = derive_fallback_analysis(event)

    assert analysis.category == "web"
    assert analysis.score == compute_fallback_score(event)
    assert analysis.severity == severity_from_score(analysis.score)
    assert analysis.severity.value == "high"
    assert 0.70 <= analysis.score <= 1.0


def test_compute_fallback_score_ranks_severe_patterns_above_mild_requests() -> None:
    mild_event = normalize_log_line(
        RawLogLineIn(
            raw_line='192.168.43.25 - - [24/Apr/2026:14:21:03 +0500] "GET / HTTP/1.1" 200 512',
        )
    )
    severe_event = normalize_log_line(
        RawLogLineIn(
            raw_line='172.16.4.9 - - [24/Apr/2026:14:21:03 +0500] "GET /etc/passwd?x=%27%20OR%201%3D1-- HTTP/1.1" 403 12',
        )
    )

    mild_score = compute_fallback_score(mild_event)
    severe_score = compute_fallback_score(severe_event)

    assert mild_score < severe_score
    assert mild_score < 0.45
    assert severe_score >= 0.90


def test_severity_from_score_uses_expected_thresholds() -> None:
    assert severity_from_score(0.20).value == "low"
    assert severity_from_score(0.45).value == "medium"
    assert severity_from_score(0.70).value == "high"
    assert severity_from_score(0.90).value == "critical"
