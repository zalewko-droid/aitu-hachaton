from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from app.models import AlertIn, Severity

if TYPE_CHECKING:
    from app.services import ApplicationService


@dataclass(frozen=True, slots=True)
class DemoScenario:
    source: str
    source_ip: str
    event_type: str
    raw_line: str
    score: float
    severity: Severity
    category: str
    explanation: str
    recommended_action: str


DEMO_SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario(
        source="auth-service",
        source_ip="10.10.0.21",
        event_type="failed_login",
        raw_line="POST /login 401 user=admin repeated_failed_attempts=12",
        score=0.82,
        severity=Severity.medium,
        category="auth",
        explanation="Multiple failed login attempts against the same privileged account from one IP.",
        recommended_action="verify whether the admin account is under brute-force attack",
    ),
    DemoScenario(
        source="nginx",
        source_ip="192.168.43.25",
        event_type="http_request",
        raw_line='GET /admin/login HTTP/1.1" 403 "-" "curl/8.0"',
        score=0.91,
        severity=Severity.high,
        category="web",
        explanation="Repeated suspicious requests against an admin endpoint with denied responses.",
        recommended_action="investigate the source IP and tighten admin route exposure",
    ),
    DemoScenario(
        source="nginx",
        source_ip="172.16.4.9",
        event_type="http_request",
        raw_line='GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 403 "-" "sqlmap"',
        score=0.97,
        severity=Severity.critical,
        category="web",
        explanation="SQL injection-like payload detected in query parameters with an automated client fingerprint.",
        recommended_action="review the request path, validate WAF rules, and inspect upstream application logs",
    ),
    DemoScenario(
        source="api-gateway",
        source_ip="10.10.4.55",
        event_type="auth_burst",
        raw_line='status=401,403 burst=19 route="/admin/export"',
        score=0.88,
        severity=Severity.high,
        category="access",
        explanation="Burst of repeated 401 and 403 responses suggests enumeration or token misuse.",
        recommended_action="inspect failed authorization patterns and consider temporary rate limiting",
    ),
    DemoScenario(
        source="systemd",
        source_ip="127.0.0.1",
        event_type="system_anomaly",
        raw_line="kernel: unusual spike in service restarts detected within 60 seconds",
        score=0.74,
        severity=Severity.medium,
        category="system",
        explanation="Unexpected restart pattern may indicate a cascading service failure or automated crash loop.",
        recommended_action="inspect service health, restart reason, and recent deployment activity",
    ),
)


class DemoController:
    def __init__(self, service: ApplicationService, interval_range: tuple[float, float] = (4.0, 7.0)) -> None:
        self.service = service
        self.interval_range = interval_range
        self._enabled = False
        self._sequence = 0
        self._stop_event = asyncio.Event()
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        self._enabled = await self.service.is_demo_mode_enabled()

    async def set_enabled(self, enabled: bool) -> None:
        async with self._lock:
            self._enabled = enabled

    async def stop(self) -> None:
        self._stop_event.set()

    async def run(self) -> None:
        await self.initialize()
        while not self._stop_event.is_set():
            if not self._enabled:
                await self._sleep(1.0)
                continue

            alert = self._build_alert()
            await self.service.ingest_alert(alert, notify=True)
            await self._sleep(random.uniform(*self.interval_range))

    def _build_alert(self) -> AlertIn:
        self._sequence += 1
        scenario = random.choice(DEMO_SCENARIOS)
        now = datetime.now().replace(microsecond=0)
        return AlertIn(
            id=f"evt_demo_{now.strftime('%Y%m%d%H%M%S')}_{self._sequence:04d}",
            timestamp=now,
            source=scenario.source,
            source_ip=scenario.source_ip,
            event_type=scenario.event_type,
            raw_line=scenario.raw_line,
            score=scenario.score,
            severity=scenario.severity,
            category=scenario.category,
            explanation=scenario.explanation,
            recommended_action=scenario.recommended_action,
        )

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except TimeoutError:
            return
