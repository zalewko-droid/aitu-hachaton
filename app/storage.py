from __future__ import annotations

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

from app.models import AlertIn, AlertSummary, ServiceName, ServiceState, ServiceStatus, TopSourceIP
from app.utils import age_seconds, parse_datetime, to_storage_timestamp


class SQLiteStorage:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize)

    async def save_alert(self, alert: AlertIn) -> bool:
        payload = alert.model_dump(mode="python")
        return await asyncio.to_thread(self._save_alert, payload)

    async def get_recent_alerts(self, limit: int = 5) -> list[AlertIn]:
        return await asyncio.to_thread(self._get_recent_alerts, limit)

    async def get_alert_by_id(self, alert_id: str) -> AlertIn | None:
        return await asyncio.to_thread(self._get_alert_by_id, alert_id)

    async def get_summary(self) -> AlertSummary:
        return await asyncio.to_thread(self._get_summary)

    async def update_heartbeat(self, service: str, timestamp: object, status: str) -> None:
        await asyncio.to_thread(self._update_heartbeat, service, timestamp, status)

    async def get_service_status(self, stale_seconds: int) -> dict[str, ServiceStatus]:
        return await asyncio.to_thread(self._get_service_status, stale_seconds)

    async def set_setting(self, key: str, value: str) -> None:
        await asyncio.to_thread(self._set_setting, key, value)

    async def get_setting(self, key: str) -> str | None:
        return await asyncio.to_thread(self._get_setting, key)

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(
                """
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_ip TEXT,
                    event_type TEXT NOT NULL,
                    raw_line TEXT,
                    score REAL NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT,
                    explanation TEXT,
                    recommended_action TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
                CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);

                CREATE TABLE IF NOT EXISTS heartbeats (
                    service TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def _save_alert(self, payload: dict[str, object]) -> bool:
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    id,
                    timestamp,
                    source,
                    source_ip,
                    event_type,
                    raw_line,
                    score,
                    severity,
                    category,
                    explanation,
                    recommended_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["id"],
                    to_storage_timestamp(payload["timestamp"]),
                    payload["source"],
                    payload["source_ip"],
                    payload["event_type"],
                    payload["raw_line"],
                    payload["score"],
                    payload["severity"].value if hasattr(payload["severity"], "value") else payload["severity"],
                    payload["category"],
                    payload["explanation"],
                    payload["recommended_action"],
                ),
            )
            conn.commit()
            return cursor.rowcount == 1

    def _row_to_alert(self, row: sqlite3.Row | None) -> AlertIn | None:
        if row is None:
            return None
        return AlertIn.model_validate(dict(row))

    def _get_recent_alerts(self, limit: int) -> list[AlertIn]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    timestamp,
                    source,
                    source_ip,
                    event_type,
                    raw_line,
                    score,
                    severity,
                    category,
                    explanation,
                    recommended_action
                FROM alerts
                ORDER BY timestamp DESC, created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_alert(row) for row in rows if self._row_to_alert(row) is not None]

    def _get_alert_by_id(self, alert_id: str) -> AlertIn | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT
                    id,
                    timestamp,
                    source,
                    source_ip,
                    event_type,
                    raw_line,
                    score,
                    severity,
                    category,
                    explanation,
                    recommended_action
                FROM alerts
                WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()
        return self._row_to_alert(row)

    def _get_summary(self) -> AlertSummary:
        with closing(self._connect()) as conn:
            total_alerts = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]
            high_severity_alerts = conn.execute(
                "SELECT COUNT(*) AS count FROM alerts WHERE severity IN ('high', 'critical')"
            ).fetchone()["count"]

            severity_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS count
                FROM alerts
                GROUP BY severity
                ORDER BY count DESC, severity ASC
                """
            ).fetchall()

            category_rows = conn.execute(
                """
                SELECT COALESCE(NULLIF(category, ''), 'uncategorized') AS category, COUNT(*) AS count
                FROM alerts
                GROUP BY COALESCE(NULLIF(category, ''), 'uncategorized')
                ORDER BY count DESC, category ASC
                """
            ).fetchall()

            source_rows = conn.execute(
                """
                SELECT COALESCE(NULLIF(source_ip, ''), 'unknown') AS source_ip, COUNT(*) AS count
                FROM alerts
                GROUP BY COALESCE(NULLIF(source_ip, ''), 'unknown')
                ORDER BY count DESC, source_ip ASC
                LIMIT 5
                """
            ).fetchall()

            latest_window = conn.execute(
                """
                SELECT MIN(timestamp) AS window_start, MAX(timestamp) AS window_end
                FROM (
                    SELECT timestamp
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 20
                )
                """
            ).fetchone()

        return AlertSummary(
            total_alerts=total_alerts,
            high_severity_alerts=high_severity_alerts,
            by_severity={row["severity"]: row["count"] for row in severity_rows},
            by_category={row["category"]: row["count"] for row in category_rows},
            top_source_ips=[TopSourceIP(source_ip=row["source_ip"], count=row["count"]) for row in source_rows],
            latest_window_start=parse_datetime(latest_window["window_start"]),
            latest_window_end=parse_datetime(latest_window["window_end"]),
        )

    def _update_heartbeat(self, service: str, timestamp: object, status: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO heartbeats (service, timestamp, status)
                VALUES (?, ?, ?)
                ON CONFLICT(service) DO UPDATE SET
                    timestamp = excluded.timestamp,
                    status = excluded.status
                """,
                (service, to_storage_timestamp(timestamp), status),
            )
            conn.commit()

    def _get_service_status(self, stale_seconds: int) -> dict[str, ServiceStatus]:
        status_map = {
            ServiceName.parser.value: ServiceStatus(service=ServiceName.parser, status=ServiceState.unknown),
            ServiceName.detector.value: ServiceStatus(service=ServiceName.detector, status=ServiceState.unknown),
        }

        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT service, timestamp, status FROM heartbeats").fetchall()

        for row in rows:
            service = row["service"]
            if service not in status_map:
                continue
            last_seen = parse_datetime(row["timestamp"])
            current_age = age_seconds(last_seen)
            stored_status = row["status"]

            if stored_status == "offline":
                effective_status = ServiceState.offline
            elif current_age is None:
                effective_status = ServiceState.unknown
            elif current_age > stale_seconds:
                effective_status = ServiceState.stale
            else:
                effective_status = ServiceState.online

            status_map[service] = ServiceStatus(
                service=ServiceName(service),
                status=effective_status,
                last_seen=last_seen,
                age_seconds=current_age,
            )

        return status_map

    def _set_setting(self, key: str, value: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            conn.commit()

    def _get_setting(self, key: str) -> str | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return str(row["value"])
