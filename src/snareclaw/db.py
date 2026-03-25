"""SQLite event store for SnareClaw alerts and audit history."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path.home() / ".snareclaw" / "events.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    severity    TEXT    NOT NULL,
    rule_id     TEXT    NOT NULL,
    package     TEXT,
    version     TEXT,
    message     TEXT    NOT NULL,
    details     TEXT,
    resolved    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_package ON events(package);

CREATE TABLE IF NOT EXISTS trust (
    package     TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    trusted_at  REAL    NOT NULL,
    reason      TEXT,
    PRIMARY KEY (package, version)
);
"""


@dataclass
class Event:
    severity: str
    rule_id: str
    message: str
    package: str | None = None
    version: str | None = None
    details: dict[str, Any] | None = None
    timestamp: float = field(default_factory=time.time)
    id: int | None = None
    resolved: bool = False


class EventStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def record(self, event: Event) -> int:
        cur = self._conn.execute(
            "INSERT INTO events (timestamp, severity, rule_id, package, version, message, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.timestamp,
                event.severity,
                event.rule_id,
                event.package,
                event.version,
                event.message,
                json.dumps(event.details) if event.details else None,
            ),
        )
        self._conn.commit()
        event.id = cur.lastrowid
        return cur.lastrowid  # type: ignore[return-value]

    def query(
        self,
        *,
        severity: str | None = None,
        package: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[Event]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if package:
            clauses.append("package = ?")
            params.append(package)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = " AND ".join(clauses)
        sql = f"SELECT * FROM events {'WHERE ' + where if where else ''} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def trust_package(self, package: str, version: str, reason: str | None = None) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO trust (package, version, trusted_at, reason) VALUES (?, ?, ?, ?)",
            (package, version, time.time(), reason),
        )
        self._conn.commit()

    def is_trusted(self, package: str, version: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM trust WHERE package = ? AND version = ?", (package, version)
        ).fetchone()
        return row is not None

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            id=row["id"],
            timestamp=row["timestamp"],
            severity=row["severity"],
            rule_id=row["rule_id"],
            package=row["package"],
            version=row["version"],
            message=row["message"],
            details=json.loads(row["details"]) if row["details"] else None,
            resolved=bool(row["resolved"]),
        )
