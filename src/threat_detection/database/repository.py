"""Small SQLite history store; raw network records are never persisted."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "outputs" / "detections.sqlite3"


class DetectionRepository:
    """Persist minimal prediction/alert metadata using Python's SQLite support."""

    def __init__(self, database_path: str | Path = DEFAULT_DATABASE_PATH):
        self.database_path = Path(database_path).expanduser()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS detections (
                    event_id TEXT PRIMARY KEY, alert_id TEXT, timestamp TEXT NOT NULL,
                    predicted_label INTEGER NOT NULL, prediction TEXT NOT NULL,
                    confidence REAL, attack_probability REAL, severity TEXT,
                    detection_method TEXT NOT NULL, source_type TEXT NOT NULL,
                    input_summary TEXT NOT NULL
                )"""
            )

    def add_events(self, events: list[dict[str, Any]]) -> None:
        """Insert a batch atomically; summary contains keys only, never values."""
        if not events:
            return
        values = [
            (
                event["event_id"], event.get("alert_id"), event["timestamp"],
                int(event["predicted_label"]), event["prediction"],
                event.get("confidence"), event.get("attack_probability"),
                event.get("severity"), event["detection_method"], event["source_type"],
                json.dumps(event.get("input_summary", {}), sort_keys=True),
            )
            for event in events
        ]
        with self._connect() as connection:
            connection.executemany(
                """INSERT INTO detections (
                    event_id, alert_id, timestamp, predicted_label, prediction,
                    confidence, attack_probability, severity, detection_method,
                    source_type, input_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                values,
            )

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000.")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        results = [dict(row) for row in rows]
        for event in results:
            event["input_summary"] = json.loads(event["input_summary"])
        return results

    def count_events(self) -> int:
        """Return the total persisted history count, independent of page limit."""
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM detections").fetchone()
        return int(row["total"])