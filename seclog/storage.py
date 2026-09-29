"""Хранилище событий и алертов: SQLite (по умолчанию) или PostgreSQL."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable

from seclog.models import Alert, Event

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS events (
        id {pk},
        ts TIMESTAMP NOT NULL,
        source TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        action TEXT NOT NULL,
        username TEXT,
        status INTEGER,
        path TEXT,
        user_agent TEXT,
        raw TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events (src_ip, ts)",
    """CREATE TABLE IF NOT EXISTS alerts (
        id {pk},
        ts TIMESTAMP NOT NULL,
        rule TEXT NOT NULL,
        severity TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        mitre TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT
    )""",
]


class Storage:
    """Обёртка над DB-API соединением с единым SQL для SQLite и Postgres."""

    def __init__(self, conn, placeholder: str, pk: str) -> None:
        self.conn = conn
        self.ph = placeholder
        cur = conn.cursor()
        for stmt in SCHEMA:
            cur.execute(stmt.format(pk=pk))
        conn.commit()

    @classmethod
    def sqlite(cls, path: str = ":memory:") -> Storage:
        """Открыть SQLite-хранилище."""
        return cls(sqlite3.connect(path), "?", "INTEGER PRIMARY KEY AUTOINCREMENT")

    @classmethod
    def postgres(cls, dsn: str) -> Storage:
        """Открыть PostgreSQL-хранилище (нужен пакет psycopg)."""
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("для Postgres установите: pip install psycopg[binary]") from exc
        return cls(psycopg.connect(dsn), "%s", "BIGSERIAL PRIMARY KEY")

    def _insert(self, table: str, cols: tuple[str, ...], rows: list[tuple]) -> int:
        if not rows:
            return 0
        marks = ", ".join([self.ph] * len(cols))
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({marks})"
        cur = self.conn.cursor()
        cur.executemany(sql, rows)
        self.conn.commit()
        return len(rows)

    def save_events(self, events: Iterable[Event]) -> int:
        """Сохранить события пачкой, вернуть количество."""
        cols = ("ts", "source", "src_ip", "action", "username", "status", "path",
                "user_agent", "raw")
        rows = [
            (e.ts.isoformat(), e.source, e.src_ip, e.action, e.user, e.status, e.path,
             e.user_agent, e.raw)
            for e in events
        ]
        return self._insert("events", cols, rows)

    def save_alerts(self, alerts: Iterable[Alert]) -> int:
        """Сохранить алерты пачкой, вернуть количество."""
        cols = ("ts", "rule", "severity", "src_ip", "mitre", "description", "evidence")
        rows = [
            (a.ts.isoformat(), a.rule, a.severity, a.src_ip, a.mitre, a.description,
             json.dumps(a.evidence, ensure_ascii=False))
            for a in alerts
        ]
        return self._insert("alerts", cols, rows)

    def query(self, sql: str, params: tuple = ()) -> list[tuple]:
        """Выполнить SELECT и вернуть строки."""
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()

    def close(self) -> None:
        """Закрыть соединение."""
        self.conn.close()
