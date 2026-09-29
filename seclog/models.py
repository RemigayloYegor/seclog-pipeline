"""Модели данных пайплайна."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Event:
    """Нормализованное событие безопасности."""

    ts: datetime
    source: str  # ssh | web
    src_ip: str
    action: str  # login_failed | login_success | http_request
    user: str | None = None
    status: int | None = None
    path: str | None = None
    user_agent: str | None = None
    raw: str = ""

    def to_dict(self) -> dict:
        """Вернуть событие в виде словаря с ISO-временем."""
        data = asdict(self)
        data["ts"] = self.ts.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Event:
        """Собрать событие из словаря (обратная операция к to_dict)."""
        return cls(**{**data, "ts": datetime.fromisoformat(data["ts"])})


@dataclass(frozen=True)
class Alert:
    """Срабатывание правила детектирования."""

    ts: datetime
    rule: str
    severity: str  # low | medium | high
    src_ip: str
    mitre: str  # идентификатор техники MITRE ATT&CK
    description: str
    evidence: dict = field(default_factory=dict)
