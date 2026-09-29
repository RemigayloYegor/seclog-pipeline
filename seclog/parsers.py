"""Парсеры сырых логов sshd и nginx в нормализованные события."""

from __future__ import annotations

import re
from datetime import datetime

from seclog.models import Event

# Пример: 2026-09-29T10:00:01 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2
_SSH_RE = re.compile(
    r"^(?P<ts>\S+) sshd\[\d+\]: (?P<result>Failed|Accepted) password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

# Combined log format nginx
_WEB_RE = re.compile(
    r'^(?P<ip>[\d.]+) - \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \d+ "[^"]*" "(?P<ua>[^"]*)"'
)
_WEB_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class ParseError(ValueError):
    """Строку лога не удалось разобрать."""


def parse_ssh(line: str) -> Event:
    """Разобрать строку auth.log от sshd."""
    m = _SSH_RE.match(line.strip())
    if not m:
        raise ParseError(f"не похоже на строку sshd: {line[:80]!r}")
    action = "login_failed" if m["result"] == "Failed" else "login_success"
    return Event(
        ts=datetime.fromisoformat(m["ts"]),
        source="ssh",
        src_ip=m["ip"],
        action=action,
        user=m["user"],
        raw=line.strip(),
    )


def parse_web(line: str) -> Event:
    """Разобрать строку access.log nginx (combined)."""
    m = _WEB_RE.match(line.strip())
    if not m:
        raise ParseError(f"не похоже на строку nginx: {line[:80]!r}")
    # Приводим к naive-времени, чтобы сравнивать с событиями sshd
    ts = datetime.strptime(m["ts"], _WEB_TS_FORMAT).replace(tzinfo=None)
    return Event(
        ts=ts,
        source="web",
        src_ip=m["ip"],
        action="http_request",
        status=int(m["status"]),
        path=m["path"],
        user_agent=m["ua"],
        raw=line.strip(),
    )


def parse_line(line: str) -> Event:
    """Определить тип строки и разобрать её подходящим парсером."""
    if " sshd[" in line:
        return parse_ssh(line)
    return parse_web(line)
