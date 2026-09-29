"""Генератор синтетических логов sshd и nginx с внедрёнными атаками."""

from __future__ import annotations

import random
from datetime import datetime, timedelta

NORMAL_USERS = ("alice", "bob", "deploy")
NORMAL_PATHS = ("/", "/index.html", "/api/items", "/login", "/static/app.js")
NORMAL_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0"


def _ssh(ts: datetime, ok: bool, user: str, ip: str, rng: random.Random) -> str:
    result = "Accepted" if ok else "Failed"
    pid = rng.randint(1000, 9999)
    port = rng.randint(30000, 65000)
    return f"{ts.isoformat()} sshd[{pid}]: {result} password for {user} from {ip} port {port} ssh2"


def _web(ts: datetime, ip: str, path: str, status: int, ua: str) -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def generate(n_normal: int = 200, seed: int = 42, start: datetime | None = None) -> list[str]:
    """Сгенерировать строки логов: фон + сценарии атак, отсортированные по времени."""
    rng = random.Random(seed)
    start = start or datetime(2026, 9, 29, 10, 0, 0)
    items: list[tuple[datetime, str]] = []

    # Фоновый легитимный трафик
    for _ in range(n_normal):
        ts = start + timedelta(seconds=rng.randint(0, 3600))
        ip = f"10.0.0.{rng.randint(2, 50)}"
        if rng.random() < 0.2:
            items.append((ts, _ssh(ts, rng.random() > 0.1, rng.choice(NORMAL_USERS), ip, rng)))
        else:
            path = rng.choice(NORMAL_PATHS)
            items.append((ts, _web(ts, ip, path, 200, NORMAL_UA)))

    # Атака 1: SSH-брутфорс с последующим успешным входом
    attacker = "185.220.101.7"
    t = start + timedelta(minutes=15)
    for i in range(12):
        ts = t + timedelta(seconds=i * 3)
        items.append((ts, _ssh(ts, False, rng.choice(("root", "admin", "test")), attacker, rng)))
    ts = t + timedelta(seconds=40)
    items.append((ts, _ssh(ts, True, "deploy", attacker, rng)))

    # Атака 2: веб-сканер (sqlmap) и перебор директорий
    scanner = "45.155.205.99"
    t = start + timedelta(minutes=30)
    for i, path in enumerate(("/.git/config", "/wp-admin", "/phpmyadmin", "/backup.zip")):
        ts = t + timedelta(seconds=i)
        items.append((ts, _web(ts, scanner, path, 404, "sqlmap/1.8#stable")))

    # Атака 3: утечка .env
    leaker = "91.240.118.20"
    ts = start + timedelta(minutes=45)
    items.append((ts, _web(ts, leaker, "/.env", 200, "curl/8.5.0")))

    items.sort(key=lambda x: x[0])
    return [line for _, line in items]
