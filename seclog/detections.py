"""Потоковые правила детектирования с привязкой к MITRE ATT&CK."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import timedelta

from seclog.models import Alert, Event

SCANNER_UA_MARKERS = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wpscan")
SENSITIVE_PATHS = ("/.env", "/.git/", "/wp-admin", "/phpmyadmin", "/etc/passwd", "/admin")


class Rule:
    """Базовый класс правила: получает события по одному, возвращает алерты."""

    name = "base"

    def feed(self, event: Event) -> list[Alert]:
        """Обработать событие и вернуть сработавшие алерты."""
        raise NotImplementedError


class SshBruteForce(Rule):
    """N неудачных входов с одного IP за окно времени (T1110)."""

    name = "ssh_brute_force"

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=1)) -> None:
        self.threshold = threshold
        self.window = window
        self._fails: dict[str, deque] = defaultdict(deque)
        self._alerted: set[str] = set()

    def feed(self, event: Event) -> list[Alert]:
        """Считать неудачные входы в скользящем окне."""
        if event.source != "ssh" or event.action != "login_failed":
            return []
        q = self._fails[event.src_ip]
        q.append(event.ts)
        # Выкидываем попытки, вышедшие за окно
        while q and event.ts - q[0] > self.window:
            q.popleft()
        if len(q) >= self.threshold and event.src_ip not in self._alerted:
            self._alerted.add(event.src_ip)
            return [
                Alert(
                    ts=event.ts,
                    rule=self.name,
                    severity="medium",
                    src_ip=event.src_ip,
                    mitre="T1110.001",
                    description=f"{len(q)} неудачных SSH-входов за {self.window}",
                    evidence={"attempts": len(q)},
                )
            ]
        return []

    def is_bruteforcer(self, ip: str) -> bool:
        """Был ли IP ранее помечен как брутфорсер."""
        return ip in self._alerted


class SuccessAfterBruteForce(Rule):
    """Успешный вход с IP, который до этого брутфорсил (T1078)."""

    name = "success_after_brute_force"

    def __init__(self, brute: SshBruteForce) -> None:
        self.brute = brute

    def feed(self, event: Event) -> list[Alert]:
        """Сработать на успешный вход от известного брутфорсера."""
        if event.action == "login_success" and self.brute.is_bruteforcer(event.src_ip):
            return [
                Alert(
                    ts=event.ts,
                    rule=self.name,
                    severity="high",
                    src_ip=event.src_ip,
                    mitre="T1078",
                    description=f"успешный вход '{event.user}' после брутфорса",
                    evidence={"user": event.user},
                )
            ]
        return []


class WebScanner(Rule):
    """Сканер по User-Agent или много 404 на чувствительные пути (T1595)."""

    name = "web_scanner"

    def __init__(self, threshold_404: int = 10) -> None:
        self.threshold_404 = threshold_404
        self._404: dict[str, int] = defaultdict(int)
        self._alerted: set[str] = set()

    def feed(self, event: Event) -> list[Alert]:
        """Проверить UA и счётчик 404 для IP."""
        if event.source != "web" or event.src_ip in self._alerted:
            return []
        ua = (event.user_agent or "").lower()
        marker = next((m for m in SCANNER_UA_MARKERS if m in ua), None)
        if event.status == 404:
            self._404[event.src_ip] += 1
        reason = None
        if marker:
            reason = f"User-Agent сканера: {marker}"
        elif self._404[event.src_ip] >= self.threshold_404:
            reason = f"{self._404[event.src_ip]} ответов 404"
        if reason is None:
            return []
        self._alerted.add(event.src_ip)
        return [
            Alert(
                ts=event.ts,
                rule=self.name,
                severity="low",
                src_ip=event.src_ip,
                mitre="T1595.002",
                description=reason,
                evidence={"path": event.path, "user_agent": event.user_agent},
            )
        ]


class SensitivePathProbe(Rule):
    """Обращение к чувствительным путям с ответом 200 (T1190)."""

    name = "sensitive_path_access"

    def feed(self, event: Event) -> list[Alert]:
        """Сработать на успешный доступ к чувствительному пути."""
        if event.source != "web" or event.status != 200 or not event.path:
            return []
        if any(event.path.startswith(p) for p in SENSITIVE_PATHS):
            return [
                Alert(
                    ts=event.ts,
                    rule=self.name,
                    severity="high",
                    src_ip=event.src_ip,
                    mitre="T1190",
                    description=f"успешный доступ к {event.path}",
                    evidence={"path": event.path},
                )
            ]
        return []


def default_rules() -> list[Rule]:
    """Набор правил по умолчанию."""
    brute = SshBruteForce()
    return [brute, SuccessAfterBruteForce(brute), WebScanner(), SensitivePathProbe()]


def detect(events: Iterable[Event], rules: list[Rule] | None = None) -> Iterator[Alert]:
    """Прогнать поток событий (в порядке времени) через правила."""
    rules = rules if rules is not None else default_rules()
    for event in events:
        for rule in rules:
            yield from rule.feed(event)
