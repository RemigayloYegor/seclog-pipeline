from datetime import datetime, timedelta

from seclog.detections import (
    SensitivePathProbe,
    SshBruteForce,
    SuccessAfterBruteForce,
    WebScanner,
    detect,
)
from seclog.models import Event

T0 = datetime(2026, 9, 29, 10, 0, 0)


def ssh(sec: int, ip: str = "6.6.6.6", ok: bool = False) -> Event:
    action = "login_success" if ok else "login_failed"
    return Event(ts=T0 + timedelta(seconds=sec), source="ssh", src_ip=ip, action=action, user="u")


def web(ip: str = "7.7.7.7", path: str = "/", status: int = 200, ua: str = "Mozilla") -> Event:
    return Event(ts=T0, source="web", src_ip=ip, action="http_request",
                 status=status, path=path, user_agent=ua)


def test_brute_force_triggers_once_at_threshold():
    rule = SshBruteForce(threshold=5)
    alerts = [a for i in range(10) for a in rule.feed(ssh(i))]
    assert len(alerts) == 1
    assert alerts[0].mitre == "T1110.001"


def test_brute_force_below_threshold():
    rule = SshBruteForce(threshold=5)
    assert not [a for i in range(4) for a in rule.feed(ssh(i))]


def test_brute_force_respects_window():
    # Попытки раз в 30 секунд — в минутное окно попадает не больше трёх
    rule = SshBruteForce(threshold=5, window=timedelta(minutes=1))
    assert not [a for i in range(10) for a in rule.feed(ssh(i * 30))]


def test_brute_force_per_ip():
    rule = SshBruteForce(threshold=3)
    alerts = [a for i in range(6) for a in rule.feed(ssh(i, ip=f"1.1.1.{i % 2}"))]
    assert {a.src_ip for a in alerts} == {"1.1.1.0", "1.1.1.1"}


def test_success_after_brute_force():
    brute = SshBruteForce(threshold=3)
    follow = SuccessAfterBruteForce(brute)
    events = [ssh(i) for i in range(3)] + [ssh(10, ok=True)]
    alerts = list(detect(events, [brute, follow]))
    assert [a.rule for a in alerts] == ["ssh_brute_force", "success_after_brute_force"]
    assert alerts[1].severity == "high"


def test_success_without_brute_force_is_quiet():
    brute = SshBruteForce()
    assert not list(detect([ssh(0, ok=True)], [brute, SuccessAfterBruteForce(brute)]))


def test_web_scanner_by_user_agent():
    alerts = WebScanner().feed(web(ua="sqlmap/1.8"))
    assert alerts and "sqlmap" in alerts[0].description


def test_web_scanner_by_404_count():
    rule = WebScanner(threshold_404=3)
    alerts = [a for _ in range(5) for a in rule.feed(web(status=404))]
    assert len(alerts) == 1


def test_sensitive_path_only_on_200():
    rule = SensitivePathProbe()
    assert rule.feed(web(path="/.env", status=200))
    assert not rule.feed(web(path="/.env", status=404))
    assert not rule.feed(web(path="/index.html", status=200))
