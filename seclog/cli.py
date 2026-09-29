"""Командная строка seclog: generate / run / report / produce / consume."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from seclog import generator
from seclog.detections import detect
from seclog.models import Event
from seclog.parsers import ParseError, parse_line
from seclog.storage import Storage


def parse_lines(lines: Iterable[str], errors: list[str]) -> Iterator[Event]:
    """Разобрать строки, складывая нераспознанные в errors вместо падения."""
    for line in lines:
        if not line.strip():
            continue
        try:
            yield parse_line(line)
        except ParseError as exc:
            errors.append(str(exc))


def process(events: Iterable[Event], storage: Storage) -> tuple[int, int]:
    """Сохранить события и алерты, вернуть (число событий, число алертов)."""
    events = sorted(events, key=lambda e: e.ts)
    alerts = list(detect(events))
    return storage.save_events(events), storage.save_alerts(alerts)


def open_storage(args: argparse.Namespace) -> Storage:
    """Открыть хранилище по аргументам CLI."""
    if args.pg_dsn:
        return Storage.postgres(args.pg_dsn)
    return Storage.sqlite(args.db)


def cmd_generate(args: argparse.Namespace) -> int:
    lines = generator.generate(n_normal=args.count, seed=args.seed)
    Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"записано {len(lines)} строк в {args.output}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    path = Path(args.input)
    if not path.is_file():
        print(f"ошибка: файл не найден: {path}", file=sys.stderr)
        return 1
    errors: list[str] = []
    events = list(parse_lines(path.read_text(encoding="utf-8").splitlines(), errors))
    storage = open_storage(args)
    n_events, n_alerts = process(events, storage)
    storage.close()
    print(f"событий: {n_events}, алертов: {n_alerts}, нераспознанных строк: {len(errors)}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    storage = open_storage(args)
    rows = storage.query(
        "SELECT ts, severity, rule, mitre, src_ip, description FROM alerts ORDER BY ts"
    )
    storage.close()
    if not rows:
        print("алертов нет")
        return 0
    for ts, sev, rule, mitre, ip, desc in rows:
        print(f"{ts}  [{sev.upper():6}] {rule:26} {mitre:10} {ip:16} {desc}")
    return 0


def cmd_produce(args: argparse.Namespace) -> int:
    from seclog.kafka_io import produce

    errors: list[str] = []
    lines = Path(args.input).read_text(encoding="utf-8").splitlines()
    n = produce(parse_lines(lines, errors), args.topic, args.bootstrap)
    print(f"отправлено в Kafka: {n}")
    return 0


def cmd_consume(args: argparse.Namespace) -> int:
    from seclog.kafka_io import consume

    storage = open_storage(args)
    n_events, n_alerts = process(consume(args.topic, args.bootstrap, args.group), storage)
    storage.close()
    print(f"из Kafka: событий {n_events}, алертов {n_alerts}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Собрать парсер аргументов."""
    p = argparse.ArgumentParser(prog="seclog", description="Security log pipeline")
    p.add_argument("--db", default="seclog.db", help="путь к SQLite (по умолчанию seclog.db)")
    p.add_argument("--pg-dsn", help="DSN PostgreSQL вместо SQLite")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="сгенерировать синтетические логи")
    g.add_argument("-o", "--output", default="sample.log")
    g.add_argument("-n", "--count", type=int, default=200)
    g.add_argument("--seed", type=int, default=42)
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("run", help="файл логов -> БД + детекты")
    r.add_argument("input")
    r.set_defaults(func=cmd_run)

    sub.add_parser("report", help="показать алерты").set_defaults(func=cmd_report)

    for name, func in (("produce", cmd_produce), ("consume", cmd_consume)):
        k = sub.add_parser(name, help=f"Kafka: {name}")
        if name == "produce":
            k.add_argument("input")
        else:
            k.add_argument("--group", default="seclog")
        k.add_argument("--topic", default="security-events")
        k.add_argument("--bootstrap", default="localhost:9092")
        k.set_defaults(func=func)
    return p


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI."""
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
