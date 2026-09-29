"""Отправка и чтение событий через Kafka (опционально, нужен confluent-kafka)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from seclog.models import Event


def _require_kafka():
    try:
        import confluent_kafka
    except ImportError as exc:
        raise RuntimeError("для Kafka установите: pip install confluent-kafka") from exc
    return confluent_kafka


def encode(event: Event) -> bytes:
    """Сериализовать событие в JSON-байты для Kafka."""
    return json.dumps(event.to_dict(), ensure_ascii=False).encode()


def decode(payload: bytes) -> Event:
    """Десериализовать событие из JSON-байтов."""
    return Event.from_dict(json.loads(payload))


def produce(events: Iterable[Event], topic: str, bootstrap: str) -> int:
    """Отправить события в топик; ключ — IP, чтобы события одного IP шли по порядку."""
    kafka = _require_kafka()
    producer = kafka.Producer({"bootstrap.servers": bootstrap})
    count = 0
    for event in events:
        producer.produce(topic, key=event.src_ip.encode(), value=encode(event))
        producer.poll(0)
        count += 1
    producer.flush()
    return count


def consume(topic: str, bootstrap: str, group: str, idle_timeout: float = 5.0) -> Iterator[Event]:
    """Читать события из топика, пока не наступит пауза idle_timeout секунд."""
    kafka = _require_kafka()
    consumer = kafka.Consumer(
        {"bootstrap.servers": bootstrap, "group.id": group, "auto.offset.reset": "earliest"}
    )
    consumer.subscribe([topic])
    try:
        while True:
            msg = consumer.poll(idle_timeout)
            if msg is None:
                return
            if msg.error():
                raise RuntimeError(f"ошибка Kafka: {msg.error()}")
            yield decode(msg.value())
    finally:
        consumer.close()
