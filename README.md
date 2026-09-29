# seclog-pipeline

![CI](https://github.com/RemigayloYegor/seclog-pipeline/actions/workflows/ci.yml/badge.svg)

Потоковый пайплайн для логов безопасности. Он разбирает логи `sshd` и `nginx`, передаёт
события через Kafka, сохраняет их в PostgreSQL/SQLite и находит атаки правилами
с разметкой по **MITRE ATT&CK**.

```
 raw logs ──► parsers ──► Kafka topic ──► consumer ──► detections ──► PostgreSQL / SQLite
 (sshd,        (regex →     security-       (группа       (скользящие     events + alerts
  nginx)        Event)      events,         seclog)        окна по IP)
                            key = src_ip
```

## Правила детектирования

| Правило | Логика | MITRE | Severity |
|---|---|---|---|
| `ssh_brute_force` | ≥5 неудачных SSH-входов с одного IP за 1 минуту (скользящее окно) | T1110.001 | medium |
| `success_after_brute_force` | успешный вход с IP, ранее помеченного как брутфорсер | T1078 | high |
| `web_scanner` | UA сканера (sqlmap, nikto, …) или ≥10 ответов 404 | T1595.002 | low |
| `sensitive_path_access` | ответ `200` на `/.env`, `/.git/`, `/phpmyadmin`, … | T1190 | high |

## Быстрый старт (без Docker)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

seclog generate -o sample.log       # синтетические логи с тремя сценариями атак
seclog run sample.log               # парсинг -> SQLite -> детекты
seclog report
```

```
2026-09-29T10:15:12  [MEDIUM] ssh_brute_force            T1110.001  185.220.101.7    5 неудачных SSH-входов за 0:01:00
2026-09-29T10:15:40  [HIGH  ] success_after_brute_force  T1078      185.220.101.7    успешный вход 'deploy' после брутфорса
2026-09-29T10:30:00  [LOW   ] web_scanner                T1595.002  45.155.205.99    User-Agent сканера: sqlmap
2026-09-29T10:45:00  [HIGH  ] sensitive_path_access      T1190      91.240.118.20    успешный доступ к /.env
```

## Полный режим: Kafka + PostgreSQL

```powershell
docker compose up -d
pip install -e ".[kafka,postgres]"
seclog produce sample.log
seclog --pg-dsn "postgresql://seclog:seclog@localhost:5432/seclog" consume
seclog --pg-dsn "postgresql://seclog:seclog@localhost:5432/seclog" report
```

## Архитектурные решения

- **Ключ сообщения Kafka — `src_ip`.** Все события одного IP попадают в одну партицию,
  и порядок сохраняется. Для оконных правил это критично.
- **Stateful-правила с `deque`.** Скользящее окно даёт O(1) на событие, поэтому весь лог
  не нужно держать в памяти.
- **Правила — классы с методом `feed(event)`.** Новое правило добавляется без изменения
  пайплайна, и каждое правило тестируется отдельно.
- **Один SQL для SQLite и Postgres.** Меняются только placeholder и тип PK. Благодаря этому
  тесты и CI работают без инфраструктуры.
- **Kafka и Postgres — опциональные зависимости.** Ядро написано на чистой стандартной
  библиотеке.
- **Нераспознанные строки не роняют пайплайн.** Они считаются и выводятся в статистике.

## Тесты

```powershell
ruff check .
pytest -q
```

Тесты покрывают парсеры (включая мусорный ввод), каждое правило (порог, окно, разделение по IP)
и прогон end-to-end: все четыре атаки находятся, на фоновом трафике ложных срабатываний нет.

## Дальнейшие шаги

- Дашборд в Grafana поверх таблицы `alerts`
- Экспорт алертов в формате Sigma / отправка в Telegram
- Обогащение IP через AbuseIPDB
