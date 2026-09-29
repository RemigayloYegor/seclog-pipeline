from seclog import generator
from seclog.cli import main, parse_lines, process
from seclog.kafka_io import decode, encode
from seclog.storage import Storage


def test_generator_is_deterministic():
    assert generator.generate(seed=1) == generator.generate(seed=1)


def test_end_to_end_finds_all_attacks():
    errors: list[str] = []
    events = list(parse_lines(generator.generate(), errors))
    storage = Storage.sqlite()
    n_events, n_alerts = process(events, storage)
    assert errors == []
    assert n_events == len(events)
    rules = {r for (r,) in storage.query("SELECT rule FROM alerts")}
    assert rules == {
        "ssh_brute_force",
        "success_after_brute_force",
        "web_scanner",
        "sensitive_path_access",
    }
    # Фоновый трафик из 10.0.0.0/24 не должен давать алертов
    assert not storage.query("SELECT 1 FROM alerts WHERE src_ip LIKE '10.0.0.%'")


def test_parse_lines_collects_errors():
    errors: list[str] = []
    assert list(parse_lines(["garbage", ""], errors)) == []
    assert len(errors) == 1


def test_kafka_serialization_roundtrip():
    event = next(iter(parse_lines(generator.generate(n_normal=5), [])))
    assert decode(encode(event)) == event


def test_cli_generate_run_report(tmp_path, capsys):
    log, db = tmp_path / "s.log", tmp_path / "s.db"
    assert main(["generate", "-o", str(log)]) == 0
    assert main(["--db", str(db), "run", str(log)]) == 0
    assert main(["--db", str(db), "report"]) == 0
    out = capsys.readouterr().out
    assert "T1078" in out and "185.220.101.7" in out


def test_cli_missing_file(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "x.db"), "run", str(tmp_path / "nope.log")]) == 1
    assert "не найден" in capsys.readouterr().err
