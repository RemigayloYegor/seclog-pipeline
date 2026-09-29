from datetime import datetime

import pytest

from seclog.parsers import ParseError, parse_line, parse_ssh, parse_web

SSH_FAIL = "2026-09-29T10:00:01 sshd[123]: Failed password for root from 1.2.3.4 port 5000 ssh2"
SSH_INVALID = (
    "2026-09-29T10:00:02 sshd[123]: Failed password for invalid user oracle "
    "from 1.2.3.4 port 5000 ssh2"
)
SSH_OK = "2026-09-29T10:00:03 sshd[9]: Accepted password for bob from 10.0.0.5 port 1 ssh2"
WEB = '8.8.8.8 - - [29/Sep/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 200 12 "-" "curl/8.5"'


def test_parse_ssh_failed():
    e = parse_ssh(SSH_FAIL)
    assert (e.source, e.action, e.user, e.src_ip) == ("ssh", "login_failed", "root", "1.2.3.4")
    assert e.ts == datetime(2026, 9, 29, 10, 0, 1)


def test_parse_ssh_invalid_user():
    assert parse_ssh(SSH_INVALID).user == "oracle"


def test_parse_ssh_success():
    assert parse_ssh(SSH_OK).action == "login_success"


def test_parse_web():
    e = parse_web(WEB)
    assert (e.src_ip, e.path, e.status, e.user_agent) == ("8.8.8.8", "/.env", 200, "curl/8.5")
    assert e.ts.tzinfo is None


def test_parse_line_dispatch():
    assert parse_line(SSH_FAIL).source == "ssh"
    assert parse_line(WEB).source == "web"


@pytest.mark.parametrize("bad", ["", "garbage", "sshd[1]: something else", "1.2.3.4 - - [bad]"])
def test_parse_garbage_raises(bad):
    with pytest.raises(ParseError):
        parse_line(bad)
