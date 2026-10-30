import json
import pytest

from app.services.log_parser import (
    normalize_level,
    parse_csv_content,
    parse_json_content,
    parse_log_content,
    parse_single_text_line,
    redact_secrets,
)


def test_redact_secrets():
    raw1 = "Login failed for user admin with password=SuperSecretPassword123 from 10.0.0.1"
    clean1 = redact_secrets(raw1)
    assert "SuperSecretPassword123" not in clean1
    assert "[REDACTED_SECRET]" in clean1

    raw2 = "HTTP Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokencontent"
    clean2 = redact_secrets(raw2)
    assert "eyJhbGci" not in clean2
    assert "Bearer [REDACTED_TOKEN]" in clean2

    raw3 = '{"api_key": "abcd1234efgh5678ijkl", "status": "active"}'
    clean3 = redact_secrets(raw3)
    assert "abcd1234efgh5678ijkl" not in clean3
    assert "[REDACTED_API_KEY]" in clean3


def test_normalize_level():
    assert normalize_level("error") == "ERROR"
    assert normalize_level("err") == "ERROR"
    assert normalize_level("warn") == "WARNING"
    assert normalize_level("warning") == "WARNING"
    assert normalize_level("crit") == "CRITICAL"
    assert normalize_level("notice") == "INFO"
    assert normalize_level(1) == "CRITICAL"
    assert normalize_level(3) == "WARNING"


def test_parse_syslog_rfc3164():
    line = "Oct 21 21:04:10 internal-gateway sshd[28410]: Failed password for invalid user admin from 192.168.1.105 port 54101 ssh2"
    event = parse_single_text_line(line)
    assert event["source"] == "sshd"
    assert event["level"] in ["ERROR", "WARNING"]
    assert "Failed password" in event["message"]
    assert "192.168.1.105" in event["message"]


def test_parse_syslog_rfc5424():
    line = "<165>1 2026-10-21T21:04:14.003Z firewall.corp ids 1234 MSG-404 - Network anomaly connection refused"
    event = parse_single_text_line(line)
    assert event["source"] == "ids"
    assert event["event_id"] == "MSG-404"
    assert "connection refused" in event["message"]


def test_parse_json_content():
    json_lines = (
        '{"timestamp": "2026-10-21T10:00:00Z", "level": "error", "source": "Auth", "message": "Logon failure 4625"}\n'
        '{"timestamp": "2026-10-21T10:00:05Z", "level": "info", "source": "System", "message": "Service started"}'
    )
    events = parse_json_content(json_lines)
    assert len(events) == 2
    assert events[0]["level"] == "ERROR"
    assert events[0]["source"] == "Auth"
    assert events[0]["event_id"] == "4625"
    assert events[1]["level"] == "INFO"


def test_parse_csv_content():
    csv_data = "timestamp,level,source,message\n2026-10-21 12:00:00,WARNING,Defender,Threat detected trojan\n"
    events = parse_csv_content(csv_data)
    assert len(events) == 1
    assert events[0]["level"] == "WARNING"
    assert events[0]["source"] == "Defender"
    assert "Threat detected" in events[0]["message"]


def test_parse_log_content_sample():
    sample = (
        "Oct 21 21:04:10 internal-gateway sshd[28410]: Failed password for invalid user admin from 192.168.1.105 port 54101 ssh2\n"
        "Oct 21 21:04:15 internal-gateway sshd[28412]: Failed password for invalid user admin from 192.168.1.105 port 54102 ssh2\n"
    )
    events = parse_log_content(sample, filename="auth.log")
    assert len(events) == 2
    assert events[0]["source"] == "sshd"
