import pytest
from app.services.severity import classify_severity, severity_classifier


def test_base_levels():
    # Low base
    res_info = classify_severity({"level": "INFO", "message": "Normal system event"})
    assert res_info["severity"] == "low"
    assert res_info["score"] == 20
    assert any("Base severity from native level" in r for r in res_info["reasons"])

    # Medium base
    res_warn = classify_severity({"level": "WARNING", "message": "Disk space low"})
    assert res_warn["severity"] == "medium"
    assert res_warn["score"] == 50

    # High base
    res_err = classify_severity({"level": "ERROR", "message": "Connection timed out"})
    assert res_err["severity"] == "high"
    assert res_err["score"] == 75

    # Critical base
    res_crit = classify_severity({"level": "CRITICAL", "message": "Kernel panic"})
    assert res_crit["severity"] == "critical"
    assert res_crit["score"] == 95


def test_event_4625_single_vs_burst_escalation():
    single_event = {
        "event_id": "4625",
        "level": "INFO",
        "message": "Failed password for user admin from 192.168.1.100",
    }
    # Single attempt without context -> medium
    res_single = classify_severity(single_event)
    assert res_single["severity"] == "medium"
    assert any("4625" in r or "Failed authentication" in r for r in res_single["reasons"])

    # Context with 6 attempts from same IP -> escalated to HIGH
    context = [
        {
            "event_id": "4625",
            "message": f"Failed password for user admin from 192.168.1.100 port {50000+i}",
        }
        for i in range(6)
    ]
    res_burst = classify_severity(single_event, context_events=context)
    assert res_burst["severity"] == "high"
    assert res_burst["score"] >= 80
    assert any("Repeated authentication failure burst" in r for r in res_burst["reasons"])


def test_account_compromise_escalation_critical():
    event = {
        "event_id": "4625",
        "level": "INFO",
        "message": "Failed password for user backup_svc from 10.0.0.50",
    }
    context = [
        {"event_id": "4625", "message": "Failed password for user backup_svc from 10.0.0.50"}
        for _ in range(4)
    ] + [
        {"event_id": "4624", "message": "Accepted password for user backup_svc from 10.0.0.50"}
    ]
    res = classify_severity(event, context_events=context)
    assert res["severity"] == "critical"
    assert res["score"] >= 95
    assert any("Possible Account Compromise" in r for r in res["reasons"])


def test_log_cleared_critical():
    evt_1102 = {"event_id": "1102", "level": "INFO", "message": "The audit log was cleared"}
    res_1102 = classify_severity(evt_1102)
    assert res_1102["severity"] == "critical"

    evt_104 = {"event_id": "104", "level": "INFO", "message": "The system log file was cleared"}
    res_104 = classify_severity(evt_104)
    assert res_104["severity"] == "critical"


def test_persistence_high():
    evt_svc = {
        "event_id": "7045",
        "level": "INFO",
        "message": "A service was installed in the system: backdoor.exe",
    }
    res_svc = classify_severity(evt_svc)
    assert res_svc["severity"] == "high"

    evt_task = {
        "event_id": "4698",
        "level": "INFO",
        "message": "A scheduled task was created: EvilTask",
    }
    res_task = classify_severity(evt_task)
    assert res_task["severity"] == "high"


def test_privilege_escalation_high():
    evt = {
        "event_id": "4732",
        "level": "INFO",
        "message": "A member was added to a security-enabled local group: administrators",
    }
    res = classify_severity(evt)
    assert res["severity"] == "high"


def test_defender_malware_and_disabled():
    evt_mal = {
        "event_id": "1116",
        "level": "INFO",
        "message": "Microsoft Defender Antivirus has detected malware: Trojan:Win32/Wacatac",
    }
    res_mal = classify_severity(evt_mal)
    assert res_mal["severity"] == "high"

    evt_disabled = {
        "event_id": "5001",
        "level": "WARNING",
        "message": "Microsoft Defender Antivirus real-time protection was disabled",
    }
    res_disabled = classify_severity(evt_disabled)
    assert res_disabled["severity"] == "critical"


def test_suspicious_powershell_high():
    evt = {
        "event_id": "4104",
        "level": "INFO",
        "message": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5n",
    }
    res = classify_severity(evt)
    assert res["severity"] == "high"


def test_firewall_and_reconnaissance():
    evt_fw = {
        "event_id": "2003",
        "level": "WARNING",
        "message": "Windows firewall rule changed: allow all inbound",
    }
    res_fw = classify_severity(evt_fw)
    assert res_fw["severity"] == "high"

    evt_scan = {
        "level": "INFO",
        "message": "connection refused on port 445 from 10.0.0.99",
    }
    res_scan = classify_severity(evt_scan)
    assert res_scan["severity"] == "medium"


def test_routine_noise_low():
    evt = {
        "event_id": "7036",
        "level": "INFO",
        "message": "The Windows Update service entered the running state.",
    }
    res = classify_severity(evt)
    assert res["severity"] == "low"


def test_correlation_with_finding():
    evt = {
        "id": "EVT-CORRELATED-01",
        "level": "INFO",
        "message": "Generic network ping",
    }
    findings = [
        {
            "id": "FND-1",
            "category": "malware",
            "title": "Confirmed Trojan Outbreak",
            "severity": "critical",
            "evidence": ["EVT-CORRELATED-01", "EVT-OTHER"],
        }
    ]
    res = classify_severity(evt, findings=findings)
    assert res["severity"] == "critical"
    assert any("Correlated with finding [malware]" in r for r in res["reasons"])


def test_escalation_never_lowers_severity():
    # If native level was ERROR (high) but rule was routine noise (low), severity stays HIGH
    evt = {
        "event_id": "7036",
        "level": "ERROR",
        "message": "The service entered the stopped state with unexpected code",
    }
    res = classify_severity(evt)
    assert res["severity"] == "high"


def test_severity_rules_summary():
    summary = severity_classifier.get_rules_summary()
    assert "levels_mapping" in summary
    assert "low" in summary["levels_mapping"]
    assert len(summary["rules"]) >= 8
