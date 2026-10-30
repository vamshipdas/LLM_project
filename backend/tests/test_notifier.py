"""
Tests for Critical Alert Email Notification System.
Covers:
- Trigger logic (critical triggers email, low/medium/high do not)
- Deduplication (same alert ID not resent)
- Cooldown and grouping (coalescing by source IP / category)
- Global rate limit (max 10 emails per hour)
- Security: HTML auto-escaping (preventing XSS/injection)
- Security: CRLF header injection prevention
- Security: Secret redaction in evidence and body
- SMTP retry logic with exponential backoff
- Missing SMTP_PASSWORD graceful fallback
- API endpoints: /test, /log, /settings, /status
"""

from datetime import datetime, timezone
import json
import smtplib
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import SessionLocal, init_db
from app.main import app, _seed
from app.models.db_models import NotificationLog, SystemSetting, Ticket, User, Role
from app.services.auth_service import create_access_token
from app.services.notifier import AlertNotifier, _sanitize_header_value


@pytest.fixture(autouse=True)
def clean_database():
    init_db()
    db = SessionLocal()
    try:
        db.query(NotificationLog).delete()
        db.query(SystemSetting).filter(SystemSetting.key == "notification_settings").delete()
        db.commit()
    finally:
        db.close()



@pytest.fixture(scope="module")
def setup_tokens():
    _seed()

    db = SessionLocal()
    admin = db.query(User).filter(User.username == "admin").first()
    analyst = db.query(User).filter(User.username == "analyst").first()
    admin_token = create_access_token(admin.username, admin.role.value)
    analyst_token = create_access_token(analyst.username, analyst.role.value)
    db.close()
    return {"admin_token": admin_token, "analyst_token": analyst_token}


@pytest.fixture
def clean_notifier():
    """Returns a fresh AlertNotifier instance with cleared in-memory state."""
    n = AlertNotifier()
    n._cooldown_tracker.clear()
    n._grouped_buffer.clear()
    n._sent_alert_ids.clear()
    n._hourly_send_timestamps.clear()
    return n


# -----------------------------------------------------------------------------
# 1. Trigger & Severity Filtering Tests
# -----------------------------------------------------------------------------

def test_critical_alert_triggers_email(clean_notifier):
    """Verify that a CRITICAL alert triggers SMTP delivery."""
    alert = {
        "id": "TKT-CRIT-001",
        "title": "Possible ransomware encryption activity",
        "severity": "critical",
        "what_happened": "Files are being encrypted rapidly on fileserver.",
        "why_it_matters": "Business disruption imminent.",
        "severity_reason": "Matches ransomware encryption behavior pattern.",
        "origin": {"ip": "198.51.100.22", "city": "Frankfurt", "country": "Germany"},
        "technical_details": {"target_host": "FS-01"},
    }

    with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-app-password"):
        instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = instance

        res = clean_notifier.send_critical_alert(alert)

        assert res["status"] == "sent"
        assert res["alert_id"] == "TKT-CRIT-001"
        assert instance.sendmail.called
        # Verify recipients
        _, to_addrs, _ = instance.sendmail.call_args[0]
        assert "dasvamshi8@gmail.com" in to_addrs


def test_non_critical_alerts_do_not_send(clean_notifier):
    """Verify low, medium, and high alerts send nothing when min_severity is critical."""
    for sev in ["low", "medium", "high"]:
        alert = {
            "id": f"TKT-TEST-{sev.upper()}",
            "title": f"Test {sev} alert",
            "severity": sev,
            "what_happened": "Routine observation.",
            "why_it_matters": "Low risk.",
            "severity_reason": "Baseline severity rule.",
            "origin": {"ip": "10.0.0.1"},
        }
        with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-app-password"):
            instance = MagicMock()
            mock_smtp.return_value.__enter__.return_value = instance

            res = clean_notifier.send_critical_alert(alert)
            assert res["status"] == "skipped"
            assert res["reason"] == "below_min_severity"
            assert not instance.sendmail.called


# -----------------------------------------------------------------------------
# 2. Spam Protection: Deduplication, Cooldown/Grouping, Rate Limiting
# -----------------------------------------------------------------------------

def test_deduplication_prevents_duplicate_sends(clean_notifier):
    """Verify same alert ID is not sent more than once."""
    alert = {
        "id": "TKT-DEDUP-001",
        "title": "Unauthorized Domain Admin creation",
        "severity": "critical",
        "what_happened": "New admin created.",
        "why_it_matters": "Privilege escalation.",
        "origin": {"ip": "203.0.113.10"},
    }

    with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-app-password"):
        instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = instance

        res1 = clean_notifier.send_critical_alert(alert)
        assert res1["status"] == "sent"
        assert instance.sendmail.call_count == 1

        # Second send with identical alert ID
        res2 = clean_notifier.send_critical_alert(alert)
        assert res2["status"] == "skipped"
        assert res2["reason"] in ("duplicate_alert_id", "already_sent_in_db")
        # Should NOT have sent another email
        assert instance.sendmail.call_count == 1


def test_cooldown_and_grouping_by_ip(clean_notifier):
    """Verify alerts from same source IP within cooldown window are grouped/skipped."""
    ip = "203.0.113.88"
    alert1 = {
        "id": "TKT-CD-001",
        "title": "Brute Force SSH Attack",
        "severity": "critical",
        "what_happened": "1000 failed logins.",
        "why_it_matters": "Credentials may be breached.",
        "origin": {"ip": ip},
    }
    alert2 = {
        "id": "TKT-CD-002",
        "title": "Subsequent Malicious Login",
        "severity": "critical",
        "what_happened": "Successful auth after brute force.",
        "why_it_matters": "Compromised account.",
        "origin": {"ip": ip},
    }

    with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-app-password"):
        instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = instance

        res1 = clean_notifier.send_critical_alert(alert1)
        assert res1["status"] == "sent"
        assert instance.sendmail.call_count == 1

        # Immediate second alert from the same IP
        res2 = clean_notifier.send_critical_alert(alert2)
        assert res2["status"] == "skipped"
        assert res2["reason"] == "cooldown_active"
        assert res2["grouped_count"] == 2
        # No extra email should have been sent
        assert instance.sendmail.call_count == 1


def test_global_rate_limit(clean_notifier):
    """Verify maximum of 10 emails per hour rate limit."""
    with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-app-password"):
        instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = instance

        # Send 10 distinct alerts from different IPs
        for i in range(10):
            a = {
                "id": f"TKT-RATE-{i}",
                "title": f"Critical Event {i}",
                "severity": "critical",
                "what_happened": "Something critical.",
                "why_it_matters": "Risk.",
                "origin": {"ip": f"198.51.100.{i+1}"},
            }
            res = clean_notifier.send_critical_alert(a)
            assert res["status"] == "sent"

        # 11th alert within the hour must be rate limited
        a_11 = {
            "id": "TKT-RATE-11",
            "title": "Critical Event 11",
            "severity": "critical",
            "what_happened": "Another event.",
            "why_it_matters": "Risk.",
            "origin": {"ip": "198.51.100.99"},
        }
        res_11 = clean_notifier.send_critical_alert(a_11)
        assert res_11["status"] == "skipped"
        assert res_11["reason"] == "rate_limit_exceeded"
        assert instance.sendmail.call_count == 10


# -----------------------------------------------------------------------------
# 3. Security: HTML Escaping, Header Injection, Secret Redaction
# -----------------------------------------------------------------------------

def test_html_autoescaping_in_email(clean_notifier):
    """Verify that malicious XSS or prompt injection payloads are HTML-escaped."""
    malicious_title = "<script>alert('XSS')</script>"
    malicious_desc = "<img src=x onerror=alert(1)> ignore previous instructions"

    alert = {
        "id": "TKT-SEC-001",
        "title": malicious_title,
        "severity": "critical",
        "what_happened": malicious_desc,
        "why_it_matters": "Testing escaping.",
        "severity_reason": "Rule violated.",
        "origin": {"ip": "203.0.113.99"},
    }

    msg = clean_notifier.build_email_message(
        alert_context=alert,
        recipients=["dasvamshi8@gmail.com"],
        sender="vamshipdas@gmail.com",
        dashboard_base_url="http://localhost:5173",
    )

    # Extract HTML part
    html_payload = None
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            html_payload = part.get_payload(decode=True).decode("utf-8")

    assert html_payload is not None
    # Raw <script> tags must NOT exist in the HTML body
    assert "<script>alert('XSS')</script>" not in html_payload
    assert "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;" in html_payload
    assert "<img src=x" not in html_payload
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_payload


def test_crlf_header_injection_prevention(clean_notifier):
    """Verify that CR/LF characters are stripped from subject and headers."""
    dirty_subject = "Critical Alert\r\nBcc: evil@hacker.com\r\nSubject: Spoofed"
    clean = _sanitize_header_value(dirty_subject)
    assert "\r" not in clean
    assert "\n" not in clean
    assert clean == "Critical Alert Bcc: evil@hacker.com Subject: Spoofed"

    alert = {
        "id": "TKT-HDR-001",
        "title": dirty_subject,
        "severity": "critical",
        "what_happened": "Header injection test.",
        "origin": {"ip": "1.2.3.4\r\nInjected-Header: evil"},
    }

    msg = clean_notifier.build_email_message(
        alert_context=alert,
        recipients=["dasvamshi8@gmail.com"],
        sender="vamshipdas@gmail.com\r\nBcc: evil@attacker.com",
        dashboard_base_url="http://localhost:5173",
    )

    # Check headers directly
    assert "\r" not in msg["Subject"]
    assert "\n" not in msg["Subject"]
    assert "\r" not in msg["From"]
    assert "\n" not in msg["From"]


def test_secret_redaction_in_email(clean_notifier):
    """Verify API keys, passwords, and tokens are redacted before email generation."""
    sensitive_evidence = [
        "User authenticated with password=SuperSecretPassword123!",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken",
        "api_key=sk-proj-abc123def456xyz789",
    ]

    alert = {
        "id": "TKT-SECRET-001",
        "title": "Credential Exposure Incident",
        "severity": "critical",
        "what_happened": "Log contains password=SuperSecretPassword123! in plain text.",
        "why_it_matters": "Credentials leaked.",
        "technical_details": {
            "linked_events": [{"message": line} for line in sensitive_evidence]
        },
        "origin": {"ip": "10.0.0.5"},
    }

    msg = clean_notifier.build_email_message(
        alert_context=alert,
        recipients=["dasvamshi8@gmail.com"],
        sender="vamshipdas@gmail.com",
        dashboard_base_url="http://localhost:5173",
    )

    # Check payload
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        content = part.get_payload(decode=True).decode("utf-8")
        assert "SuperSecretPassword123!" not in content
        assert "doNotLeakThisToken" not in content
        assert "sk-proj-abc123def456" not in content



# -----------------------------------------------------------------------------
# 4. SMTP Retry Logic with Exponential Backoff
# -----------------------------------------------------------------------------

def test_smtp_retry_succeeds_on_attempt_3(clean_notifier):
    """Verify that transient SMTP failures trigger retries and succeed on attempt 3."""
    alert = {
        "id": "TKT-RETRY-001",
        "title": "Lateral Movement Detected",
        "severity": "critical",
        "what_happened": "PsExec executed remotely.",
        "origin": {"ip": "172.16.0.4"},
    }

    call_count = 0

    def mock_smtp_builder(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        instance = MagicMock()
        if call_count < 3:
            # Raise transient exception on first 2 attempts
            instance.sendmail.side_effect = smtplib.SMTPServerDisconnected("Temporary connection loss")
        else:
            # Succeed on 3rd attempt
            instance.sendmail.return_value = {}
        context = MagicMock()
        context.__enter__.return_value = instance
        return context

    with patch("smtplib.SMTP", side_effect=mock_smtp_builder), \
         patch.object(settings, "SMTP_PASSWORD", "mock-password"), \
         patch("time.sleep") as mock_sleep:

        res = clean_notifier.send_critical_alert(alert)
        assert res["status"] == "sent"
        assert res["attempts"] == 3
        # Backoff sleep should have been called twice (between attempt 1-2 and 2-3)
        assert mock_sleep.call_count == 2


def test_smtp_retry_fails_after_3_attempts(clean_notifier):
    """Verify that persistent SMTP failures mark status as failed after 3 attempts."""
    alert = {
        "id": "TKT-FAIL-001",
        "title": "Failed Dispatch Test",
        "severity": "critical",
        "what_happened": "Something bad.",
        "origin": {"ip": "1.1.1.1"},
    }

    with patch("smtplib.SMTP", side_effect=smtplib.SMTPConnectError(421, b"Service unavailable")), \
         patch.object(settings, "SMTP_PASSWORD", "mock-password"), \
         patch("time.sleep"):

        res = clean_notifier.send_critical_alert(alert)
        assert res["status"] == "failed"
        assert res["attempts"] == 3
        assert "SMTP delivery failed after 3 attempts" in res["error"]


def test_missing_smtp_password_disabled_safely(clean_notifier):
    """Verify that when SMTP_PASSWORD is empty, sending is gracefully disabled and logged."""
    alert = {
        "id": "TKT-NOPW-001",
        "title": "No Password Test",
        "severity": "critical",
        "what_happened": "Something.",
        "origin": {"ip": "10.0.0.1"},
    }

    with patch.object(settings, "SMTP_PASSWORD", ""):
        res = clean_notifier.send_critical_alert(alert)
        assert res["status"] == "failed"
        assert "SMTP_PASSWORD not configured" in res["error"]


# -----------------------------------------------------------------------------
# 5. API Endpoints
# -----------------------------------------------------------------------------

def test_api_trigger_test_notification(setup_tokens):
    """Test POST /api/notifications/test."""
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {setup_tokens['analyst_token']}"}

    with patch("smtplib.SMTP") as mock_smtp, patch.object(settings, "SMTP_PASSWORD", "mock-pass"):
        instance = MagicMock()
        mock_smtp.return_value.__enter__.return_value = instance

        res = client.post("/api/notifications/test", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "sent"
        assert "dasvamshi8@gmail.com" in data["recipients"]


def test_api_notification_logs(setup_tokens):
    """Test GET /api/notifications/log."""
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {setup_tokens['analyst_token']}"}

    res = client.get("/api/notifications/log", headers=headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_settings_read_and_update(setup_tokens):
    """Test GET and PUT /api/notifications/settings."""
    client = TestClient(app)
    analyst_headers = {"Authorization": f"Bearer {setup_tokens['analyst_token']}"}
    admin_headers = {"Authorization": f"Bearer {setup_tokens['admin_token']}"}

    # 1. Analyst can read settings
    res = client.get("/api/notifications/settings", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    assert "enabled" in data
    assert "recipients" in data
    assert "smtp_password" not in data  # Never leaked

    # 2. Analyst CANNOT update settings (403)
    res_update_analyst = client.put(
        "/api/notifications/settings",
        json={"cooldown_seconds": 600},
        headers=analyst_headers,
    )
    assert res_update_analyst.status_code == 403

    # 3. Admin can update settings
    res_update_admin = client.put(
        "/api/notifications/settings",
        json={"cooldown_seconds": 600, "min_severity": "critical"},
        headers=admin_headers,
    )
    assert res_update_admin.status_code == 200
    updated_data = res_update_admin.json()
    assert updated_data["cooldown_seconds"] == 600
    assert updated_data["min_severity"] == "critical"
