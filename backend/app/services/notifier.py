"""
Critical Alert Email Notification Service.
Sends automated multipart (HTML + plain text) email notifications to analysts
when critical security alerts, tickets, or findings occur.

Features:
- SMTP with STARTTLS (configurable via env vars only, never hardcoded)
- Background execution (non-blocking)
- Deduplication by alert ID
- Cooldown and grouping by source IP or category
- Global rate limiting (max 10 emails/hour)
- Retry with exponential backoff on SMTP errors
- Strict security: Jinja2 HTML auto-escaping, secret redaction, CRLF injection prevention,
  recipient allowlist enforcement, audit logging in NotificationLog.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
import json
import logging
import os
import re
import smtplib
import socket
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from jinja2 import Environment, select_autoescape
from sqlalchemy.orm import Session

from app.config import settings
from app.db import SessionLocal
from app.models.db_models import NotificationLog, SystemSetting, Ticket, Finding as DBFinding, utcnow
from app.services.alert_context import alert_context_builder
from app.services.log_explainer import redact_secrets

logger = logging.getLogger(__name__)

# Jinja2 environment configured for strict HTML autoescaping
_JINJA_ENV = Environment(
    autoescape=select_autoescape(["html", "xml"])
)

# Email address validation regex
_EMAIL_REGEX = re.compile(r"^[\w\.\+\-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$")

# HTML Email Template
_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ subject }}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; margin: 0; padding: 24px; }
    .container { max-width: 650px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 10px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    .banner { background: linear-gradient(90deg, #b91c1c 0%, #dc2626 100%); color: #ffffff; padding: 16px 24px; font-weight: 800; font-size: 18px; letter-spacing: 0.05em; display: flex; align-items: center; justify-content: space-between; }
    .content { padding: 24px; }
    .alert-header { border-bottom: 1px solid #1f2937; padding-bottom: 16px; margin-bottom: 20px; }
    .alert-title { font-size: 20px; font-weight: 700; color: #f8fafc; margin: 0 0 8px 0; }
    .alert-meta { font-size: 13px; color: #94a3b8; }
    .section { margin-bottom: 20px; }
    .section-title { font-size: 13px; font-weight: 700; text-transform: uppercase; color: #38bdf8; letter-spacing: 0.05em; margin-bottom: 8px; }
    .card { background: #1a2234; border: 1px solid #2d3748; border-radius: 6px; padding: 14px; font-size: 14px; line-height: 1.5; color: #cbd5e1; }
    .grid { display: table; width: 100%; }
    .grid-row { display: table-row; }
    .grid-cell { display: table-cell; padding: 6px 10px 6px 0; font-size: 13px; }
    .grid-label { color: #94a3b8; width: 120px; font-weight: 600; }
    .grid-val { color: #f1f5f9; font-family: monospace; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-critical { background: rgba(220, 38, 38, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-demo { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-internal { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid #0284c7; }
    .evidence-box { background: #080c14; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; font-family: 'Courier New', Courier, monospace; font-size: 12px; color: #94a3b8; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
    .action-btn { display: inline-block; background: #0284c7; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 700; font-size: 14px; margin-top: 10px; box-shadow: 0 4px 12px rgba(2, 132, 199, 0.35); text-align: center; }
    .footer { border-top: 1px solid #1f2937; padding: 16px 24px; font-size: 12px; color: #64748b; text-align: center; background: #0d121f; }
    ul { margin: 6px 0 0 0; padding-left: 20px; }
    li { margin-bottom: 4px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">
      <span>🚨 CRITICAL SECURITY ALERT</span>
      <span style="font-size: 13px; font-weight: normal; opacity: 0.9;">Sentinel Desk</span>
    </div>

    <div class="content">
      <div class="alert-header">
        <h1 class="alert-title">{{ alert_title }}</h1>
        <div class="alert-meta">
          <strong>Alert ID:</strong> {{ alert_id }} &nbsp;|&nbsp;
          <strong>Timestamp:</strong> {{ timestamp }} &nbsp;|&nbsp;
          <strong>Severity:</strong> <span class="badge badge-critical">CRITICAL</span>
          {% if grouped_count > 1 %}
          &nbsp;|&nbsp; <span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7;">{{ grouped_count }} ALERTS GROUPED</span>
          {% endif %}
        </div>
      </div>

      <!-- What Happened -->
      <div class="section">
        <div class="section-title">What Happened</div>
        <div class="card">{{ what_happened }}</div>
      </div>

      <!-- Why It Matters -->
      <div class="section">
        <div class="section-title">Why It Matters</div>
        <div class="card">{{ why_it_matters }}</div>
      </div>

      <!-- Severity Reason -->
      <div class="section">
        <div class="section-title">Severity Engine Reason</div>
        <div class="card" style="border-left: 3px solid #dc2626;">{{ severity_reason }}</div>
      </div>

      <!-- Entity & Source Details -->
      <div class="section">
        <div class="section-title">Target & Source Telemetry</div>
        <div class="card">
          <div class="grid">
            <div class="grid-row">
              <div class="grid-cell grid-label">Source IP:</div>
              <div class="grid-cell grid-val">
                {{ origin.ip or 'N/A' }}
                {% if origin.classification == 'demo' %}
                  <span class="badge badge-demo">DEMO</span>
                {% elif origin.classification == 'internal' or origin.classification == 'private' %}
                  <span class="badge badge-internal">INTERNAL</span>
                {% endif %}
              </div>
            </div>
            <div class="grid-row">
              <div class="grid-cell grid-label">Location:</div>
              <div class="grid-cell grid-val">{{ origin.city or 'Unknown' }}, {{ origin.country or 'Unknown' }}</div>
            </div>
            <div class="grid-row">
              <div class="grid-cell grid-label">ASN / Org:</div>
              <div class="grid-cell grid-val">{{ origin.asn or '' }} {{ origin.org or 'Unknown' }}</div>
            </div>
            <div class="grid-row">
              <div class="grid-cell grid-label">Affected Host:</div>
              <div class="grid-cell grid-val">{{ target_host or 'Unknown host' }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Top 3 Recommended SOP Steps -->
      <div class="section">
        <div class="section-title">Top Recommended SOP Steps</div>
        <div class="card">
          {% if sop_steps and sop_steps|length > 0 %}
            <ol style="margin: 0; padding-left: 20px;">
              {% for step in sop_steps[:3] %}
                <li style="margin-bottom: 6px;">{{ step }}</li>
              {% endfor %}
            </ol>
            {% if sop_citations and sop_citations|length > 0 %}
              <div style="font-size: 11px; color: #64748b; margin-top: 8px;">
                Citations: {% for cit in sop_citations[:3] %}<span style="background: #1e293b; padding: 2px 6px; border-radius: 4px; margin-right: 4px;">{{ cit.document or cit.sop_id or cit }}</span>{% endfor %}
              </div>
            {% endif %}
          {% else %}
            <em style="color: #94a3b8;">No matching SOP found. Refer to General Incident Response guidelines.</em>
          {% endif %}
        </div>
      </div>

      <!-- Likely Next Attacker Steps (MITRE Trajectory) -->
      <div class="section">
        <div class="section-title">Likely Next Attacker Steps (MITRE ATT&amp;CK Trajectory)</div>
        <div class="card">
          {% if trajectory and trajectory|length > 0 %}
            <ul>
              {% for step in trajectory[:3] %}
                <li>
                  <strong>{{ step.technique_id or step.technique }}</strong> - {{ step.name or 'Technique' }}:
                  <span style="color: #38bdf8; font-weight: bold;">{{ step.probability_pct or step.probability }}% likelihood</span>
                </li>
              {% endfor %}
            </ul>
          {% else %}
            <em style="color: #94a3b8;">Standard post-exploitation tactics expected. Monitor for credential access and lateral movement.</em>
          {% endif %}
        </div>
      </div>

      <!-- Evidence Samples (at most 5 short redacted lines) -->
      {% if evidence and evidence|length > 0 %}
      <div class="section">
        <div class="section-title">Evidence Excerpts (Redacted)</div>
        <div class="evidence-box">
{% for line in evidence[:5] -%}
{{ line }}
{% endfor %}
        </div>
      </div>
      {% endif %}

      <!-- Open in Sentinel Desk Button -->
      <div style="text-align: center; margin: 28px 0 10px 0;">
        <a href="{{ dashboard_url }}" class="action-btn" target="_blank" rel="noopener noreferrer">
          Open in Sentinel Desk &rarr;
        </a>
      </div>
    </div>

    <div class="footer">
      Automated alert. Do not reply. Generated by Sentinel Desk CyberLLM Incident Response System.
    </div>
  </div>
</body>
</html>
"""

# Plain text fallback template
_PLAIN_TEMPLATE = """
================================================================================
🚨 [CRITICAL ALERT] {{ alert_title }} | Sentinel Desk
================================================================================
Alert ID:    {{ alert_id }}
Timestamp:   {{ timestamp }}
Severity:    CRITICAL
{% if grouped_count > 1 %}Grouped:     {{ grouped_count }} alerts coalesced
{% endif %}

WHAT HAPPENED:
{{ what_happened }}

WHY IT MATTERS:
{{ why_it_matters }}

SEVERITY REASON:
{{ severity_reason }}

TARGET & SOURCE TELEMETRY:
- Source IP:      {{ origin.ip or 'N/A' }} ({{ origin.classification or 'public' }})
- Location:       {{ origin.city or 'Unknown' }}, {{ origin.country or 'Unknown' }}
- ASN / Org:      {{ origin.asn or '' }} {{ origin.org or 'Unknown' }}
- Affected Host:  {{ target_host or 'Unknown host' }}

TOP RECOMMENDED SOP STEPS:
{% if sop_steps and sop_steps|length > 0 %}
{% for step in sop_steps[:3] %}{{ loop.index }}. {{ step }}
{% endfor %}
{% else %}No matching SOP found.
{% endif %}

LIKELY NEXT ATTACKER STEPS (MITRE ATT&CK):
{% if trajectory and trajectory|length > 0 %}
{% for step in trajectory[:3] %}- {{ step.technique_id or step.technique }} {{ step.name or '' }}: {{ step.probability_pct or step.probability }}% likelihood
{% endfor %}
{% else %}Standard post-exploitation tactics expected.
{% endif %}

{% if evidence and evidence|length > 0 %}
EVIDENCE EXCERPTS (REDACTED):
{% for line in evidence[:5] %}> {{ line }}
{% endfor %}
{% endif %}

INVESTIGATE IN DASHBOARD:
{{ dashboard_url }}

--------------------------------------------------------------------------------
Automated alert. Do not reply. Sentinel Desk CyberLLM Incident Response.
"""


def _sanitize_header_value(value: str) -> str:
    """Strip CR and LF characters to prevent SMTP header injection."""
    if not value:
        return ""
    return re.sub(r"[\r\n]+", " ", str(value)).strip()


class AlertNotifier:
    """
    Manages critical alert notifications, spam control, and SMTP dispatch.
    """

    def __init__(self):
        # In-memory cooldown tracking: key (ip or category) -> timestamp of last sent email
        self._cooldown_tracker: Dict[str, float] = {}
        # In-memory alert grouping buffer: key -> list of alert dicts
        self._grouped_buffer: Dict[str, List[Dict[str, Any]]] = {}
        # Sent alert IDs (avoid duplicates in session)
        self._sent_alert_ids: set = set()
        # Hourly send timestamp log (for global rate limiting)
        self._hourly_send_timestamps: List[float] = []
        # Max emails per hour
        self.MAX_EMAILS_PER_HOUR = 10

    # -------------------------------------------------------------------------
    # Settings Management (DB backed with env fallback)
    # -------------------------------------------------------------------------
    def get_effective_password(self, db: Optional[Session] = None) -> str:
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            stored = db.query(SystemSetting).filter(SystemSetting.key == "notification_settings").first()
            if stored and stored.value:
                try:
                    data = json.loads(stored.value)
                    pwd = data.get("smtp_password")
                    if pwd and str(pwd).strip() and str(pwd).strip() != "<GMAIL_APP_PASSWORD>":
                        return str(pwd).strip()
                except Exception:
                    pass
            pwd = settings.SMTP_PASSWORD or ""
            return pwd.strip() if pwd.strip() != "<GMAIL_APP_PASSWORD>" else ""
        finally:
            if close_db:
                db.close()

    def get_settings(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Returns active notification settings.
        Settings stored in DB override env defaults.
        SMTP password is NEVER exposed.
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            effective_pwd = self.get_effective_password(db)
            is_configured = bool(effective_pwd)

            stored = db.query(SystemSetting).filter(SystemSetting.key == "notification_settings").first()
            if stored and stored.value:
                try:
                    data = json.loads(stored.value)
                    return {
                        "enabled": bool(data.get("enabled", settings.ALERT_EMAIL_ENABLED)),
                        "min_severity": str(data.get("min_severity", settings.ALERT_MIN_SEVERITY)).lower(),
                        "recipients": self._parse_recipients(data.get("recipients", settings.ALERT_EMAIL_TO)),
                        "cooldown_seconds": int(data.get("cooldown_seconds", settings.ALERT_COOLDOWN_SECONDS)),
                        "smtp_configured": is_configured,
                        "smtp_host": settings.SMTP_HOST,
                        "smtp_port": settings.SMTP_PORT,
                        "sender_email": str(data.get("sender_email", settings.ALERT_EMAIL_FROM)).strip(),
                    }
                except Exception as e:
                    logger.warning(f"Failed to parse stored notification settings: {e}")

            # Fallback to config settings
            return {
                "enabled": settings.ALERT_EMAIL_ENABLED,
                "min_severity": (settings.ALERT_MIN_SEVERITY or "critical").lower(),
                "recipients": self._parse_recipients(settings.ALERT_EMAIL_TO),
                "cooldown_seconds": settings.ALERT_COOLDOWN_SECONDS,
                "smtp_configured": is_configured,
                "smtp_host": settings.SMTP_HOST,
                "smtp_port": settings.SMTP_PORT,
                "sender_email": settings.ALERT_EMAIL_FROM,
            }
        finally:
            if close_db:
                db.close()

    def update_settings(self, db: Session, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates persistent notification settings in DB.
        Admins can adjust enabled, min_severity, recipients, cooldown_seconds, and smtp_password.
        """
        current = self.get_settings(db)
        if "enabled" in update_data and update_data["enabled"] is not None:
            current["enabled"] = bool(update_data["enabled"])
        if "min_severity" in update_data and update_data["min_severity"]:
            current["min_severity"] = str(update_data["min_severity"]).lower()
        if "recipients" in update_data and update_data["recipients"] is not None:
            current["recipients"] = self._parse_recipients(update_data["recipients"])
        if "cooldown_seconds" in update_data and update_data["cooldown_seconds"] is not None:
            current["cooldown_seconds"] = max(10, int(update_data["cooldown_seconds"]))

        if "sender_email" in update_data and update_data["sender_email"]:
            current["sender_email"] = str(update_data["sender_email"]).strip()

        save_dict = {
            "enabled": current["enabled"],
            "min_severity": current["min_severity"],
            "recipients": current["recipients"],
            "cooldown_seconds": current["cooldown_seconds"],
            "sender_email": current.get("sender_email", settings.ALERT_EMAIL_FROM),
        }

        # Check for smtp_password update or preservation
        if "smtp_password" in update_data and update_data["smtp_password"] is not None:
            pwd_input = str(update_data["smtp_password"]).strip()
            save_dict["smtp_password"] = pwd_input
            settings.SMTP_PASSWORD = pwd_input
        else:
            setting_existing = db.query(SystemSetting).filter(SystemSetting.key == "notification_settings").first()
            if setting_existing and setting_existing.value:
                try:
                    prev_data = json.loads(setting_existing.value)
                    if prev_data.get("smtp_password"):
                        save_dict["smtp_password"] = prev_data["smtp_password"]
                except Exception:
                    pass

        # Sync in-memory settings
        if "sender_email" in update_data and update_data["sender_email"]:
            settings.ALERT_EMAIL_FROM = str(update_data["sender_email"]).strip()
            settings.SMTP_USER = str(update_data["sender_email"]).strip()
        if "min_severity" in update_data and update_data["min_severity"]:
            settings.ALERT_MIN_SEVERITY = str(update_data["min_severity"]).lower()

        # Update .env file on disk if available
        try:
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            env_file = os.path.join(backend_dir, ".env")
            if os.path.exists(env_file):
                with open(env_file, "r", encoding="utf-8") as ef:
                    content = ef.read()
                import re
                if "smtp_password" in save_dict and save_dict["smtp_password"] is not None:
                    content = re.sub(r"^SMTP_PASSWORD=.*$", f"SMTP_PASSWORD={save_dict['smtp_password']}", content, flags=re.MULTILINE)
                if "sender_email" in save_dict and save_dict["sender_email"]:
                    content = re.sub(r"^SMTP_USER=.*$", f"SMTP_USER={save_dict['sender_email']}", content, flags=re.MULTILINE)
                    content = re.sub(r"^ALERT_EMAIL_FROM=.*$", f"ALERT_EMAIL_FROM={save_dict['sender_email']}", content, flags=re.MULTILINE)
                if "recipients" in save_dict and save_dict["recipients"]:
                    content = re.sub(r"^ALERT_EMAIL_TO=.*$", f"ALERT_EMAIL_TO={','.join(save_dict['recipients'])}", content, flags=re.MULTILINE)
                if "min_severity" in save_dict and save_dict["min_severity"]:
                    content = re.sub(r"^ALERT_MIN_SEVERITY=.*$", f"ALERT_MIN_SEVERITY={save_dict['min_severity']}", content, flags=re.MULTILINE)
                with open(env_file, "w", encoding="utf-8") as ef:
                    ef.write(content)
        except Exception as env_err:
            logger.warning(f"Could not persist notification settings to .env file: {env_err}")

        setting = db.query(SystemSetting).filter(SystemSetting.key == "notification_settings").first()
        if not setting:
            setting = SystemSetting(key="notification_settings", value=json.dumps(save_dict))
            db.add(setting)
        else:
            setting.value = json.dumps(save_dict)
            setting.updated_at = utcnow()

        db.commit()
        return self.get_settings(db)

    def _parse_recipients(self, recipients_input: Any) -> List[str]:
        """Validates and parses recipient email address list."""
        raw_list = []
        if isinstance(recipients_input, list):
            raw_list = recipients_input
        elif isinstance(recipients_input, str):
            raw_list = [r.strip() for r in recipients_input.split(",") if r.strip()]

        valid_list = []
        for email in raw_list:
            clean_email = email.strip()
            if _EMAIL_REGEX.match(clean_email):
                valid_list.append(clean_email)
            else:
                logger.warning(f"Ignored invalid email address in config/payload: '{clean_email}'")

        if not valid_list and settings.ALERT_EMAIL_TO:
            fallback = [r.strip() for r in settings.ALERT_EMAIL_TO.split(",") if _EMAIL_REGEX.match(r.strip())]
            return fallback

        return valid_list

    # -------------------------------------------------------------------------
    # Spam Protection Checks
    # -------------------------------------------------------------------------
    def _is_rate_limited(self) -> bool:
        """Enforces global limit of max 10 emails per hour."""
        now = time.time()
        one_hour_ago = now - 3600.0
        # Prune older timestamps
        self._hourly_send_timestamps = [t for t in self._hourly_send_timestamps if t > one_hour_ago]
        return len(self._hourly_send_timestamps) >= self.MAX_EMAILS_PER_HOUR

    def _record_send_timestamp(self):
        """Records a successful dispatch for hourly rate limit tracking."""
        self._hourly_send_timestamps.append(time.time())

    def _check_cooldown_and_group(
        self, group_key: str, alert_item: Dict[str, Any], cooldown_seconds: int
    ) -> Tuple[bool, int]:
        """
        Checks if an alert for this group key (source IP or category) is in cooldown.
        If in cooldown, registers the alert in the group buffer and returns (in_cooldown=True, count).
        If not in cooldown, updates the cooldown timestamp and returns (in_cooldown=False, 1).
        """
        now = time.time()
        last_sent = self._cooldown_tracker.get(group_key, 0)
        elapsed = now - last_sent

        if elapsed < cooldown_seconds:
            # Active cooldown window: buffer this alert for grouping
            if group_key not in self._grouped_buffer:
                self._grouped_buffer[group_key] = []
            self._grouped_buffer[group_key].append(alert_item)
            count = len(self._grouped_buffer[group_key]) + 1
            return True, count

        # New window
        self._cooldown_tracker[group_key] = now
        grouped_alerts = self._grouped_buffer.pop(group_key, [])
        grouped_count = len(grouped_alerts) + 1
        return False, grouped_count

    # -------------------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------------------
    def _log_attempt(
        self,
        db: Session,
        alert_id: str,
        alert_type: str,
        alert_title: str,
        severity: str,
        recipients: List[str],
        status: str,
        error_message: Optional[str] = None,
        retry_count: int = 0,
        grouped_count: int = 1,
    ) -> NotificationLog:
        """Writes an audit log entry to the notification_logs table."""
        recipients_str = ", ".join(recipients)
        # Ensure error message never contains sensitive credentials
        clean_err = error_message
        if clean_err and settings.SMTP_PASSWORD:
            clean_err = clean_err.replace(settings.SMTP_PASSWORD, "[REDACTED_SECRET]")

        entry = NotificationLog(
            alert_id=alert_id,
            alert_type=alert_type,
            alert_title=_sanitize_header_value(alert_title)[:250],
            severity=severity.lower(),
            recipients=_sanitize_header_value(recipients_str)[:500],
            status=status,
            error_message=clean_err,
            retry_count=retry_count,
            grouped_count=grouped_count,
            created_at=utcnow(),
        )
        try:
            db.add(entry)
            db.commit()
            db.refresh(entry)
            return entry
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to record NotificationLog in database: {e}")
            return entry

    # -------------------------------------------------------------------------
    # Email Construction
    # -------------------------------------------------------------------------
    def build_email_message(
        self,
        alert_context: Dict[str, Any],
        recipients: List[str],
        sender: str,
        dashboard_base_url: str,
        grouped_count: int = 1,
        is_test: bool = False,
    ) -> MIMEMultipart:
        """
        Builds a multipart MIME email with HTML and plain text parts.
        All dynamic fields are sanitized, secrets redacted, and HTML auto-escaped.
        """
        alert_title = alert_context.get("title", "Security Alert")
        alert_id = alert_context.get("id", "UNKNOWN")
        source_ip = alert_context.get("origin", {}).get("ip") or "unknown"
        target_host = alert_context.get("technical_details", {}).get("target_host") or ""
        host_or_ip = target_host if target_host and target_host != "unknown" else source_ip

        # Prevent CRLF injection in subject
        clean_title = _sanitize_header_value(alert_title)
        clean_host_ip = _sanitize_header_value(host_or_ip)
        
        if is_test:
            subject_str = f"[TEST ALERT] {clean_title} | {clean_host_ip} | Sentinel Desk"
        else:
            if grouped_count > 1:
                subject_str = f"[CRITICAL] {grouped_count} critical alerts from {clean_host_ip} | Sentinel Desk"
            else:
                subject_str = f"[CRITICAL] {clean_title} | {clean_host_ip} | Sentinel Desk"

        clean_subject = _sanitize_header_value(subject_str)

        # Dashboard deep-link
        clean_base = dashboard_base_url.rstrip("/")
        dashboard_url = f"{clean_base}/?alert={alert_id}"

        # Redact secrets from description and evidence lines
        what_happened = redact_secrets(alert_context.get("what_happened", "A critical security event was triggered."))
        why_it_matters = redact_secrets(alert_context.get("why_it_matters", "Immediate investigation is required."))
        severity_reason = redact_secrets(alert_context.get("severity_reason", "Classified as critical by the security engine."))

        # Process evidence lines (at most 5 short, redacted lines)
        raw_evidence = alert_context.get("technical_details", {}).get("linked_events", [])
        evidence_lines = []
        for item in raw_evidence[:5]:
            msg = item.get("message") or item.get("raw") or str(item)
            msg_redacted = redact_secrets(str(msg))
            # Truncate overly long lines to prevent bloated emails
            if len(msg_redacted) > 200:
                msg_redacted = msg_redacted[:197] + "..."
            evidence_lines.append(msg_redacted)

        # Prepare template context
        ctx = {
            "subject": clean_subject,
            "alert_id": alert_id,
            "alert_title": clean_title,
            "timestamp": alert_context.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "what_happened": what_happened,
            "why_it_matters": why_it_matters,
            "severity_reason": severity_reason,
            "origin": alert_context.get("origin", {}),
            "target_host": target_host,
            "sop_steps": alert_context.get("sop_actions", {}).get("steps", []),
            "sop_citations": alert_context.get("sop_actions", {}).get("citations", []),
            "trajectory": alert_context.get("trajectory", []),
            "evidence": evidence_lines,
            "dashboard_url": dashboard_url,
            "grouped_count": grouped_count,
        }

        # Render HTML and Plain text templates safely using Jinja2
        html_template = _JINJA_ENV.from_string(_HTML_TEMPLATE)
        plain_template = _JINJA_ENV.from_string(_PLAIN_TEMPLATE)

        html_body = html_template.render(**ctx)
        plain_body = plain_template.render(**ctx)

        # Create MIME structure
        msg = MIMEMultipart("alternative")
        msg["Subject"] = clean_subject
        msg["From"] = formataddr((_sanitize_header_value("Sentinel Desk SOC"), _sanitize_header_value(sender)))
        msg["To"] = ", ".join([_sanitize_header_value(r) for r in recipients])
        msg["Auto-Submitted"] = "auto-generated"
        msg["X-Auto-Response-Suppress"] = "All"

        # Attach text parts (Plain first, HTML second per RFC 2046)
        part_plain = MIMEText(plain_body, "plain", "utf-8")
        part_html = MIMEText(html_body, "html", "utf-8")

        msg.attach(part_plain)
        msg.attach(part_html)

        return msg

    # -------------------------------------------------------------------------
    # SMTP Delivery Engine with Retries
    # -------------------------------------------------------------------------
    def _deliver_email_sync(
        self,
        msg: MIMEMultipart,
        recipients: List[str],
        max_retries: int = 3,
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Delivers the MIME email via SMTP using STARTTLS.
        Retries up to max_retries with exponential backoff on transient errors.
        Returns: (success: bool, attempts: int, error_message: Optional[str])
        """
        current_config = self.get_settings()
        host = current_config.get("smtp_host") or settings.SMTP_HOST
        port = int(current_config.get("smtp_port") or settings.SMTP_PORT)
        user = current_config.get("sender_email") or settings.SMTP_USER
        from_email = current_config.get("sender_email") or settings.ALERT_EMAIL_FROM
        password = self.get_effective_password()

        if not password or not password.strip() or password == "<GMAIL_APP_PASSWORD>":
            warning_msg = (
                "[WARN] SMTP_PASSWORD is not configured in .env. "
                "Email sending is disabled. Skipping dispatch."
            )
            logger.warning(warning_msg)
            return False, 0, "SMTP_PASSWORD not configured in .env"

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempting SMTP dispatch to {recipients} (attempt {attempt}/{max_retries})...")
                # Connect to SMTP server
                with smtplib.SMTP(host, port, timeout=15) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    if user and password:
                        clean_pw = password.replace(" ", "").strip()
                        server.login(user.strip(), clean_pw)
                    server.sendmail(from_email, recipients, msg.as_string())

                logger.info(f"Successfully delivered alert email to {recipients}")
                self._record_send_timestamp()
                return True, attempt, None

            except (smtplib.SMTPException, OSError, TimeoutError, socket.error) as err:
                err_text = str(err)
                if password and password in err_text:
                    err_text = err_text.replace(password, "[REDACTED_PASSWORD]")
                clean_pw = password.replace(" ", "").strip()
                if clean_pw and clean_pw in err_text:
                    err_text = err_text.replace(clean_pw, "[REDACTED_PASSWORD]")
                last_error = err_text
                logger.warning(f"SMTP send attempt {attempt}/{max_retries} failed: {err_text}")
                if attempt < max_retries:
                    # Exponential backoff: 1s, 2s, 4s...
                    time.sleep(1.0 * (2 ** (attempt - 1)))

        return False, max_retries, f"SMTP delivery failed after {max_retries} attempts: {last_error}"

    # -------------------------------------------------------------------------
    # Core Dispatch Logic
    # -------------------------------------------------------------------------
    def send_critical_alert(
        self,
        alert_item: Union[Dict[str, Any], Ticket, DBFinding],
        db: Optional[Session] = None,
        is_test: bool = False,
    ) -> Dict[str, Any]:
        """
        High-level dispatcher for critical alerts.
        Can accept a raw Ticket, DBFinding, or an assembled alert context dict.
        Validates severity, deduplicates, enforces cooldown, and dispatches.
        """
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True

        try:
            # 1. Normalize input into unified alert summary payload
            alert_dict = self._normalize_alert_item(alert_item, db)
            alert_id = str(alert_dict.get("id") or "UNKNOWN")
            severity = str(alert_dict.get("severity") or "critical").lower()
            alert_title = alert_dict.get("title") or "Security Finding"
            alert_type = alert_dict.get("alert_type") or "ticket"

            # 2. Check configuration and threshold
            config = self.get_settings(db)
            if not config["enabled"] and not is_test:
                logger.info(f"Alert notifications disabled in settings. Skipping {alert_id}.")
                return {"status": "skipped", "reason": "notifications_disabled"}

            # Severity filter check
            min_sev = config["min_severity"]
            if not is_test and not self._is_severity_eligible(severity, min_sev):
                logger.info(f"Alert severity '{severity}' is below threshold '{min_sev}'. Skipping {alert_id}.")
                return {"status": "skipped", "reason": "below_min_severity"}

            # Deduplication check: do not resend for same alert id
            if not is_test and alert_id in self._sent_alert_ids:
                logger.info(f"Alert {alert_id} was already sent in this session. Skipping duplicate.")
                return {"status": "skipped", "reason": "duplicate_alert_id"}

            # Also check DB for previously successful send of this alert
            if not is_test:
                prev_sent = (
                    db.query(NotificationLog)
                    .filter(NotificationLog.alert_id == alert_id, NotificationLog.status == "sent")
                    .first()
                )
                if prev_sent:
                    self._sent_alert_ids.add(alert_id)
                    logger.info(f"Alert {alert_id} already marked as sent in DB. Skipping duplicate.")
                    return {"status": "skipped", "reason": "already_sent_in_db"}

            # 3. Recipients allowlist validation
            recipients = config["recipients"]
            if not recipients:
                err_msg = "No valid recipient email configured in settings or environment."
                logger.warning(err_msg)
                self._log_attempt(
                    db=db,
                    alert_id=alert_id,
                    alert_type=alert_type,
                    alert_title=alert_title,
                    severity=severity,
                    recipients=[],
                    status="failed",
                    error_message=err_msg,
                )
                return {"status": "failed", "reason": err_msg}

            # 4. Global Rate Limit Check (max 10 emails/hour)
            if not is_test and self._is_rate_limited():
                warn_msg = f"Global rate limit of {self.MAX_EMAILS_PER_HOUR} emails/hour exceeded."
                logger.warning(warn_msg)
                self._log_attempt(
                    db=db,
                    alert_id=alert_id,
                    alert_type=alert_type,
                    alert_title=alert_title,
                    severity=severity,
                    recipients=recipients,
                    status="skipped",
                    error_message=warn_msg,
                )
                return {"status": "skipped", "reason": "rate_limit_exceeded"}

            # 5. Cooldown & Grouping check
            group_key = self._get_group_key(alert_dict)
            grouped_count = 1
            if not is_test:
                in_cooldown, grouped_count = self._check_cooldown_and_group(
                    group_key=group_key,
                    alert_item=alert_dict,
                    cooldown_seconds=config["cooldown_seconds"],
                )
                if in_cooldown:
                    skip_msg = f"Cooldown active for key '{group_key}' ({config['cooldown_seconds']}s window). Alert grouped."
                    logger.info(skip_msg)
                    self._log_attempt(
                        db=db,
                        alert_id=alert_id,
                        alert_type=alert_type,
                        alert_title=alert_title,
                        severity=severity,
                        recipients=recipients,
                        status="skipped",
                        error_message=skip_msg,
                        grouped_count=grouped_count,
                    )
                    return {"status": "skipped", "reason": "cooldown_active", "grouped_count": grouped_count}

            # 6. Build multipart MIME message
            msg = self.build_email_message(
                alert_context=alert_dict,
                recipients=recipients,
                sender=config["sender_email"],
                dashboard_base_url=settings.DASHBOARD_BASE_URL,
                grouped_count=grouped_count,
                is_test=is_test,
            )

            # 7. Deliver via SMTP with retries
            success, attempts, error_msg = self._deliver_email_sync(
                msg=msg,
                recipients=recipients,
                max_retries=3,
            )

            status_str = "sent" if success else "failed"
            if success:
                self._sent_alert_ids.add(alert_id)

            # 8. Audit log
            log_entry = self._log_attempt(
                db=db,
                alert_id=alert_id,
                alert_type=alert_type,
                alert_title=alert_title,
                severity=severity,
                recipients=recipients,
                status=status_str,
                error_message=error_msg,
                retry_count=attempts,
                grouped_count=grouped_count,
            )

            return {
                "status": status_str,
                "alert_id": alert_id,
                "recipients": recipients,
                "log_id": log_entry.id if log_entry else None,
                "error": error_msg,
                "attempts": attempts,
            }

        finally:
            if close_db:
                db.close()

    def send_critical_alert_background(
        self,
        alert_item: Union[Dict[str, Any], Ticket, DBFinding],
        db: Optional[Session] = None,
    ):
        """
        Schedules `send_critical_alert` to execute in the background so it never
        blocks FastAPI request-response lifecycles or WebSocket streams.
        """
        try:
            loop = asyncio.get_running_loop()
            # If inside an asyncio event loop, run in a worker thread
            loop.run_in_executor(None, self.send_critical_alert, alert_item, None, False)
        except RuntimeError:
            # Fallback if no running asyncio loop
            import threading
            threading.Thread(
                target=self.send_critical_alert,
                args=(alert_item, None, False),
                daemon=True,
            ).start()

    def send_test_email(self, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Dispatches a clearly labeled test notification email to the configured recipients.
        """
        test_alert = {
            "id": f"TEST-{int(time.time())}",
            "alert_type": "test",
            "title": "Sentinel Desk Automated Email Pipeline Verification",
            "threat_type": "diagnostic_test",
            "severity": "CRITICAL",
            "severity_reason": "Manual diagnostic test triggered by administrator to verify SMTP delivery.",
            "what_happened": "An administrator triggered a diagnostic test email to verify SMTP delivery and notification formatting.",
            "why_it_matters": "Ensures the incident response team receives rapid, uncorrupted alerts during live cyber attacks.",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "origin": {
                "ip": "127.0.0.1",
                "city": "Localhost",
                "country": "Security Operations Center",
                "asn": "AS0",
                "org": "Internal SOC Test Harness",
                "classification": "internal",
            },
            "technical_details": {
                "target_host": "SENTINEL-HQ-01",
                "linked_events": [
                    {"message": "Test event 1: SMTP handshake initialized."},
                    {"message": "Test event 2: STARTTLS security layer negotiated successfully."},
                    {"message": "Test event 3: Email template rendered with Jinja2 autoescaping."},
                ],
            },
            "sop_actions": {
                "steps": [
                    "Verify this test email reached the intended analyst inbox (dasvamshi8@gmail.com).",
                    "Check spam or junk folders if not visible in primary inbox.",
                    "Confirm that the 'Open in Sentinel Desk' link navigates to your local dashboard.",
                ],
                "citations": [{"document": "SOP-SEC-00-Diagnostics.txt"}],
            },
            "trajectory": [
                {"technique_id": "T1078", "name": "Valid Accounts", "probability_pct": 95},
                {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "probability_pct": 80},
                {"technique_id": "T1021", "name": "Remote Services", "probability_pct": 65},
            ],
        }
        return self.send_critical_alert(test_alert, db=db, is_test=True)

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------
    def _normalize_alert_item(self, item: Any, db: Session) -> Dict[str, Any]:
        """Converts raw tickets, findings, or dicts into unified alert summary payload."""
        if isinstance(item, dict) and "what_happened" in item and "origin" in item:
            return item

        if isinstance(item, Ticket):
            return alert_context_builder.build_summary("ticket", item.id, mode="simple", db=db)

        if isinstance(item, DBFinding):
            return alert_context_builder.build_summary("finding", item.id, mode="simple", db=db)

        if isinstance(item, dict):
            alert_id = item.get("id") or item.get("ticket_id") or item.get("finding_id")
            if alert_id:
                a_type = "ticket" if str(alert_id).startswith("TKT-") else ("finding" if str(alert_id).startswith("FND-") else "ticket")
                try:
                    return alert_context_builder.build_summary(a_type, alert_id, mode="simple", db=db)
                except Exception as e:
                    logger.warning(f"Failed to build full summary for alert {alert_id}: {e}")

            # Basic fallback dict representation
            return {
                "id": str(item.get("id") or "UNKNOWN"),
                "alert_type": item.get("alert_type") or "ticket",
                "title": item.get("title") or "Critical Alert",
                "severity": item.get("severity") or "critical",
                "severity_reason": item.get("severity_reason") or "Triggered by critical severity rule.",
                "what_happened": item.get("description") or "Critical security finding detected.",
                "why_it_matters": "Requires immediate triage and containment.",
                "created_at": item.get("created_at") or datetime.now(timezone.utc).isoformat(),
                "origin": {
                    "ip": item.get("source_ip") or "unknown",
                    "city": "Unknown",
                    "country": "Unknown",
                    "classification": "public",
                },
                "technical_details": {
                    "target_host": item.get("target_host"),
                    "linked_events": item.get("evidence") or [],
                },
                "sop_actions": {
                    "steps": ["Isolate affected asset", "Revoke compromised credentials", "Preserve memory dump"],
                    "citations": [],
                },
                "trajectory": [],
            }

        return {
            "id": "UNKNOWN",
            "title": "Security Anomaly",
            "severity": "critical",
            "what_happened": "A critical event was detected.",
            "why_it_matters": "Requires analyst review.",
            "severity_reason": "Rule-based threshold breached.",
            "origin": {"ip": "unknown"},
            "technical_details": {},
        }

    def _get_group_key(self, alert_dict: Dict[str, Any]) -> str:
        """Determines grouping key: source IP if present and valid; else category."""
        ip = alert_dict.get("origin", {}).get("ip")
        if ip and ip not in ("unknown", "127.0.0.1", ""):
            return f"ip:{ip}"
        category = alert_dict.get("threat_type") or alert_dict.get("category") or "general"
        return f"cat:{category}"

    def _is_severity_eligible(self, alert_severity: str, min_severity: str) -> bool:
        """Checks if alert severity satisfies the minimum threshold."""
        levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_val = levels.get(str(alert_severity).lower().strip(), 0)
        min_val = levels.get(str(min_severity).lower().strip(), 4)
        return alert_val >= min_val


# Singleton instance
notifier = AlertNotifier()

