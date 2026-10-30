"""
Alert Context Builder Service.
Assembles unified alert payloads across tickets, findings, log events, and IP addresses.
Provides plain-language explanations with bracketed terms, computed severity,
SOP actions with citations, false-positive likelihood, MITRE trajectory predictions,
and sanitized context for LLM interaction.
"""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.db_models import (
    AttackerIP,
    Finding as DBFinding,
    IPGeoCache,
    LogEvent,
    Ticket,
    utcnow,
)
from app.services.ip_intel import classify_ip, ip_intel
from app.services.log_collector import log_collector
from app.services.log_explainer import log_explainer, redact_secrets
from app.services.severity import classify_severity
from app.services.trajectory import predict_next_techniques
from app.services.vector_store import vector_store

# In-memory cache for generated alert summaries
_SUMMARY_CACHE: Dict[Tuple[str, str, str], Dict[str, Any]] = {}


def invalidate_alert_cache(alert_type: Optional[str] = None, alert_id: Optional[str] = None):
    """Invalidate summary cache for a specific alert or all alerts."""
    global _SUMMARY_CACHE
    if not alert_type or not alert_id:
        _SUMMARY_CACHE.clear()
        return

    keys_to_delete = [
        k for k in _SUMMARY_CACHE.keys()
        if k[0] == alert_type.lower() and k[1] == str(alert_id)
    ]
    for k in keys_to_delete:
        _SUMMARY_CACHE.pop(k, None)


# Common technical term bracket dictionary for plain-language translations
GLOSSARY = {
    "brute force": "brute force (someone guessing passwords repeatedly)",
    "brute-force": "brute force (someone guessing passwords repeatedly)",
    "lsass": "LSASS (the Windows security process that holds login passwords in memory)",
    "mimikatz": "Mimikatz (a hacker tool used to steal passwords from computer memory)",
    "pass the hash": "Pass the Hash (using stolen password fragments to log into other systems)",
    "c2": "Command & Control (the attacker's remote server controlling the compromised host)",
    "command and control": "Command & Control (the attacker's remote server controlling the compromised host)",
    "beaconing": "beaconing (regular check-in signals sent secretly to the attacker's server)",
    "privilege escalation": "privilege escalation (gaining administrator or superuser powers)",
    "persistence": "persistence (leaving a secret backdoor so the attacker can re-enter later)",
    "exfiltration": "exfiltration (stealing company files and sending them outside the network)",
    "ransomware": "ransomware (malicious software that scrambles and locks files for extortion)",
    "port scan": "port scan (probing network doors to see which services are open)",
    "reconnaissance": "reconnaissance (scouting out computers to find vulnerabilities)",
    "phishing": "phishing (deceptive emails designed to trick people into giving away credentials)",
    "sql injection": "SQL injection (tricking a database into revealing private records)",
    "lateral movement": "lateral movement (jumping from one infected computer to others inside the network)",
}


def _humanize_text(text: str) -> str:
    """Replaces security jargon with bracketed layman explanations."""
    if not text:
        return ""
    humanized = str(text)
    for term, explanation in GLOSSARY.items():
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        # Avoid double-wrapping
        if f"({explanation}" not in humanized:
            humanized = pattern.sub(explanation, humanized)
    return humanized


class AlertContextBuilder:
    def __init__(self):
        pass

    def build_summary(
        self,
        alert_type: str,
        alert_id: str,
        mode: str = "simple",
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        Builds unified alert summary payload.
        Caches per (alert_type, alert_id, mode).
        """
        a_type = (alert_type or "ticket").lower().strip()
        a_id = str(alert_id).strip()
        cache_key = (a_type, a_id, mode)

        if cache_key in _SUMMARY_CACHE:
            return _SUMMARY_CACHE[cache_key]

        payload = self._assemble_payload(a_type, a_id, mode, db)
        _SUMMARY_CACHE[cache_key] = payload
        return payload

    def _assemble_payload(
        self,
        alert_type: str,
        alert_id: str,
        mode: str,
        db: Optional[Session],
    ) -> Dict[str, Any]:
        title = "Security Alert"
        threat_type = "unauthorized_access"
        severity = "medium"
        severity_score = 50
        severity_reasons = ["Rule violation observed."]
        source_ip: Optional[str] = None
        target_host: Optional[str] = None
        description = ""
        status = "open"
        created_at = datetime.now(timezone.utc).isoformat()
        mitre_technique = None
        event_ids: List[str] = []
        raw_data: Dict[str, Any] = {}
        linked_events: List[Dict[str, Any]] = []

        # -------------------------------------------------------------
        # 1. Fetch Alert Entity
        # -------------------------------------------------------------
        if alert_type == "ticket":
            ticket = db.query(Ticket).filter(Ticket.id == alert_id).first() if db else None
            if ticket:
                title = ticket.title
                threat_type = ticket.threat_type
                severity = (ticket.severity or "medium").lower()
                status = ticket.status or "open"
                source_ip = ticket.source_ip
                target_host = ticket.target_host
                description = ticket.description
                created_at = ticket.created_at.isoformat() if ticket.created_at else created_at
                raw_data = {
                    "ticket_id": ticket.id,
                    "title": ticket.title,
                    "threat_type": ticket.threat_type,
                    "severity": ticket.severity,
                    "status": ticket.status,
                    "source_ip": ticket.source_ip,
                    "target_host": ticket.target_host,
                    "description": ticket.description,
                }
            else:
                title = f"Ticket {alert_id}"
                description = "Investigating active SOC ticket."

        elif alert_type == "finding":
            finding = db.query(DBFinding).filter(DBFinding.id == alert_id).first() if db else None
            if finding:
                title = finding.title
                threat_type = finding.category
                severity = (finding.severity or "high").lower()
                description = finding.description
                mitre_technique = finding.mitre_technique
                created_at = finding.created_at.isoformat() if finding.created_at else created_at
                try:
                    event_ids = json.loads(finding.evidence or "[]")
                except Exception:
                    event_ids = []
                raw_data = {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity,
                    "description": finding.description,
                    "mitre_technique": finding.mitre_technique,
                    "evidence": event_ids,
                }
            else:
                # Check live buffer findings or in-memory
                live_match = next((f for f in getattr(log_collector, "_buffer", []) if f.get("id") == alert_id), None)
                if live_match:
                    title = live_match.get("title", "Live Security Finding")
                    description = live_match.get("description", "")
                    severity = live_match.get("severity", "high")
                    mitre_technique = live_match.get("mitre_technique")
                    raw_data = live_match

        elif alert_type in ("log", "event"):
            # Query LogEvent from DB or live buffer
            log_item = db.query(LogEvent).filter(LogEvent.id == alert_id).first() if db else None
            if not log_item and db:
                log_item = db.query(LogEvent).filter(LogEvent.event_id == alert_id).first()

            if log_item:
                title = f"Log Event {log_item.event_id or ''}: {log_item.source}".strip()
                description = log_item.message
                severity = (log_item.severity or "low").lower()
                severity_score = log_item.severity_score or 20
                target_host = log_item.host
                if log_item.event_id:
                    event_ids.append(str(log_item.event_id))
                raw_data = {
                    "id": log_item.id,
                    "event_id": log_item.event_id,
                    "source": log_item.source,
                    "level": log_item.level,
                    "message": log_item.message,
                    "host": log_item.host,
                }
            else:
                # Search in-memory live buffer
                match = next((e for e in log_collector.buffer if e.get("id") == alert_id or str(e.get("event_id")) == alert_id), None)
                if match:
                    title = f"Log Event {match.get('event_id') or ''}: {match.get('source')}".strip()
                    description = match.get("message", "")
                    severity = (match.get("severity") or "low").lower()
                    severity_score = match.get("severity_score") or 20
                    target_host = match.get("host")
                    if match.get("event_id"):
                        event_ids.append(str(match.get("event_id")))
                    raw_data = match

        elif alert_type == "ip":
            source_ip = alert_id
            title = f"Attacker Origin: {alert_id}"
            description = f"External attacker connection telemetry associated with {alert_id}."
            if db:
                a_ip = db.query(AttackerIP).filter(AttackerIP.ip == alert_id).first()
                if a_ip:
                    severity = (a_ip.max_severity or "high").lower()
                    try:
                        event_ids = json.loads(a_ip.linked_event_ids or "[]")
                    except Exception:
                        pass
                    raw_data = {
                        "ip": a_ip.ip,
                        "country": a_ip.country,
                        "city": a_ip.city,
                        "asn": a_ip.asn,
                        "org": a_ip.org,
                        "event_count": a_ip.event_count,
                    }

        # Extract source IP from description or raw data if not found
        if not source_ip and description:
            ip_candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", description)
            if ip_candidates:
                source_ip = ip_candidates[0]

        # -------------------------------------------------------------
        # 2. Gather Linked Events (up to 30, secrets redacted)
        # -------------------------------------------------------------
        if db:
            if event_ids:
                events = db.query(LogEvent).filter(LogEvent.id.in_(event_ids[:30])).all()
                for e in events:
                    linked_events.append({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "level": e.level,
                        "source": e.source,
                        "event_id": e.event_id,
                        "message": redact_secrets(e.message),
                    })
            elif source_ip:
                events = db.query(LogEvent).filter(LogEvent.message.like(f"%{source_ip}%")).limit(20).all()
                for e in events:
                    linked_events.append({
                        "id": e.id,
                        "timestamp": e.timestamp,
                        "level": e.level,
                        "source": e.source,
                        "event_id": e.event_id,
                        "message": redact_secrets(e.message),
                    })

        # Fallback to buffer if no events from DB
        if not linked_events:
            for b_evt in log_collector.buffer[-15:]:
                if (source_ip and source_ip in str(b_evt.get("message", ""))) or (event_ids and str(b_evt.get("event_id")) in event_ids):
                    linked_events.append({
                        "id": b_evt.get("id"),
                        "timestamp": b_evt.get("timestamp"),
                        "level": b_evt.get("level"),
                        "source": b_evt.get("source"),
                        "event_id": b_evt.get("event_id"),
                        "message": redact_secrets(str(b_evt.get("message", ""))),
                    })

        # -------------------------------------------------------------
        # 3. Severity Calculation (Reuse existing deterministic engine)
        # -------------------------------------------------------------
        orig_level = severity.upper() if severity else "MEDIUM"
        synth_event = {
            "id": alert_id,
            "message": f"{title}. {description}".strip(),
            "raw": str(raw_data),
            "event_id": event_ids[0] if event_ids else None,
            "level": orig_level,
            "severity": severity,
        }
        sev_res = classify_severity(synth_event, context_events=linked_events)
        computed_severity = sev_res["severity"].upper()
        severity_score = sev_res["score"]
        severity_reasons = sev_res["reasons"] or []

        # If entity had an explicit non-low severity, maintain consistency
        if orig_level in ("HIGH", "CRITICAL") and computed_severity not in ("HIGH", "CRITICAL"):
            computed_severity = orig_level
            severity_reasons = [f"Classified as {computed_severity} based on organizational {threat_type} triage rule."] + severity_reasons
        elif not severity_reasons:
            severity_reasons = [f"Base severity calculated as {computed_severity} ({severity_score}/100) from telemetry patterns."]

        # -------------------------------------------------------------
        # 4. Geolocation Origin Details
        # -------------------------------------------------------------
        origin_data = {
            "ip": source_ip or "Unknown",
            "country": "Unknown",
            "country_code": "UNK",
            "city": "Unknown",
            "lat": 37.7749,
            "lon": -122.4194,
            "asn": "AS0000",
            "org": "Internal / Unresolved",
            "classification": "unknown",
            "source": "demo",
            "badge": "INTERNAL" if not source_ip else "DEMO",
            "is_routable": False,
        }

        if source_ip and db:
            geo_record = ip_intel.resolve_ip(db, source_ip)
            if geo_record:
                is_demo = geo_record.get("source") == "demo"
                is_internal = geo_record.get("classification") in ("private", "loopback", "internal")
                badge = "DEMO" if is_demo else ("INTERNAL" if is_internal else "PUBLIC")

                origin_data.update({
                    "country": geo_record.get("country") or "Unknown",
                    "country_code": geo_record.get("country_code") or "UNK",
                    "city": geo_record.get("city") or "Unknown",
                    "lat": float(geo_record.get("lat") or 37.7749),
                    "lon": float(geo_record.get("lon") or -122.4194),
                    "asn": geo_record.get("asn") or "AS64512",
                    "org": geo_record.get("org") or "Provider",
                    "classification": geo_record.get("classification") or "public",
                    "source": geo_record.get("source") or "demo",
                    "badge": badge,
                    "is_routable": geo_record.get("classification") not in ("private", "loopback"),
                })

        # -------------------------------------------------------------
        # 5. SOP Retrieval & Actions (Similarity threshold 0.15)
        # -------------------------------------------------------------
        sop_query = f"{threat_type} {title} {description}"
        sop_chunks = log_explainer.search_sops(sop_query)

        sop_steps = []
        sop_citations = []
        has_matching_sop = False

        # Threshold check: best similarity score must be >= 0.15
        best_score = sop_chunks[0][1] if sop_chunks else 0.0

        if sop_chunks and best_score >= 0.15:
            has_matching_sop = True
            for i, (chunk, score) in enumerate(sop_chunks[:4], 1):
                sop_id = chunk.get("sop_id", "SOP-SEC")
                raw_sec = chunk.get("section", "1.0")
                sec = raw_sec.split("\n")[0].strip()
                content = chunk.get("content", "").strip()

                # Extract concise action text
                lines = [l.strip() for l in content.split("\n") if l.strip()]
                action_text = ""
                for line in lines:
                    # Strip leading section headers like '2.0 Containment' or '- Step 2.1:'
                    cleaned = re.sub(r"^(?:-?\s*Step\s*\d+(?:\.\d+)?[:\s]*|\d+\.\d+\s+[A-Za-z\s]+:?|\d+\.\d+\s*)", "", line).strip()
                    if cleaned and not cleaned.lower() in ("containment", "detection", "eradication", "recovery", "triage", "analysis"):
                        action_text = cleaned
                        break
                if not action_text:
                    action_text = lines[0] if lines else content

                # Ensure action_text ends with a period
                if action_text and not action_text.endswith("."):
                    action_text += "."

                sop_steps.append(f"{i}. {action_text}")
                sop_citations.append({
                    "sop_id": sop_id,
                    "section": sec,
                    "title": f"{sop_id} §{sec}",
                    "similarity": round(score, 3),
                })
        else:
            sop_steps = [
                "No matching SOP found.",
                "1. Isolate the affected endpoint or network segment immediately to contain spread.",
                "2. Preserve volatile forensic logs and active network connections.",
                "3. Escalate the incident finding to the on-call Security Operations lead.",
            ]

        # -------------------------------------------------------------
        # 6. What Happened & Why It Matters (Plain Language)
        # -------------------------------------------------------------
        # Check event knowledge base
        primary_id = event_ids[0] if event_ids else None
        knowledge = log_explainer.lookup_knowledge(primary_id, description)

        if knowledge:
            what_happened_raw = knowledge.get("what_happened", description)
            why_it_matters_raw = knowledge.get("why_it_matters", "Monitored to detect abnormal network activity.")
            verdict_raw = knowledge.get("is_normal", "Suspicious activity detected.")
            if not mitre_technique:
                mitre_technique = knowledge.get("mitre_technique")
        else:
            if "failed" in description.lower() or "brute" in description.lower():
                what_happened_raw = "Multiple authentication attempts failed due to invalid passwords or non-existent usernames."
                why_it_matters_raw = "Attackers guess credentials systematically to break into authorized company accounts."
                verdict_raw = "Likely malicious (High confidence) when originating from unfamiliar geolocations."
                if not mitre_technique:
                    mitre_technique = "T1110 - Brute Force"
            elif "ransomware" in description.lower() or ".locked" in description.lower():
                what_happened_raw = "Ransomware encryption activity was detected modifying multiple files in seconds."
                why_it_matters_raw = "High risk of permanent operational data loss and extortion."
                verdict_raw = "Confirmed malicious (Critical confidence). Requires immediate automated containment."
                if not mitre_technique:
                    mitre_technique = "T1486 - Data Encrypted for Impact"
            elif "cleared" in description.lower() or "1102" in str(event_ids):
                what_happened_raw = "The security audit log was cleared deliberately by an account."
                why_it_matters_raw = "Attackers wipe event logs to conceal unauthorized actions and impede incident investigation."
                verdict_raw = "Highly suspicious (High confidence). Legitimate administrators rarely clear audit logs."
                if not mitre_technique:
                    mitre_technique = "T1070.001 - Clear Windows Event Logs"
            elif "powershell" in description.lower():
                what_happened_raw = "An encoded or evasive PowerShell script was launched in the background."
                why_it_matters_raw = "Scripts can download payloads, steal passwords, and bypass local security protections."
                verdict_raw = "Suspicious (High confidence). Verify whether IT administrative tools generated the command."
                if not mitre_technique:
                    mitre_technique = "T1059.001 - PowerShell"
            else:
                what_happened_raw = f"A security anomaly was recorded: {description[:160]}."
                why_it_matters_raw = "Requires validation to prevent unauthorized access or system disruption."
                verdict_raw = "Suspicious activity requiring analyst verification (Medium confidence)."

        what_happened = _humanize_text(what_happened_raw)
        why_it_matters = _humanize_text(why_it_matters_raw)

        # -------------------------------------------------------------
        # 7. Likelihood & Confidence (Real vs False Positive)
        # -------------------------------------------------------------
        is_malicious = computed_severity in ("HIGH", "CRITICAL")
        confidence_level = "High" if computed_severity in ("HIGH", "CRITICAL") else ("Medium" if computed_severity == "MEDIUM" else "Low")
        likelihood_verdict = "Likely malicious" if is_malicious else "Likely false positive or routine baseline"

        likelihood_reasons = []
        if is_malicious:
            likelihood_reasons.append(f"Classified as {computed_severity} based on threat severity engine rules.")
            if origin_data["country"] != "Unknown":
                likelihood_reasons.append(f"Originated from external untrusted IP in {origin_data['country']}.")
            if event_ids:
                likelihood_reasons.append(f"Triggered sensitive Event IDs: {', '.join(event_ids[:4])}.")
        else:
            likelihood_reasons.append("Matches benign administrative patterns or routine user typographical errors.")
            likelihood_reasons.append("No active lateral movement or privilege abuse detected.")

        # -------------------------------------------------------------
        # 8. MITRE Trajectory Prediction (Computed numbers only)
        # -------------------------------------------------------------
        trajectory_predictions = predict_next_techniques(
            observed_technique=mitre_technique,
            threat_type=threat_type,
            evidence_text=f"{title} {description} {' '.join(str(e.get('message', '')) for e in linked_events)}",
            linked_event_ids=event_ids,
            severity=computed_severity,
        )

        # -------------------------------------------------------------
        # 9. Sanitized Untrusted Alert Data Sandbox (for Ask Bot)
        # -------------------------------------------------------------
        sanitized_data_block = (
            f"<ALERT_DATA>\n"
            f"Alert ID: {alert_id}\n"
            f"Type: {alert_type}\n"
            f"Title: {title}\n"
            f"Severity: {computed_severity} (Score: {severity_score}/100)\n"
            f"Severity Reasons: {'; '.join(severity_reasons)}\n"
            f"Origin IP: {origin_data['ip']} ({origin_data['city']}, {origin_data['country']})\n"
            f"Host: {target_host or 'N/A'}\n"
            f"Description: {description}\n"
            f"Observed MITRE Technique: {mitre_technique or 'N/A'}\n"
            f"Predicted Next Techniques: {', '.join(t['technique_id'] + ' (' + str(t['probability_pct']) + '%)' for t in trajectory_predictions)}\n"
            f"Linked Events Count: {len(linked_events)}\n"
            f"</ALERT_DATA>"
        )

        return {
            "id": alert_id,
            "alert_type": alert_type,
            "title": title,
            "threat_type": threat_type,
            "status": status,
            "created_at": created_at,
            "mode": mode,
            "what_happened": what_happened,
            "why_it_matters": why_it_matters,
            "severity": computed_severity,
            "severity_score": severity_score,
            "severity_reason": severity_reasons[0] if severity_reasons else "Evaluated by security engine.",
            "severity_reasons": severity_reasons,
            "origin": origin_data,
            "sop_actions": {
                "has_matching_sop": has_matching_sop,
                "steps": sop_steps,
                "citations": sop_citations,
            },
            "likelihood": {
                "verdict": likelihood_verdict,
                "confidence": confidence_level,
                "reasons": likelihood_reasons,
            },
            "trajectory": trajectory_predictions,
            "trajectory_predictions": trajectory_predictions,
            "technical_details": {
                "event_ids": event_ids,
                "mitre_technique": mitre_technique or "T1078 / General",
                "target_host": target_host,
                "raw_data": raw_data,
                "linked_events": linked_events[:30],
                "timeline": {
                    "first_seen": linked_events[0].get("timestamp") if linked_events else created_at,
                    "last_seen": linked_events[-1].get("timestamp") if linked_events else created_at,
                },
            },
            "sanitized_data_block": sanitized_data_block,
        }


alert_context_builder = AlertContextBuilder()
