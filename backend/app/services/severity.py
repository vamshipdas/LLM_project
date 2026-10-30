import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

_SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_SEVERITY_DEFAULT_SCORES = {
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 95,
}

_RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "severity_rules.yaml")


def load_severity_rules() -> Dict[str, Any]:
    if not os.path.exists(_RULES_FILE):
        return {"base_levels": {}, "rules": []}
    try:
        with open(_RULES_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {"base_levels": {}, "rules": []}
    except Exception as e:
        print(f"Error loading severity_rules.yaml: {e}")
        return {"base_levels": {}, "rules": []}


def _extract_ip(text: str) -> Optional[str]:
    m = re.search(r'\b(?:from\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    return m.group(1) if m else None


def _extract_user(text: str) -> Optional[str]:
    m = re.search(r'\b(?:user|for user|for invalid user|Account Name:)\s+([a-zA-Z0-9_\-\.]+)\b', text, re.IGNORECASE)
    return m.group(1) if m else None


class SeverityClassifier:
    def __init__(self):
        self.config = load_severity_rules()

    def reload(self):
        self.config = load_severity_rules()

    def get_rules_summary(self) -> Dict[str, Any]:
        """Return active mapping & rules for UI legend / documentation."""
        return {
            "levels_mapping": {
                "low": "Benign system operations, routine info, debug/verbose telemetry",
                "medium": "Warnings, isolated logon failures, port scans/reconnaissance",
                "high": "Errors, brute-force bursts (5+ failures), privilege escalation, service creation, suspicious scripts",
                "critical": "Audit log clearing (anti-forensics), confirmed malware, account compromise after brute-force",
            },
            "rules": self.config.get("rules", []),
        }

    def classify_event(
        self,
        event: Dict[str, Any],
        context_events: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Classifies an event's security severity deterministically.
        Returns: { "severity": str, "score": int, "reasons": List[str] }
        """
        reasons: List[str] = []

        # --- Step A: Base severity from native log level ---
        raw_level = str(event.get("level") or "INFO").strip().lower()
        base_levels = self.config.get("base_levels", {})

        current_severity = "low"
        current_score = 20

        if raw_level in base_levels:
            current_severity = base_levels[raw_level].get("severity", "low")
            current_score = base_levels[raw_level].get("score", 20)
            reasons.append(f"Base severity from native level '{event.get('level')}': {current_severity.upper()}")
        else:
            # Fallback level detection
            if raw_level in ["critical", "fatal", "emerg", "emergency"]:
                current_severity = "critical"
                current_score = 95
            elif raw_level in ["error", "err"]:
                current_severity = "high"
                current_score = 75
            elif raw_level in ["warning", "warn"]:
                current_severity = "medium"
                current_score = 50
            else:
                current_severity = "low"
                current_score = 20
            reasons.append(f"Level '{event.get('level')}' mapped to: {current_severity.upper()}")

        def escalate(new_sev: str, new_score: int, reason: str):
            nonlocal current_severity, current_score
            if _SEVERITY_ORDER[new_sev] > _SEVERITY_ORDER[current_severity]:
                reasons.append(f"{reason} -> Escalated from {current_severity.upper()} to {new_sev.upper()}")
                current_severity = new_sev
                current_score = max(current_score, new_score)
            elif _SEVERITY_ORDER[new_sev] == _SEVERITY_ORDER[current_severity]:
                current_score = max(current_score, new_score)
                reasons.append(reason)

        event_id = str(event.get("event_id") or "")
        msg = str(event.get("message") or "")
        raw = str(event.get("raw") or "")
        full_text = f"{msg} {raw}".lower()

        # --- Step B: Rule overrides from YAML ---
        rules = self.config.get("rules", [])
        for r in rules:
            r_event_ids = [str(x) for x in r.get("event_ids", [])]
            r_keywords = [str(k).lower() for k in r.get("keywords", [])]

            match_id = event_id and (event_id in r_event_ids)
            match_kw = any(kw in full_text for kw in r_keywords)

            if match_id or match_kw:
                target_sev = r.get("severity", "medium")
                target_score = r.get("score", 50)
                reason_text = r.get("reason", r.get("name", "Matched security rule"))
                if match_id:
                    reason_text = f"Event ID {event_id}: {reason_text}"
                escalate(target_sev, target_score, reason_text)

        # Special Pattern Check: Failed Logon Escalation (4625 / failed password)
        is_failed_logon = (
            event_id in ["4625", "18456"]
            or any(k in full_text for k in ["failed password", "authentication failure", "failed login", "logon failure"])
        )

        if is_failed_logon:
            # Check context events if available
            if context_events:
                src_ip = _extract_ip(msg)
                target_user = _extract_user(msg)

                # Count matching failed logons within context
                similar_failures = [
                    e for e in context_events
                    if (
                        str(e.get("event_id")) in ["4625", "18456"]
                        or any(k in str(e.get("message", "")).lower() for k in ["failed password", "authentication failure", "failed login"])
                    ) and (
                        not src_ip or _extract_ip(str(e.get("message", ""))) == src_ip
                    )
                ]

                if len(similar_failures) >= 5:
                    escalate(
                        "high",
                        80,
                        f"Repeated authentication failure burst ({len(similar_failures)} attempts detected)",
                    )

                # Check if followed by success (Account compromise)
                has_success = any(
                    str(e.get("event_id")) == "4624"
                    or any(k in str(e.get("message", "")).lower() for k in ["accepted password", "successful logon", "session opened"])
                    for e in context_events
                )
                if has_success and len(similar_failures) >= 3:
                    escalate(
                        "critical",
                        95,
                        "Possible Account Compromise: successful logon followed prior authentication failures",
                    )

        # --- Step C: Correlation with Findings ---
        if findings:
            evt_id = str(event.get("id") or "")
            for f in findings:
                f_evidence = f.get("evidence", [])
                if isinstance(f_evidence, str):
                    try:
                        f_evidence = json.loads(f_evidence)
                    except Exception:
                        f_evidence = []

                if evt_id and evt_id in f_evidence:
                    f_sev = str(f.get("severity", "medium")).lower()
                    if f_sev in _SEVERITY_ORDER:
                        escalate(
                            f_sev,
                            _SEVERITY_DEFAULT_SCORES[f_sev],
                            f"Correlated with finding [{f.get('category')}]: '{f.get('title')}'",
                        )

        # Deduplicate reasons while preserving order
        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)

        return {
            "severity": current_severity,
            "score": current_score,
            "reasons": unique_reasons,
        }


severity_classifier = SeverityClassifier()


def classify_severity(
    event: Dict[str, Any],
    context_events: Optional[List[Dict[str, Any]]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Top-level deterministic severity classification function."""
    return severity_classifier.classify_event(event, context_events, findings)
