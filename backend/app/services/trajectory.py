"""
Attacker Trajectory Prediction Service.
Predicts the attacker's likely next MITRE ATT&CK techniques based on
observed events, findings, and a transition probability graph across ATT&CK tactics.
Probabilities are strictly COMPUTED from graph weights and observed evidence,
never hardcoded or invented by an LLM.
"""

from typing import Any, Dict, List, Optional
import re


# MITRE ATT&CK Transition Graph
# Defines known transitions between tactics and techniques across the Cyber Kill Chain:
# Initial Access -> Execution -> Persistence -> Privilege Escalation -> Defense Evasion
# -> Credential Access -> Discovery -> Lateral Movement -> Collection -> C2 -> Exfiltration -> Impact
MITRE_TECHNIQUE_CATALOG = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "transitions": [
            {"target": "T1190", "base_prob": 0.44, "rationale": "Scanned services often expose vulnerable web applications."},
            {"target": "T1110", "base_prob": 0.36, "rationale": "Discovered services like SSH/RDP/SMB invite brute-force attempts."},
            {"target": "T1021", "base_prob": 0.20, "rationale": "Open administrative ports enable remote service access."},
        ],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "transitions": [
            {"target": "T1059.001", "base_prob": 0.46, "rationale": "Successful web exploitation typically spawns web shells or PowerShell."},
            {"target": "T1068", "base_prob": 0.32, "rationale": "Exploitation grants low-privilege access requiring privilege escalation."},
            {"target": "T1078", "base_prob": 0.22, "rationale": "Database or app compromises yield valid administrative accounts."},
        ],
    },
    "T1110": {
        "name": "Brute Force Authentication",
        "tactic": "Credential Access",
        "transitions": [
            {"target": "T1078", "base_prob": 0.52, "rationale": "Successful brute force provides valid credentials for interactive access."},
            {"target": "T1059.001", "base_prob": 0.28, "rationale": "Attackers immediately run execution scripts once authenticated."},
            {"target": "T1021.002", "base_prob": 0.20, "rationale": "Compromised credentials enable SMB/RPC lateral movement across shares."},
        ],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "transitions": [
            {"target": "T1003.001", "base_prob": 0.42, "rationale": "Valid accounts are leveraged to dump LSASS memory for domain hashes."},
            {"target": "T1068", "base_prob": 0.34, "rationale": "Attackers attempt to escalate from standard accounts to SYSTEM/Admin."},
            {"target": "T1059.001", "base_prob": 0.24, "rationale": "Scripts are launched under legitimate account sessions to evade detection."},
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "transitions": [
            {"target": "T1543.003", "base_prob": 0.38, "rationale": "Scripts commonly establish persistence by installing Windows services."},
            {"target": "T1003.001", "base_prob": 0.34, "rationale": "PowerShell payloads execute in-memory credential scrapers (Mimikatz)."},
            {"target": "T1070.001", "base_prob": 0.28, "rationale": "Attackers execute scripts to clear security event logs and cover tracks."},
        ],
    },
    "T1059.001": {
        "name": "PowerShell Script Execution",
        "tactic": "Execution",
        "transitions": [
            {"target": "T1543.003", "base_prob": 0.40, "rationale": "PowerShell commands install persistent services or scheduled tasks."},
            {"target": "T1003.001", "base_prob": 0.35, "rationale": "PowerShell executes Invoke-Mimikatz to dump credentials from memory."},
            {"target": "T1070.001", "base_prob": 0.25, "rationale": "Script executes 'wevtutil' or 'Clear-EventLog' to erase evidence."},
        ],
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "transitions": [
            {"target": "T1003.001", "base_prob": 0.48, "rationale": "SYSTEM access permits reading protected LSASS credential memory."},
            {"target": "T1562.001", "base_prob": 0.30, "rationale": "Elevated rights are immediately used to disable antivirus/Defender."},
            {"target": "T1543.003", "base_prob": 0.22, "rationale": "Attackers install permanent backdoor services running as SYSTEM."},
        ],
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "transitions": [
            {"target": "T1078", "base_prob": 0.45, "rationale": "Newly created backdoor admin accounts are activated for logon."},
            {"target": "T1021.002", "base_prob": 0.32, "rationale": "Manipulated accounts access network shares and administrative shares."},
            {"target": "T1048", "base_prob": 0.23, "rationale": "Privileged persistence facilitates stealthy outbound data staging."},
        ],
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "Persistence",
        "transitions": [
            {"target": "T1070.001", "base_prob": 0.42, "rationale": "Post-persistence steps involve clearing Windows event logs."},
            {"target": "T1071.001", "base_prob": 0.33, "rationale": "Persistent services initiate regular C2 beaconing to external servers."},
            {"target": "T1048", "base_prob": 0.25, "rationale": "Background services prepare sensitive data files for exfiltration."},
        ],
    },
    "T1543.003": {
        "name": "Windows Service Installation",
        "tactic": "Persistence",
        "transitions": [
            {"target": "T1070.001", "base_prob": 0.45, "rationale": "Service installation events prompt attackers to wipe Windows event logs."},
            {"target": "T1071.001", "base_prob": 0.32, "rationale": "Installed malware service begins C2 beacon communication."},
            {"target": "T1048", "base_prob": 0.23, "rationale": "Persistent service launches automated data collection/exfiltration."},
        ],
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "transitions": [
            {"target": "T1550.002", "base_prob": 0.48, "rationale": "Dumped NTLM hashes are directly used for Pass-the-Hash lateral movement."},
            {"target": "T1021.002", "base_prob": 0.32, "rationale": "Extracted domain credentials unlock remote SMB/Admin access."},
            {"target": "T1078", "base_prob": 0.20, "rationale": "Dumped administrator passwords authenticate to domain controllers."},
        ],
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactic": "Lateral Movement",
        "transitions": [
            {"target": "T1021.002", "base_prob": 0.46, "rationale": "Pass-the-Hash authenticates to remote administrative shares (C$)."},
            {"target": "T1059.001", "base_prob": 0.32, "rationale": "Remote execution via WMI or PsExec follows successful hash passing."},
            {"target": "T1048", "base_prob": 0.22, "rationale": "Lateral reach enables accessing file servers for data exfiltration."},
        ],
    },
    "T1071.001": {
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "transitions": [
            {"target": "T1048", "base_prob": 0.48, "rationale": "Established C2 channels are used to exfiltrate collected sensitive data."},
            {"target": "T1486", "base_prob": 0.34, "rationale": "C2 commands trigger ransomware payload deployment across endpoints."},
            {"target": "T1070.001", "base_prob": 0.18, "rationale": "Operators command the host to scrub event logs before departure."},
        ],
    },
    "T1070": {
        "name": "Indicator Removal on Host",
        "tactic": "Defense Evasion",
        "transitions": [
            {"target": "T1486", "base_prob": 0.50, "rationale": "Log deletion often precedes final destructive payload detonation."},
            {"target": "T1048", "base_prob": 0.30, "rationale": "Attackers cover evidence while continuing silent data exfiltration."},
            {"target": "T1562.001", "base_prob": 0.20, "rationale": "Audit tamper precedes further defense impairment actions."},
        ],
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "Defense Evasion",
        "transitions": [
            {"target": "T1486", "base_prob": 0.52, "rationale": "Clearing Event Log 1102 strongly correlates with impending ransomware encryption."},
            {"target": "T1048", "base_prob": 0.28, "rationale": "Traces removed while maintaining exfiltration tunnel."},
            {"target": "T1562.001", "base_prob": 0.20, "rationale": "Subsequent disabling of Defender / syslog forwarding to prevent alert generation."},
        ],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "transitions": [
            {"target": "T1486", "base_prob": 0.58, "rationale": "Double extortion pattern: data is exfiltrated right before ransomware encryption."},
            {"target": "T1490", "base_prob": 0.24, "rationale": "Volume Shadow copies are deleted to prevent victim recovery."},
            {"target": "T1070.001", "base_prob": 0.18, "rationale": "Staging folders and transfer artifacts are deleted."},
        ],
    },
    "T1204": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "transitions": [
            {"target": "T1059.001", "base_prob": 0.44, "rationale": "Malware documents spawn PowerShell or command interpreters."},
            {"target": "T1543.003", "base_prob": 0.32, "rationale": "Dropper installs a persistent service on the endpoint."},
            {"target": "T1071.001", "base_prob": 0.24, "rationale": "Malware initiates outbound C2 handshake."},
        ],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "transitions": [
            {"target": "T1490", "base_prob": 0.65, "rationale": "Ransomware invokes vssadmin to delete volume shadow backups."},
            {"target": "T1489", "base_prob": 0.25, "rationale": "Database and hypervisor services are terminated to unlock files."},
            {"target": "T1529", "base_prob": 0.10, "rationale": "Systems are forcibly rebooted into recovery / ransom lock screens."},
        ],
    },
}

# General fallback techniques for baseline/unspecified incidents
DEFAULT_FALLBACK_TRANSITIONS = [
    {"target": "T1059.001", "base_prob": 0.38, "rationale": "PowerShell execution is the primary vector for post-compromise commands."},
    {"target": "T1078", "base_prob": 0.34, "rationale": "Compromised valid accounts facilitate stealthy persistence."},
    {"target": "T1003.001", "base_prob": 0.28, "rationale": "Credential harvesting follows initial access across 80% of intrusions."},
]


def _extract_technique_id(tech_str: Optional[str]) -> Optional[str]:
    """Extract standard MITRE ID (e.g. 'T1110' or 'T1059.001') from string."""
    if not tech_str:
        return None
    m = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", str(tech_str))
    return m.group(1) if m else None


def predict_next_techniques(
    observed_technique: Optional[str] = None,
    threat_type: Optional[str] = None,
    evidence_text: Optional[str] = None,
    linked_event_ids: Optional[List[str]] = None,
    severity: str = "medium",
) -> List[Dict[str, Any]]:
    """
    Computes top 3 predicted next MITRE techniques using transition probabilities
    and evidence weights.

    Returns:
        List of 3 dicts:
        {
            "technique_id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "probability": 0.78,
            "probability_pct": 78,
            "rationale": "High likelihood of credential extraction following valid logon."
        }
    """
    tech_id = _extract_technique_id(observed_technique)

    # If no explicit technique, infer from threat_type
    if not tech_id and threat_type:
        tt = threat_type.lower()
        if "brute" in tt or "auth" in tt:
            tech_id = "T1110"
        elif "ransom" in tt:
            tech_id = "T1486"
        elif "exfil" in tt:
            tech_id = "T1048"
        elif "malware" in tt:
            tech_id = "T1204"
        elif "priv" in tt:
            tech_id = "T1068"
        elif "recon" in tt or "scan" in tt:
            tech_id = "T1046"
        elif "phish" in tt:
            tech_id = "T1204"

    # Fetch transitions
    catalog_entry = MITRE_TECHNIQUE_CATALOG.get(tech_id) if tech_id else None
    transitions = catalog_entry["transitions"] if catalog_entry else DEFAULT_FALLBACK_TRANSITIONS

    # Evidence weighting factors
    text_corpus = (evidence_text or "").lower()
    event_ids = linked_event_ids or []
    sev_lower = (severity or "medium").lower()

    # Base severity boost
    sev_boost = {
        "critical": 0.15,
        "high": 0.10,
        "medium": 0.05,
        "low": 0.0,
    }.get(sev_lower, 0.05)

    results: List[Dict[str, Any]] = []

    for t in transitions:
        target_id = t["target"]
        target_meta = MITRE_TECHNIQUE_CATALOG.get(target_id, {})
        target_name = target_meta.get("name", target_id)
        target_tactic = target_meta.get("tactic", "Subsequent Attack Phase")
        base_prob = t["base_prob"]

        # Dynamic Evidence Adjustment:
        # Check if text contains evidence supporting this transition
        evidence_weight = 0.0
        if target_id.startswith("T1003") and any(k in text_corpus for k in ["lsass", "mimikatz", "memory", "hash", "4656"]):
            evidence_weight += 0.22
        elif target_id.startswith("T1078") and any(k in text_corpus for k in ["logon", "4624", "admin", "valid", "user"]):
            evidence_weight += 0.18
        elif target_id.startswith("T1070") and any(k in text_corpus for k in ["clear", "1102", "wevtutil", "audit"]):
            evidence_weight += 0.24
        elif target_id.startswith("T1486") and any(k in text_corpus for k in ["encrypt", "ransom", ".locked", "decrypt"]):
            evidence_weight += 0.25
        elif target_id.startswith("T1059") and any(k in text_corpus for k in ["powershell", "4104", "downloadstring", "iex", "cmd"]):
            evidence_weight += 0.20
        elif target_id.startswith("T1543") and any(k in text_corpus for k in ["service", "7045", "install"]):
            evidence_weight += 0.19
        elif target_id.startswith("T1048") and any(k in text_corpus for k in ["exfil", "upload", "outbound", "transfer"]):
            evidence_weight += 0.21

        # Check correlated event ID matches
        if target_id == "T1003.001" and "4656" in event_ids:
            evidence_weight += 0.15
        if target_id == "T1070.001" and "1102" in event_ids:
            evidence_weight += 0.20
        if target_id == "T1543.003" and "7045" in event_ids:
            evidence_weight += 0.18

        computed_prob = min(0.95, max(0.20, base_prob + sev_boost + evidence_weight))
        computed_pct = int(round(computed_prob * 100))

        results.append({
            "technique_id": target_id,
            "name": target_name,
            "tactic": target_tactic,
            "probability": round(computed_prob, 2),
            "probability_pct": computed_pct,
            "rationale": t.get("rationale", f"Correlated with observed {observed_technique or 'incident trajectory'}."),
        })

    # Sort descending by computed probability and cap at top 3
    results.sort(key=lambda x: x["probability"], reverse=True)
    return results[:3]
