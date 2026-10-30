import csv
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --- Secrets Redaction ----------------------------------------------------

_SECRET_PATTERNS = [
    # Passwords in query params, key-value pairs, or JSON
    (re.compile(r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*["\']?([^"\'\s&,;]{3,})["\']?'), r'\1=[REDACTED_SECRET]'),
    (re.compile(r'(?i)"(password|passwd|pwd|secret)"\s*:\s*"[^"]+"'), r'"\1":"[REDACTED_SECRET]"'),
    # Bearer tokens
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}'), 'Bearer [REDACTED_TOKEN]'),
    # API keys / access tokens
    (re.compile(r'(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?'), r'\1=[REDACTED_API_KEY]'),
    (re.compile(r'(?i)"(api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)"\s*:\s*"[^"]+"'), r'"\1":"[REDACTED_API_KEY]"'),
    # Private keys
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
]


def redact_secrets(text: str) -> str:
    """Redact passwords, API keys, and sensitive tokens from log messages."""
    if not text:
        return ""
    redacted = text
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


# --- Level Normalization --------------------------------------------------

_LEVEL_MAP = {
    "0": "INFO",
    "1": "CRITICAL",
    "2": "ERROR",
    "3": "WARNING",
    "4": "INFO",
    "5": "DEBUG",
    "emerg": "CRITICAL",
    "emergency": "CRITICAL",
    "alert": "CRITICAL",
    "crit": "CRITICAL",
    "critical": "CRITICAL",
    "fatal": "CRITICAL",
    "err": "ERROR",
    "error": "ERROR",
    "warn": "WARNING",
    "warning": "WARNING",
    "notice": "INFO",
    "info": "INFO",
    "information": "INFO",
    "informational": "INFO",
    "debug": "DEBUG",
    "trace": "DEBUG",
    "audit_failure": "WARNING",
    "audit_success": "INFO",
    "failure audit": "WARNING",
    "success audit": "INFO",
}


def normalize_level(raw_level: Any) -> str:
    if raw_level is None:
        return "INFO"
    s = str(raw_level).strip().lower()
    return _LEVEL_MAP.get(s, "INFO")


def current_iso_time() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Syslog & Text Regular Expressions ------------------------------------

# RFC 3164 Syslog: Oct 21 21:04:14 host daemon[123]: message
_RFC3164_RE = re.compile(
    r'^(?P<pri><\d+>)?'
    r'(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>[^\s:]+)\s+'
    r'(?P<source>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

# RFC 5424 Syslog: <165>1 2026-10-21T21:04:14.003Z host app 123 msgid [sd] message
_RFC5424_RE = re.compile(
    r'^<(?P<pri>\d+)>(?P<ver>\d+)\s+'
    r'(?P<time>\d{4}-\d{2}-\d{2}T[^\s]+)\s+'
    r'(?P<host>[^\s]+)\s+'
    r'(?P<source>[^\s]+)\s+'
    r'(?P<pid>[^\s]+)\s+'
    r'(?P<msgid>[^\s]+)\s+'
    r'(?:\[[^\]]*\]\s*)?'
    r'(?P<message>.*)$'
)

# Generic standard timestamped log: 2026-10-21 21:04:14,123 [LEVEL] [Source] Message
_GENERIC_LOG_RE = re.compile(
    r'^(?P<time>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+'
    r'(?:\[?(?P<level>CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTICE)\]?\s+)?'
    r'(?:\[?(?P<source>[a-zA-Z0-9_\-\.]{2,30})\]?\s*[:\-]?\s*)?'
    r'(?P<message>.*)$',
    re.IGNORECASE
)


def _detect_level_from_message(msg: str) -> str:
    lower = msg.lower()
    if any(k in lower for k in ["failed", "failure", "denied", "error", "exception", "refused"]):
        if any(k in lower for k in ["critical", "fatal", "ransomware", "compromise"]):
            return "CRITICAL"
        return "ERROR" if "failed" in lower or "error" in lower else "WARNING"
    if any(k in lower for k in ["warning", "warn", "suspicious"]):
        return "WARNING"
    return "INFO"


def _extract_event_id(msg: str) -> Optional[str]:
    # Look for Windows EventID or common Event: 4625 / ID=4625
    m = re.search(r'\b(?:EventID|Event ID|Event|ID)[:=\s]+(\d{3,6})\b', msg, re.IGNORECASE)
    if m:
        return m.group(1)
    # Also match well-known standard Windows security event IDs
    m2 = re.search(r'\b(4625|4624|7045|4698|1102|4720|4732|4728|1116|1117|4104|104|18456)\b', msg)
    if m2:
        return m2.group(1)
    return None



# --- Format Parsers -------------------------------------------------------

def parse_json_content(text: str) -> List[Dict[str, Any]]:
    """Parse JSON array or JSON Lines (jsonl)."""
    events = []
    text = text.strip()
    if not text:
        return events

    # Case 1: JSON array of objects
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        events.append(_normalize_dict_event(item))
                return events
        except Exception:
            pass

    # Case 2: JSON Lines (each line is a json object)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                events.append(_normalize_dict_event(item))
            else:
                events.append(_make_event(message=str(item), raw=line))
        except Exception:
            # Fallback to plain text line if JSON decode fails
            events.append(parse_single_text_line(line))
    return events


def _normalize_dict_event(item: dict) -> Dict[str, Any]:
    raw_str = json.dumps(item)

    # Resolve timestamp
    ts = None
    for k in ["timestamp", "time", "@timestamp", "Date", "datetime", "TimeCreated"]:
        if k in item and item[k]:
            ts = str(item[k])
            break
    if not ts:
        ts = current_iso_time()

    # Resolve level
    raw_lvl = None
    for k in ["level", "severity", "type", "LogLevel", "Level"]:
        if k in item and item[k] is not None:
            raw_lvl = item[k]
            break

    # Resolve source
    source = "System"
    for k in ["source", "provider", "channel", "service", "app", "ProviderName", "program"]:
        if k in item and item[k]:
            source = str(item[k])
            break

    # Resolve event_id
    event_id = None
    for k in ["event_id", "eventId", "EventID", "id", "code"]:
        if k in item and item[k]:
            event_id = str(item[k])
            break

    # Resolve message
    msg = ""
    for k in ["message", "msg", "log", "description", "event_data", "payload"]:
        if k in item and item[k]:
            if isinstance(item[k], (dict, list)):
                msg = json.dumps(item[k])
            else:
                msg = str(item[k])
            break
    if not msg:
        msg = raw_str

    # Resolve host
    host = None
    for k in ["host", "hostname", "computer", "Computer", "server"]:
        if k in item and item[k]:
            host = str(item[k])
            break

    # Extract event_id from message if still missing
    if not event_id:
        event_id = _extract_event_id(msg)

    level = normalize_level(raw_lvl) if raw_lvl else _detect_level_from_message(msg)
    clean_msg = redact_secrets(msg)

    return {
        "id": f"EVT-{uuid.uuid4().hex[:12]}",
        "timestamp": ts,
        "level": level,
        "source": source,
        "event_id": event_id,
        "message": clean_msg,
        "host": host,
        "raw": redact_secrets(raw_str),
    }


def parse_csv_content(text: str) -> List[Dict[str, Any]]:
    """Parse CSV text with header detection."""
    events = []
    f = io.StringIO(text)
    try:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            events.append(_normalize_dict_event(row))
    except Exception:
        # Fall back to line by line text parsing
        for line in text.splitlines():
            if line.strip():
                events.append(parse_single_text_line(line.strip()))
    return events


def parse_evtx_file(file_path: str) -> List[Dict[str, Any]]:
    """Parse Windows .evtx binary log file using python-evtx."""
    events = []
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET

        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    # Strip namespace for easier query
                    xml_clean = re.sub(r' xmlns="[^"]+"', '', xml_str, count=1)
                    root = ET.fromstring(xml_clean)

                    system = root.find("System")
                    if system is None:
                        continue

                    # Event ID
                    event_id_el = system.find("EventID")
                    event_id = event_id_el.text.strip() if event_id_el is not None and event_id_el.text else None

                    # Provider
                    provider_el = system.find("Provider")
                    source = provider_el.attrib.get("Name", "Windows") if provider_el is not None else "Windows"

                    # TimeCreated
                    time_el = system.find("TimeCreated")
                    ts = time_el.attrib.get("SystemTime", current_iso_time()) if time_el is not None else current_iso_time()

                    # Level
                    level_el = system.find("Level")
                    raw_lvl = level_el.text.strip() if level_el is not None and level_el.text else "4"
                    level = normalize_level(raw_lvl)

                    # Computer
                    comp_el = system.find("Computer")
                    host = comp_el.text.strip() if comp_el is not None and comp_el.text else None

                    # EventData
                    event_data = root.find("EventData")
                    data_items = []
                    if event_data is not None:
                        for d in event_data.findall("Data"):
                            name = d.attrib.get("Name", "")
                            val = d.text or ""
                            if name:
                                data_items.append(f"{name}={val}")
                            elif val:
                                data_items.append(val)
                    msg = f"Event ID {event_id or 'unknown'} ({source}): " + " | ".join(data_items) if data_items else f"Event ID {event_id} from {source}"

                    events.append({
                        "id": f"EVT-{uuid.uuid4().hex[:12]}",
                        "timestamp": ts,
                        "level": level,
                        "source": source,
                        "event_id": event_id,
                        "message": redact_secrets(msg),
                        "host": host,
                        "raw": redact_secrets(xml_str[:1000]),
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"EVTX parsing failed: {e}")
    return events


def parse_single_text_line(line: str) -> Dict[str, Any]:
    """Parse a single text or syslog line into a normalized event."""
    line_clean = line.strip()
    if not line_clean:
        return _make_event(message="", raw="")

    # 1. Try RFC 5424
    m = _RFC5424_RE.match(line_clean)
    if m:
        d = m.groupdict()
        pri = int(d.get("pri", 13))
        severity_code = pri & 7
        msg = d.get("message", "")
        return {
            "id": f"EVT-{uuid.uuid4().hex[:12]}",
            "timestamp": d.get("time", current_iso_time()),
            "level": normalize_level(str(severity_code)),
            "source": d.get("source", "Syslog"),
            "event_id": d.get("msgid") if d.get("msgid") != "-" else _extract_event_id(msg),
            "message": redact_secrets(msg),
            "host": d.get("host"),
            "raw": redact_secrets(line_clean),
        }

    # 2. Try RFC 3164
    m = _RFC3164_RE.match(line_clean)
    if m:
        d = m.groupdict()
        msg = d.get("message", "")
        event_id = _extract_event_id(msg)
        lvl = _detect_level_from_message(msg)
        return {
            "id": f"EVT-{uuid.uuid4().hex[:12]}",
            "timestamp": d.get("time", current_iso_time()),
            "level": lvl,
            "source": d.get("source", "Syslog"),
            "event_id": event_id,
            "message": redact_secrets(msg),
            "host": d.get("host"),
            "raw": redact_secrets(line_clean),
        }

    # 3. Try Generic Timestamped format
    m = _GENERIC_LOG_RE.match(line_clean)
    if m:
        d = m.groupdict()
        msg = d.get("message", "")
        raw_lvl = d.get("level")
        level = normalize_level(raw_lvl) if raw_lvl else _detect_level_from_message(msg)
        source = d.get("source") or "System"
        event_id = _extract_event_id(msg)
        return {
            "id": f"EVT-{uuid.uuid4().hex[:12]}",
            "timestamp": d.get("time", current_iso_time()),
            "level": level,
            "source": source,
            "event_id": event_id,
            "message": redact_secrets(msg),
            "host": None,
            "raw": redact_secrets(line_clean),
        }

    # 4. Fallback unstructured line
    event_id = _extract_event_id(line_clean)
    level = _detect_level_from_message(line_clean)
    return {
        "id": f"EVT-{uuid.uuid4().hex[:12]}",
        "timestamp": current_iso_time(),
        "level": level,
        "source": "Unstructured",
        "event_id": event_id,
        "message": redact_secrets(line_clean),
        "host": None,
        "raw": redact_secrets(line_clean),
    }


def _make_event(message: str, raw: str) -> Dict[str, Any]:
    return {
        "id": f"EVT-{uuid.uuid4().hex[:12]}",
        "timestamp": current_iso_time(),
        "level": "INFO",
        "source": "Log",
        "event_id": None,
        "message": redact_secrets(message),
        "host": None,
        "raw": redact_secrets(raw),
    }


# --- Unified Parser Entrypoint --------------------------------------------

def parse_log_content(
    content: str, filename: str = "", file_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Auto-detect log format and parse into normalized event dicts.
    Supported: .evtx, .json, .jsonl, .csv, .log, .txt, syslog.
    """
    ext = os.path.splitext(filename)[1].lower() if filename else ""

    # EVTX binary file
    if ext == ".evtx" and file_path and os.path.exists(file_path):
        return parse_evtx_file(file_path)

    stripped = content.strip()
    if not stripped:
        return []

    # JSON or JSONL detection
    if ext in [".json", ".jsonl"] or stripped.startswith(("[", "{")):
        try:
            res = parse_json_content(content)
            if res:
                return res
        except Exception:
            pass

    # CSV detection
    if ext == ".csv" or ("," in stripped[:200] and "\n" in stripped[:200]):
        first_line = stripped.splitlines()[0]
        if any(h in first_line.lower() for h in ["time", "level", "message", "source", "event"]):
            try:
                res = parse_csv_content(content)
                if res:
                    return res
            except Exception:
                pass

    # Line by line parsing for syslog / plain text
    events = []
    for line in content.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        events.append(parse_single_text_line(line_str))
    return events
