import asyncio
import collections
import json
import os
import re
import sys
import uuid
from typing import AsyncGenerator, Dict, List, Optional

from app.services.log_analyzer import log_analyzer
from app.services.log_parser import normalize_level, redact_secrets
from app.services.severity import classify_severity


_MAX_BUFFER_SIZE = 1000


class LogCollector:
    """Collects real-time OS logs asynchronously across Windows, Linux, and macOS."""

    def __init__(self):
        self._buffer: collections.deque = collections.deque(maxlen=_MAX_BUFFER_SIZE)
        self._active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._is_running = False
        self._stop_events: Dict[str, asyncio.Event] = {}

    @property
    def buffer(self) -> List[Dict]:
        return list(self._buffer)

    def stop_stream(self, session_id: Optional[str] = None):
        """Stop streaming for a specific session or all active sessions."""
        if session_id and session_id in self._stop_events:
            self._stop_events[session_id].set()
            proc = self._active_processes.get(session_id)
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
        else:
            for s_id, event in self._stop_events.items():
                event.set()
                proc = self._active_processes.get(s_id)
                if proc:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
        self._is_running = False

    async def stream_logs(self, session_id: str) -> AsyncGenerator[str, None]:
        """
        Spawns OS-appropriate subprocess and yields SSE formatted data:
        data: {"type": "log"|"finding"|"warning", ...}\n\n
        """
        stop_event = asyncio.Event()
        self._stop_events[session_id] = stop_event
        self._is_running = True

        platform = sys.platform

        try:
            if platform.startswith("win"):
                async for chunk in self._stream_windows(session_id, stop_event):
                    yield chunk
            elif platform.startswith("linux"):
                async for chunk in self._stream_linux(session_id, stop_event):
                    yield chunk
            elif platform == "darwin":
                async for chunk in self._stream_macos(session_id, stop_event):
                    yield chunk
            else:
                yield f"data: {json.dumps({'type': 'warning', 'message': f'Unsupported OS platform: {platform}'})}\n\n"
        finally:
            self.stop_stream(session_id)
            self._stop_events.pop(session_id, None)
            self._active_processes.pop(session_id, None)

    async def _stream_windows(
        self, session_id: str, stop_event: asyncio.Event
    ) -> AsyncGenerator[str, None]:
        """
        Polls Windows Event Logs via PowerShell.
        Attempts Security, System, and Application logs.
        Falls back to System, Application if Security is denied (non-admin).
        """
        import subprocess

        ps1_path = os.path.join(os.path.dirname(__file__), "stream_win_logs.ps1")
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ps1_path,
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                encoding="utf-8",
                errors="replace",
            )
            self._active_processes[session_id] = proc
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'warning', 'message': f'Failed to launch PowerShell logger: {exc}'})}\n\n"
            return

        recent_window_events: List[Dict] = []

        while not stop_event.is_set():
            if proc.poll() is not None:
                break
            line = await asyncio.to_thread(proc.stdout.readline)
            if not line:
                if proc.poll() is not None:
                    break
                await asyncio.sleep(0.3)
                continue

            line = line.strip()
            if not line:
                continue

            if "WARN_SECURITY_DENIED" in line:
                yield f"data: {json.dumps({'type': 'warning', 'message': 'Windows Security log access denied (run IDE/terminal as Administrator to view Security events). Falling back to System and Application logs.'})}\n\n"
                continue

            try:
                item = json.loads(line)
                normalized = {
                    "id": f"EVT-{uuid.uuid4().hex[:12]}",
                    "timestamp": item.get("TimeCreated") or datetime.utcnow().isoformat(),
                    "level": normalize_level(item.get("Level", "INFO")),
                    "source": str(item.get("Source", "System")),
                    "event_id": str(item.get("EventID", "")),
                    "message": redact_secrets(str(item.get("Message", ""))),
                    "host": item.get("Host"),
                    "raw": redact_secrets(line),
                }

                self._buffer.append(normalized)
                recent_window_events.append(normalized)
                if len(recent_window_events) > 50:
                    recent_window_events.pop(0)

                # Run analyzer on recent window (now including the latest event)
                findings = log_analyzer.analyze_events(recent_window_events)

                # Classify severity
                sev_res = classify_severity(normalized, context_events=recent_window_events, findings=findings)
                normalized["severity"] = sev_res["severity"]
                normalized["severity_score"] = sev_res["score"]
                normalized["severity_reasons"] = sev_res["reasons"]

                # Process IP intelligence and broadcast external origins to Threat Origin Globe
                try:
                    from app.db import SessionLocal
                    from app.services.ip_intel import ip_intel
                    with SessionLocal() as db_session:
                        ip_intel.process_and_link_ips(db_session, [normalized], upload_id=None, findings=findings)
                except Exception:
                    pass

                # Emit normalized log entry with severity
                yield f"data: {json.dumps({'type': 'log', 'data': normalized})}\n\n"

                for fnd in findings:
                    yield f"data: {json.dumps({'type': 'finding', 'data': fnd})}\n\n"

            except Exception:
                # Non-JSON line or output artifact
                continue


    async def _stream_linux(
        self, session_id: str, stop_event: asyncio.Event
    ) -> AsyncGenerator[str, None]:
        cmd = ["journalctl", "-f", "-o", "json", "-n", "20"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._active_processes[session_id] = proc
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'warning', 'message': f'journalctl not available: {exc}'})}\n\n"
            return

        recent: List[Dict] = []
        while not stop_event.is_set():
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                await asyncio.sleep(0.5)
                continue
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                msg = d.get("MESSAGE", "")
                ts = d.get("__REALTIME_TIMESTAMP")
                normalized = {
                    "id": f"EVT-{uuid.uuid4().hex[:12]}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "level": normalize_level(d.get("PRIORITY")),
                    "source": d.get("_COMM", d.get("SYSLOG_IDENTIFIER", "linux")),
                    "event_id": None,
                    "message": redact_secrets(str(msg)),
                    "host": d.get("_HOSTNAME"),
                    "raw": redact_secrets(line),
                }
                findings = log_analyzer.analyze_events(recent)
                sev_res = classify_severity(normalized, context_events=recent, findings=findings)
                normalized["severity"] = sev_res["severity"]
                normalized["severity_score"] = sev_res["score"]
                normalized["severity_reasons"] = sev_res["reasons"]

                self._buffer.append(normalized)
                recent.append(normalized)
                if len(recent) > 50:
                    recent.pop(0)

                yield f"data: {json.dumps({'type': 'log', 'data': normalized})}\n\n"

                for fnd in findings:
                    yield f"data: {json.dumps({'type': 'finding', 'data': fnd})}\n\n"
            except Exception:
                continue

    async def _stream_macos(
        self, session_id: str, stop_event: asyncio.Event
    ) -> AsyncGenerator[str, None]:
        cmd = ["log", "stream", "--style", "ndjson"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._active_processes[session_id] = proc
        except Exception as exc:
            yield f"data: {json.dumps({'type': 'warning', 'message': f'log stream not available: {exc}'})}\n\n"
            return

        recent: List[Dict] = []
        while not stop_event.is_set():
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                await asyncio.sleep(0.5)
                continue
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                normalized = {
                    "id": f"EVT-{uuid.uuid4().hex[:12]}",
                    "timestamp": d.get("timestamp", datetime.utcnow().isoformat()),
                    "level": normalize_level(d.get("messageType", "INFO")),
                    "source": d.get("processImagePath", "macOS").split("/")[-1],
                    "event_id": None,
                    "message": redact_secrets(d.get("eventMessage", "")),
                    "host": None,
                    "raw": redact_secrets(line),
                }

                findings = log_analyzer.analyze_events(recent)
                sev_res = classify_severity(normalized, context_events=recent, findings=findings)
                normalized["severity"] = sev_res["severity"]
                normalized["severity_score"] = sev_res["score"]
                normalized["severity_reasons"] = sev_res["reasons"]

                self._buffer.append(normalized)
                recent.append(normalized)
                if len(recent) > 50:
                    recent.pop(0)

                yield f"data: {json.dumps({'type': 'log', 'data': normalized})}\n\n"

                for fnd in findings:
                    yield f"data: {json.dumps({'type': 'finding', 'data': fnd})}\n\n"
            except Exception:
                continue



log_collector = LogCollector()
