import json
import os
import re
import tempfile
import uuid
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import _decode_token, get_current_user, require_any_user
from app.db import get_db
from app.models.db_models import (
    Finding as DBFinding,
    LogChatMessage,
    LogEvent,
    LogUpload,
    Role,
    Ticket,
    User,
)
from app.models.schemas import (
    AnalyzeResult,
    FindingSchema,
    LogChatMessageOut,
    LogChatRequest,
    LogChatResponse,
    LogEventSchema,
    LogEventsPageResponse,
    LogUploadSummary,
)
from app.services.log_analyzer import log_analyzer
from app.services.log_collector import log_collector
from app.services.log_explainer import log_explainer
from app.services.log_parser import parse_log_content
from app.services.severity import classify_severity, severity_classifier
from app.services.ip_intel import ip_intel


router = APIRouter(prefix="/logs", tags=["Log Analysis"])

_MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
_ALLOWED_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".jsonl", ".evtx", ".syslog"}


def _get_user_from_token_or_query(
    request: Request,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> User:
    """
    Authenticate user via query param (?token=...) or Authorization header.
    EventSource cannot send custom headers, so token parameter is supported.
    """
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header.split(" ", 1)[1]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = _decode_token(raw_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# --- 1. Real-Time Log Collection (SSE) ------------------------------------

@router.get("/stream")
async def stream_live_logs(
    user: User = Depends(_get_user_from_token_or_query),
):
    """
    Server-Sent Events endpoint streaming live host logs.
    Supports ?token=<jwt> for EventSource compatibility.
    """
    session_id = f"stream-{user.username}-{uuid.uuid4().hex[:8]}"
    print(f"[AUDIT] Real-time log stream started by user: {user.username} (session: {session_id})")

    async def event_generator():
        try:
            async for chunk in log_collector.stream_logs(session_id):
                yield chunk
        finally:
            log_collector.stop_stream(session_id)
            print(f"[AUDIT] Real-time log stream ended for user: {user.username} (session: {session_id})")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/stop")
def stop_live_stream(user: User = Depends(require_any_user)):
    """Stop live log collection subprocess."""
    log_collector.stop_stream()
    print(f"[AUDIT] User {user.username} requested live stream stop")
    return {"status": "stopped", "message": "Live log collection halted"}


@router.get("/live/buffer")
def get_live_buffer(user: User = Depends(require_any_user)):
    """Return current in-memory buffer from live collection."""
    buffer = log_collector.buffer
    return {
        "total_events": len(buffer),
        "events": buffer[-500:],
    }


@router.post("/analyze/live", response_model=AnalyzeResult)
async def analyze_live_buffer(
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Run rule-based detection + SOP RAG correlation over the live in-memory buffer."""
    buffer = log_collector.buffer
    if not buffer:
        return AnalyzeResult(
            upload_id=None,
            total_findings=0,
            findings=[],
            tickets_created=[],
            summary="Live buffer is empty. Start real-time logs to collect events first.",
        )

    findings = log_analyzer.analyze_events(buffer)
    enriched = await log_analyzer.correlate_with_rag(findings, db=db)

    try:
        ip_intel.process_and_link_ips(db, buffer, upload_id=None, findings=enriched)
    except Exception as e:
        print(f"[WARN] IP intel processing failed for live buffer: {e}")

    tickets_created = [f["ticket_id"] for f in enriched if f.get("ticket_id")]

    return AnalyzeResult(
        upload_id=None,
        total_findings=len(enriched),
        findings=[FindingSchema(**f) for f in enriched],
        tickets_created=tickets_created,
        summary=f"Analyzed {len(buffer)} live events. Identified {len(enriched)} security findings.",
    )


# --- 2. Upload Logs -------------------------------------------------------

@router.post("/upload", response_model=LogUploadSummary)
async def upload_log_file(
    file: UploadFile = File(...),
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """
    Upload and parse log files (.log, .txt, .csv, .json, .jsonl, .evtx, syslog).
    Validates size (max 20MB) and format. Sanitizes file names and content.
    """
    orig_name = file.filename or "unknown.log"
    clean_name = os.path.basename(re.sub(r"[^a-zA-Z0-9_\-\.]", "_", orig_name))
    ext = os.path.splitext(clean_name)[1].lower()

    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}",
        )

    # Read content safely and enforce 20MB limit
    content_bytes = await file.read()
    file_size = len(content_bytes)

    if file_size > _MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of 20 MB ({file_size} bytes).",
        )

    # Handle EVTX via temporary file
    parsed_events = []
    if ext == ".evtx":
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
            tmp.write(content_bytes)
            tmp_path = tmp.name
        try:
            parsed_events = parse_log_content("", filename=clean_name, file_path=tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
    else:
        try:
            text = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = content_bytes.decode("latin-1", errors="replace")
        parsed_events = parse_log_content(text, filename=clean_name)

    if not parsed_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not extract any valid log events from uploaded file.",
        )

    # Run detection rules first so correlation can escalate severity
    findings = log_analyzer.analyze_events(parsed_events)

    # Classify severity for every event deterministically
    for evt in parsed_events:
        sev_res = classify_severity(evt, context_events=parsed_events, findings=findings)
        evt["severity"] = sev_res["severity"]
        evt["severity_score"] = sev_res["score"]
        evt["severity_reasons"] = sev_res["reasons"]

    # Create LogUpload record in SQLite
    upload_id = f"UPL-{uuid.uuid4().hex[:12]}"
    upload = LogUpload(
        id=upload_id,
        user_id=user.id,
        filename=clean_name,
        file_size=file_size,
        total_events=len(parsed_events),
    )
    db.add(upload)

    # Batch save events with severity
    db_events = []
    for evt in parsed_events:
        db_events.append(
            LogEvent(
                id=evt.get("id") or f"EVT-{uuid.uuid4().hex[:12]}",
                upload_id=upload_id,
                timestamp=evt.get("timestamp", ""),
                level=evt.get("level", "INFO"),
                source=evt.get("source", "System"),
                event_id=evt.get("event_id"),
                message=evt.get("message", ""),
                host=evt.get("host"),
                raw=evt.get("raw"),
                severity=evt.get("severity", "low"),
                severity_score=evt.get("severity_score", 20),
                severity_reasons=json.dumps(evt.get("severity_reasons", [])),
            )
        )
    db.add_all(db_events)

    db_findings = []
    for f in findings:
        db_f = DBFinding(
            id=f["id"],
            upload_id=upload_id,
            severity=f["severity"],
            category=f["category"],
            title=f["title"],
            description=f["description"],
            evidence=json.dumps(f.get("evidence", [])),
            first_seen=f.get("first_seen"),
            last_seen=f.get("last_seen"),
            mitre_technique=f.get("mitre_technique"),
        )
        db.add(db_f)
        db_findings.append(db_f)

    db.commit()

    try:
        ip_intel.process_and_link_ips(db, parsed_events, upload_id=upload_id, findings=findings)
    except Exception as e:
        print(f"[WARN] IP intel processing failed for upload {upload_id}: {e}")

    print(
        f"[AUDIT] User '{user.username}' uploaded '{clean_name}' "
        f"({file_size} bytes, {len(parsed_events)} events, {len(findings)} findings)"
    )

    # Compute breakdown stats
    levels_count: dict = {}
    severities_count: dict = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    sources_count: dict = {}
    for evt in parsed_events:
        lvl = evt.get("level", "INFO")
        levels_count[lvl] = levels_count.get(lvl, 0) + 1
        sev = str(evt.get("severity", "low")).upper()
        severities_count[sev] = severities_count.get(sev, 0) + 1
        src = evt.get("source", "System")
        sources_count[src] = sources_count.get(src, 0) + 1

    top_sources = dict(sorted(sources_count.items(), key=lambda x: x[1], reverse=True)[:5])

    timestamps = [e.get("timestamp") for e in parsed_events if e.get("timestamp")]
    time_range = {
        "start": min(timestamps) if timestamps else None,
        "end": max(timestamps) if timestamps else None,
    }

    return LogUploadSummary(
        id=upload_id,
        filename=clean_name,
        file_size=file_size,
        total_events=len(parsed_events),
        levels_count=levels_count,
        severities_count=severities_count,
        top_sources=top_sources,
        time_range=time_range,
        findings=[FindingSchema(**f) for f in findings],
        events_sample=[LogEventSchema(**e) for e in parsed_events[:500]],
    )


@router.get("/uploads/{upload_id}/events", response_model=LogEventsPageResponse)
def get_upload_events(
    upload_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    level: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    sort_by_severity: bool = Query(False),
    q: Optional[str] = Query(None),
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Paginated, filterable event listing for an uploaded log."""
    upload = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Log upload not found")

    query = db.query(LogEvent).filter(LogEvent.upload_id == upload_id)
    if level and level.strip() and level.strip().upper() != "ALL":
        query = query.filter(LogEvent.level == level.strip().upper())
    if severity and severity.strip() and severity.strip().upper() != "ALL":
        query = query.filter(LogEvent.severity == severity.strip().lower())
    if q and q.strip():
        search_pattern = f"%{q.strip()}%"
        query = query.filter(
            (LogEvent.message.ilike(search_pattern))
            | (LogEvent.source.ilike(search_pattern))
            | (LogEvent.event_id.ilike(search_pattern))
        )

    total = query.count()
    order_clause = (
        (LogEvent.severity_score.desc(), LogEvent.id.asc())
        if sort_by_severity
        else (LogEvent.id.asc(),)
    )
    events = (
        query.order_by(*order_clause)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return LogEventsPageResponse(
        upload_id=upload_id,
        page=page,
        page_size=page_size,
        total=total,
        events=[LogEventSchema.model_validate(e) for e in events],
    )


@router.get("/severity-rules")
def get_severity_rules(user: User = Depends(require_any_user)):
    """Return active deterministic severity classification rules for the UI legend."""
    return severity_classifier.get_rules_summary()



# --- 3. Analyze Uploaded Log with RAG -------------------------------------

@router.post("/analyze/{upload_id}", response_model=AnalyzeResult)
async def analyze_upload_log(
    upload_id: str,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """
    Run rules + RAG SOP correlation over an uploaded log.
    Auto-creates tickets for high/critical findings and returns SOP citations.
    """
    upload = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Log upload not found")

    # Fetch events
    events = db.query(LogEvent).filter(LogEvent.upload_id == upload_id).all()
    events_dicts = [
        {
            "id": e.id,
            "timestamp": e.timestamp,
            "level": e.level,
            "source": e.source,
            "event_id": e.event_id,
            "message": e.message,
            "host": e.host,
            "raw": e.raw,
        }
        for e in events
    ]

    findings = log_analyzer.analyze_events(events_dicts)
    enriched = await log_analyzer.correlate_with_rag(findings, db=db)

    # Persist or update findings in DB
    for f in enriched:
        db_f = db.query(DBFinding).filter(DBFinding.id == f["id"]).first()
        if not db_f:
            db_f = DBFinding(
                id=f["id"],
                upload_id=upload_id,
                severity=f["severity"],
                category=f["category"],
                title=f["title"],
                description=f["description"],
                evidence=json.dumps(f.get("evidence", [])),
                first_seen=f.get("first_seen"),
                last_seen=f.get("last_seen"),
                mitre_technique=f.get("mitre_technique"),
                sop_recommendation=f.get("sop_recommendation"),
                sop_citations=json.dumps(f.get("sop_citations", [])),
                ticket_id=f.get("ticket_id"),
            )
            db.add(db_f)
        else:
            db_f.sop_recommendation = f.get("sop_recommendation")
            db_f.sop_citations = json.dumps(f.get("sop_citations", []))
            db_f.ticket_id = f.get("ticket_id")
    db.commit()

    tickets_created = [f["ticket_id"] for f in enriched if f.get("ticket_id")]

    return AnalyzeResult(
        upload_id=upload_id,
        total_findings=len(enriched),
        findings=[FindingSchema(**f) for f in enriched],
        tickets_created=tickets_created,
        summary=(
            f"Successfully analyzed log file '{upload.filename}'. "
            f"Correlated {len(enriched)} findings with SOP knowledge base. "
            f"Auto-generated {len(tickets_created)} incident tickets."
        ),
    )


@router.post("/create-ticket")
def create_ticket_from_finding(
    payload: dict,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Manually create an incident ticket from a finding card."""
    finding_id = payload.get("finding_id")
    title = payload.get("title", "Log Analysis Finding")
    category = payload.get("category", "Log Analysis")
    severity = payload.get("severity", "medium")
    description = payload.get("description", "")

    ticket_id = f"TKT-{uuid.uuid4().hex[:10].upper()}"
    ticket = Ticket(
        id=ticket_id,
        title=f"[{severity.upper()}] {title}",
        threat_type=category,
        severity=severity,
        status="open",
        description=description,
    )
    db.add(ticket)

    if finding_id:
        fnd = db.query(DBFinding).filter(DBFinding.id == finding_id).first()
        if fnd:
            fnd.ticket_id = ticket_id

    db.commit()

    if severity.lower() == "critical":
        try:
            from app.services.notifier import notifier
            notifier.send_critical_alert_background(ticket)
        except Exception as ex:
            print(f"[WARN] Failed to trigger notification for critical ticket {ticket_id}: {ex}")

    return {"status": "ok", "ticket_id": ticket_id}



# --- 8. Log Explainer Chatbot --------------------------------------------

@router.post("/chat", response_model=LogChatResponse)
async def log_explainer_chat(
    payload: LogChatRequest,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """
    Log Explainer chatbot: explains logs and findings in simple, plain language.
    Strictly follows 5-part template, supports offline knowledge base, and audits queries.
    """
    session_id = payload.session_id or f"LOGCHAT-{user.username}-{uuid.uuid4().hex[:8]}"
    detail_level = payload.detail_level or "simple"
    context = payload.context

    # Audit logging
    print(
        f"[AUDIT] Log Explainer query by user '{user.username}' (session: {session_id}, "
        f"detail: {detail_level}, msg: {payload.message[:60]}...)"
    )

    events_pool: List[dict] = []
    findings_pool: List[dict] = []

    # 1. Gather events from DB if upload_id or event_ids specified
    if context:
        if context.upload_id:
            db_events = db.query(LogEvent).filter(LogEvent.upload_id == context.upload_id).all()
            for e in db_events:
                events_pool.append({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "level": e.level,
                    "source": e.source,
                    "event_id": e.event_id,
                    "message": e.message,
                    "host": e.host,
                    "severity": e.severity,
                    "severity_score": e.severity_score,
                })
            db_findings = db.query(DBFinding).filter(DBFinding.upload_id == context.upload_id).all()
            for f in db_findings:
                findings_pool.append({
                    "id": f.id,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "mitre_technique": f.mitre_technique,
                })
        elif context.event_ids:
            db_events = db.query(LogEvent).filter(LogEvent.id.in_(context.event_ids)).all()
            for e in db_events:
                events_pool.append({
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "level": e.level,
                    "source": e.source,
                    "event_id": e.event_id,
                    "message": e.message,
                    "host": e.host,
                    "severity": e.severity,
                    "severity_score": e.severity_score,
                })

        # Add any raw events supplied directly by client buffer (e.g. real-time mode)
        if context.raw_events:
            for re_item in context.raw_events:
                if re_item not in events_pool:
                    events_pool.append(re_item)

    # 2. Invoke Log Explainer Service
    result = await log_explainer.explain_log(
        message=payload.message,
        context=context,
        events_pool=events_pool,
        findings_pool=findings_pool,
        detail_level=detail_level,
    )

    # 3. Store conversation in database
    user_msg = LogChatMessage(
        user_id=user.id,
        session_id=session_id,
        role="user",
        content=payload.message,
        detail_level=detail_level,
        context_json=json.dumps(context.model_dump() if context else {}),
    )
    db.add(user_msg)

    assistant_msg = LogChatMessage(
        user_id=user.id,
        session_id=session_id,
        role="assistant",
        content=result["answer"],
        detail_level=detail_level,
        context_json=json.dumps(context.model_dump() if context else {}),
        citations_json=json.dumps(result.get("citations", [])),
        severity_json=json.dumps(result["severity_summary"].model_dump()),
        suggested_questions_json=json.dumps(result.get("suggested_questions", [])),
    )
    db.add(assistant_msg)
    db.commit()

    return LogChatResponse(
        session_id=session_id,
        answer=result["answer"],
        severity_summary=result["severity_summary"],
        citations=result.get("citations", []),
        suggested_questions=result.get("suggested_questions", []),
        detail_level=detail_level,
    )


@router.get("/chat/sessions/{session_id}/messages", response_model=List[LogChatMessageOut])
def get_log_chat_messages(
    session_id: str,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Fetch stored message history for a Log Explainer session."""
    msgs = (
        db.query(LogChatMessage)
        .filter(LogChatMessage.session_id == session_id, LogChatMessage.user_id == user.id)
        .order_by(LogChatMessage.created_at.asc())
        .all()
    )
    results = []
    for m in msgs:
        sev_summary = None
        citations = []
        questions = []
        try:
            if m.severity_json:
                sev_summary = json.loads(m.severity_json)
            if m.citations_json:
                citations = json.loads(m.citations_json)
            if m.suggested_questions_json:
                questions = json.loads(m.suggested_questions_json)
        except Exception:
            pass

        results.append(
            LogChatMessageOut(
                id=m.id,
                session_id=m.session_id,
                role=m.role,
                content=m.content,
                detail_level=m.detail_level,
                severity_summary=sev_summary,
                citations=citations,
                suggested_questions=questions,
                created_at=m.created_at,
            )
        )
    return results


@router.post("/chat/sessions/{session_id}/clear")
def clear_log_chat_messages(
    session_id: str,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Clear message history for a Log Explainer session."""
    db.query(LogChatMessage).filter(
        LogChatMessage.session_id == session_id,
        LogChatMessage.user_id == user.id,
    ).delete()
    db.commit()
    return {"status": "ok", "cleared_session": session_id}
