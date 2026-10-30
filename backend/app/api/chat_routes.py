import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import require_any_user
from app.db import get_db
from app.models.db_models import ChatMessage, ChatSession, User
from app.models.schemas import (
    ChatMessageOut,
    ChatRequest,
    ChatResponse,
    ChatSessionListOut,
    ChatSessionOut,
)
from app.services.rag_engine import soc_agent

router = APIRouter(prefix="/chat", tags=["SOC Chatbot"])


def _ensure_session(db: Session, user: User, session_id: str) -> ChatSession:
    session = (
        db.query(ChatSession)
        .filter(ChatSession.id == session_id, ChatSession.user_id == user.id)
        .first()
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Chat session not found")
    return session


def _save_message(db: Session, session: ChatSession, role: str, content: str) -> ChatMessage:
    msg = ChatMessage(session_id=session.id, role=role, content=content)
    db.add(msg)
    session.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(msg)
    return msg


@router.post("", response_model=ChatSessionListOut, status_code=201)
def new_chat(
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> ChatSessionListOut:
    session = ChatSession(user_id=user.id, title="New Chat")
    db.add(session)
    db.commit()
    db.refresh(session)
    return ChatSessionListOut(
        id=session.id, title=session.title, updated_at=session.updated_at
    )


@router.get("/sessions", response_model=List[ChatSessionListOut])
def list_sessions(
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
    include_archived: bool = False,
) -> List[ChatSessionListOut]:
    query = db.query(ChatSession).filter(ChatSession.user_id == user.id)
    if not include_archived:
        query = query.filter(ChatSession.archived == False)  # noqa: E712
    rows = query.order_by(ChatSession.updated_at.desc()).all()
    return [
        ChatSessionListOut(id=r.id, title=r.title, updated_at=r.updated_at)
        for r in rows
    ]


@router.get("/sessions/{session_id}/messages", response_model=List[ChatMessageOut])
def get_messages(
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> List[ChatMessageOut]:
    session = _ensure_session(db, user, session_id)
    return [
        ChatMessageOut(
            id=m.id,
            session_id=m.session_id,
            role=m.role,
            content=m.content,
            created_at=m.created_at,
        )
        for m in session.messages
    ]


@router.post("/sessions/{session_id}/message", response_model=ChatResponse)
async def send_message(
    session_id: str,
    request: ChatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> ChatResponse:
    session = _ensure_session(db, user, session_id)

    # Capture prior context before persisting the current turn.
    history = [
        {"role": m.role, "content": m.content} for m in session.messages
    ]
    _save_message(db, session, "user", request.message)

    recommendation = await soc_agent.chat(request.message, history)

    # Persist assistant reply
    _save_message(db, session, "assistant", recommendation.message)

    # Update session title from first user message if still default
    if session.title == "New Chat":
        session.title = request.message[:60]
        db.commit()

    return ChatResponse(
        session_id=session.id,
        message=recommendation.message,
        sources=recommendation.sources,
    )


@router.post("/sessions/{session_id}/stream")
async def stream_message(
    session_id: str,
    request: ChatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> StreamingResponse:
    session = _ensure_session(db, user, session_id)
    history = [{"role": m.role, "content": m.content} for m in session.messages]
    _save_message(db, session, "user", request.message)

    async def events():
        answer = []
        sources = []
        async for event in soc_agent.stream(request.message, history):
            if event["type"] == "delta":
                answer.append(event["content"])
            elif event["type"] == "sources":
                sources = event["sources"]
            yield json.dumps(event, ensure_ascii=False) + "\n"

        message = "".join(answer)
        _save_message(db, session, "assistant", message)
        if session.title == "New Chat":
            session.title = request.message[:60]
            db.commit()
        yield json.dumps({"type": "done", "message": message, "sources": sources}, ensure_ascii=False) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson")


@router.patch("/sessions/{session_id}/archive", response_model=ChatSessionListOut)
def archive_session(
    session_id: str,
    archived: bool,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> ChatSessionListOut:
    session = _ensure_session(db, user, session_id)
    session.archived = archived
    session.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(session)
    return ChatSessionListOut(
        id=session.id, title=session.title, updated_at=session.updated_at,
        archived=session.archived,
    )


@router.delete("/sessions/{session_id}", status_code=204)
def delete_session(
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> None:
    session = _ensure_session(db, user, session_id)
    db.delete(session)
    db.commit()
