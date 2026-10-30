from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import require_any_user
from app.db import get_db
from app.models.db_models import Ticket, User
from app.models.schemas import TicketCreate, TicketOut, TicketSeverityUpdate, TicketStatusUpdate
from app.services.notifier import notifier
from app.services.ticket_service import ticket_service

router = APIRouter(prefix="/tickets", tags=["SOC Tickets"])



@router.get("", response_model=List[TicketOut])
def list_tickets(
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> List[TicketOut]:
    rows = ticket_service.get_all(db)
    return [
        TicketOut(
            id=r.id,
            title=r.title,
            threat_type=r.threat_type,
            severity=r.severity,
            status=r.status,
            source_ip=r.source_ip,
            target_host=r.target_host,
            description=r.description,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/open", response_model=List[TicketOut])
def open_tickets(
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> List[TicketOut]:
    rows = ticket_service.get_open(db)
    return [
        TicketOut(
            id=r.id,
            title=r.title,
            threat_type=r.threat_type,
            severity=r.severity,
            status=r.status,
            source_ip=r.source_ip,
            target_host=r.target_host,
            description=r.description,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("", response_model=TicketOut, status_code=status.HTTP_201_CREATED)
def create_ticket(
    payload: TicketCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_any_user),
) -> Ticket:
    ticket_id = f"TKT-{uuid.uuid4().hex[:10].upper()}"
    ticket = Ticket(
        id=ticket_id,
        title=payload.title,
        threat_type=payload.threat_type,
        severity=payload.severity.lower(),
        status=payload.status,
        source_ip=payload.source_ip,
        target_host=payload.target_host,
        description=payload.description,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    # Trigger notification if severity is high or critical
    if ticket.severity.lower() in ("critical", "high"):
        notifier.send_critical_alert_background(ticket)

    return ticket


@router.patch("/{ticket_id}/status", response_model=TicketOut)
def update_ticket_status(
    ticket_id: str,
    update: TicketStatusUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> Ticket:
    ticket = ticket_service.update_status(db, ticket_id, update.status)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@router.patch("/{ticket_id}/severity", response_model=TicketOut)
def update_ticket_severity(
    ticket_id: str,
    update: TicketSeverityUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> Ticket:
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")

    old_severity = ticket.severity.lower()
    new_severity = update.severity.lower()
    ticket.severity = new_severity
    db.commit()
    db.refresh(ticket)

    # Trigger if updated to high or critical from lower severity
    if new_severity in ("critical", "high") and old_severity not in ("critical", "high"):
        notifier.send_critical_alert_background(ticket)

    return ticket


@router.post("/simulate", response_model=TicketOut)
def simulate_new_threat_ticket(
    db: Session = Depends(get_db),
    _: User = Depends(require_any_user),
) -> Ticket:
    """
    Simulates a new incoming HIGH or CRITICAL security threat incident,
    records it in SQLite, and automatically dispatches an alert email to configured analysts.
    """
    import random
    from datetime import datetime, timezone
    from app.services.ticket_service import _TITLES, _DESCRIPTIONS, _THREAT_TYPES, _IPS, _HOSTS

    threat_idx = random.randint(0, len(_TITLES) - 1)
    severity = random.choice(["HIGH", "CRITICAL"])
    threat_type = _THREAT_TYPES[threat_idx % len(_THREAT_TYPES)]
    ticket_id = f"TKT-{uuid.uuid4().hex[:10].upper()}"

    ticket = Ticket(
        id=ticket_id,
        title=_TITLES[threat_idx],
        threat_type=threat_type,
        severity=severity.lower(),
        status=None,
        source_ip=random.choice(_IPS),
        target_host=random.choice(_HOSTS),
        description=_DESCRIPTIONS[threat_idx],
        created_at=datetime.now(timezone.utc),
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    # Automatically trigger background email notification (force=True ensures immediate delivery without cooldown suppression)
    notifier.send_critical_alert_background(ticket, force=True)

    return ticket

