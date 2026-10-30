"""
Alerts API Router.
Endpoints for unified alert summary, status management, and audit logging.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_any_user
from app.db import get_db
from app.models.db_models import Finding as DBFinding, Ticket, User
from app.services.alert_context import alert_context_builder, invalidate_alert_cache

router = APIRouter(prefix="/alerts", tags=["Alert Intelligence"])


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="Status value: 'open', 'in_progress', or 'resolved'")


@router.get("/{alert_type}/{alert_id}/summary")
def get_alert_summary(
    alert_type: str,
    alert_id: str,
    mode: str = Query("simple", pattern="^(simple|technical)$"),
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Returns full unified summary payload for an alert (ticket, finding, log, or ip).
    Includes plain-language explanations with bracketed terms, computed severity reasons,
    SOP actions with citations, false positive likelihood, and MITRE trajectory predictions.
    """
    print(f"[AUDIT] User '{user.username}' viewed alert summary for {alert_type}:{alert_id} (mode={mode})")

    try:
        summary = alert_context_builder.build_summary(
            alert_type=alert_type,
            alert_id=alert_id,
            mode=mode,
            db=db,
        )
        return summary
    except Exception as e:
        print(f"[ERROR] Failed to build alert summary for {alert_type}:{alert_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate alert summary: {str(e)}",
        )


@router.patch("/{alert_type}/{alert_id}/status")
def update_alert_status(
    alert_type: str,
    alert_id: str,
    payload: AlertStatusUpdate,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Updates the triage status of an alert (open, in_progress, resolved).
    Invalidates cached summaries.
    """
    new_status = payload.status.lower().strip()
    if new_status not in ("open", "in_progress", "resolved", "untriaged"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status must be one of: open, in_progress, resolved",
        )

    print(f"[AUDIT] User '{user.username}' changed status of {alert_type}:{alert_id} to '{new_status}'")

    updated = False
    a_type = alert_type.lower()

    if a_type == "ticket":
        ticket = db.query(Ticket).filter(Ticket.id == alert_id).first()
        if ticket:
            ticket.status = new_status if new_status != "open" else None
            db.commit()
            updated = True
    elif a_type == "finding":
        finding = db.query(DBFinding).filter(DBFinding.id == alert_id).first()
        if finding and finding.ticket_id:
            ticket = db.query(Ticket).filter(Ticket.id == finding.ticket_id).first()
            if ticket:
                ticket.status = new_status if new_status != "open" else None
                db.commit()
                updated = True

    # Invalidate cached summaries
    invalidate_alert_cache(alert_type, alert_id)

    return {
        "id": alert_id,
        "alert_type": alert_type,
        "status": new_status,
        "updated_in_db": updated,
        "message": f"Alert status updated to {new_status}",
    }
