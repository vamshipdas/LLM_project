import asyncio
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import _decode_token, get_current_user, require_any_user
from app.db import get_db
from app.models.db_models import AttackerIP, LogEvent, User
from app.models.schemas import (
    AttackerIPDetail,
    AttackerIPOrigin,
    HomeLocation,
    HomeLocationUpdate,
    LogEventSchema,
)
from app.services.ip_intel import (
    classify_ip,
    ip_intel,
    threat_map_broadcaster,
)

router = APIRouter(prefix="/threat-map", tags=["Threat Map"])
settings_router = APIRouter(prefix="/settings", tags=["Settings"])


def _get_user_from_token_or_query(
    request: Request,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> User:
    """
    Authenticate user via query param (?token=...) or Authorization header.
    Allows EventSource SSE connections without custom headers.
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


@router.get("/origins", response_model=List[AttackerIPOrigin])
def get_attacker_origins(
    upload_id: Optional[str] = Query(None),
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """
    List all attacker IPs with resolved geolocation, event count, max severity,
    first_seen, last_seen, and linked finding IDs.
    """
    query = db.query(AttackerIP)
    if upload_id and upload_id.strip():
        query = query.filter(AttackerIP.upload_id == upload_id.strip())

    records = query.order_by(AttackerIP.updated_at.desc()).all()

    origins: List[AttackerIPOrigin] = []
    for r in records:
        f_ids = []
        try:
            f_ids = json.loads(r.linked_finding_ids or "[]")
        except Exception:
            pass

        origins.append(
            AttackerIPOrigin(
                id=r.id,
                ip=r.ip,
                upload_id=r.upload_id,
                classification=r.classification,
                source=r.source,
                country=r.country,
                country_code=r.country_code,
                city=r.city,
                lat=r.lat,
                lon=r.lon,
                asn=r.asn,
                org=r.org,
                is_tor_or_vpn=r.is_tor_or_vpn,
                event_count=r.event_count,
                max_severity=r.max_severity,
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                linked_finding_ids=f_ids,
                is_active=True,
            )
        )
    return origins


@router.get("/origins/{ip}", response_model=AttackerIPDetail)
def get_attacker_ip_detail(
    ip: str,
    upload_id: Optional[str] = Query(None),
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """
    Detailed attacker record for a specific IP with its linked events.
    """
    query = db.query(AttackerIP).filter(AttackerIP.ip == ip)
    if upload_id:
        query = query.filter(AttackerIP.upload_id == upload_id)
    record = query.first()

    if not record:
        # If not already persisted, attempt on-demand classification & geo
        geo = ip_intel.geolocate_ip(ip, db)
        return AttackerIPDetail(
            id=f"ON_DEMAND-{ip}",
            ip=ip,
            upload_id=upload_id,
            classification=geo.get("classification", "public"),
            source=geo.get("source", "demo"),
            country=geo.get("country"),
            country_code=geo.get("country_code"),
            city=geo.get("city"),
            lat=geo.get("lat"),
            lon=geo.get("lon"),
            asn=geo.get("asn"),
            org=geo.get("org"),
            is_tor_or_vpn=geo.get("is_tor_or_vpn", False),
            event_count=0,
            max_severity="low",
            first_seen=None,
            last_seen=None,
            linked_finding_ids=[],
            is_active=False,
            linked_events=[],
        )

    f_ids = []
    e_ids = []
    try:
        f_ids = json.loads(record.linked_finding_ids or "[]")
        e_ids = json.loads(record.linked_event_ids or "[]")
    except Exception:
        pass

    # Query linked events
    events: List[LogEvent] = []
    if e_ids:
        events = db.query(LogEvent).filter(LogEvent.id.in_(e_ids[:100])).all()
    if not events:
        # Fallback to text match
        events = (
            db.query(LogEvent)
            .filter(LogEvent.message.contains(ip))
            .order_by(LogEvent.created_at.desc())
            .limit(50)
            .all()
        )

    event_schemas = [
        LogEventSchema(
            id=e.id,
            timestamp=e.timestamp,
            level=e.level,
            source=e.source,
            event_id=e.event_id,
            message=e.message,
            host=e.host,
            raw=e.raw,
            severity=e.severity,
            severity_score=e.severity_score,
            severity_reasons=json.loads(e.severity_reasons or "[]"),
        )
        for e in events
    ]

    return AttackerIPDetail(
        id=record.id,
        ip=record.ip,
        upload_id=record.upload_id,
        classification=record.classification,
        source=record.source,
        country=record.country,
        country_code=record.country_code,
        city=record.city,
        lat=record.lat,
        lon=record.lon,
        asn=record.asn,
        org=record.org,
        is_tor_or_vpn=record.is_tor_or_vpn,
        event_count=record.event_count,
        max_severity=record.max_severity,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        linked_finding_ids=f_ids,
        is_active=True,
        linked_events=event_schemas,
    )


@router.get("/stream")
async def stream_threat_map_origins(
    user: User = Depends(_get_user_from_token_or_query),
    db: Session = Depends(get_db),
):
    """
    SSE stream pushing new/updated origins whenever findings or high+ severity events appear.
    Supports ?token=<jwt> for EventSource compatibility.
    """
    q = threat_map_broadcaster.subscribe()

    async def event_generator():
        try:
            # Send initial keepalive/hello message
            initial_data = json.dumps({"type": "connected", "user": user.username})
            yield f"data: {initial_data}\n\n"

            while True:
                try:
                    # Wait up to 15s for new origin, or send ping keepalive
                    origin_data = await asyncio.wait_for(q.get(), timeout=15.0)
                    payload = json.dumps({"type": "origin_update", "data": origin_data})
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            threat_map_broadcaster.unsubscribe(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --- Protected Asset / Home Location Endpoints -----------------------------

@settings_router.get("/home-location", response_model=HomeLocation)
def get_home_location(
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Get the protected asset's current home lat/lon coordinates."""
    loc = ip_intel.get_home_location(db)
    return HomeLocation(**loc)


@settings_router.put("/home-location", response_model=HomeLocation)
def update_home_location(
    payload: HomeLocationUpdate,
    user: User = Depends(require_any_user),
    db: Session = Depends(get_db),
):
    """Update the protected asset's home lat/lon coordinates."""
    loc = ip_intel.set_home_location(
        db,
        lat=payload.lat,
        lon=payload.lon,
        label=payload.label,
    )
    return HomeLocation(**loc)
