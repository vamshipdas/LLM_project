"""Simulated SOC ticket data for the right-hand tickets panel."""

import random
from datetime import datetime, timedelta, timezone
from typing import List

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.db_models import Ticket

_TITLES = [
    "Suspicious login from unknown IP",
    "Possible ransomware encryption activity",
    "Phishing email reported by user",
    "Brute-force attempts on SSH",
    "Data exfiltration to external domain",
    "Malware beaconing detected",
    "Privilege escalation attempt",
    "Unauthorized access to file share",
]

_DESCRIPTIONS = [
    "Multiple failed logins followed by a successful auth from an unfamiliar geolocation.",
    "Files on the workstation are being renamed with a strange extension; ransom note detected.",
    "User reported a suspicious email with a malicious attachment and link.",
    "High volume of authentication attempts against the SSH service.",
    "Large outbound transfer to an external IP outside business hours.",
    "Endpoint beaconing to a known malicious C2 domain every 5 minutes.",
    "User added to local administrators group without a change ticket.",
    "Sensitive files accessed from a host with no prior history of access.",
]

_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_THREAT_TYPES = [
    "unauthorized_access",
    "ransomware",
    "phishing",
    "brute_force",
    "data_exfiltration",
    "malware",
    "unauthorized_access",
    "unauthorized_access",
]
_IPS = ["203.0.113.45", "198.51.100.22", "192.0.2.10", "10.0.0.99", "172.16.5.4"]
_HOSTS = [
    "WKSTN-0142",
    "SRV-FILE-03",
    "DC-01",
    "WKSTN-0881",
    "SRV-WEB-07",
    "LAPTOP-EXEC-02",
]


class TicketService:
    def __init__(self) -> None:
        self._seeded = False

    def seed_initial_tickets(self, db: Session, count: int = 12) -> None:
        if self._seeded:
            return
        existing = db.query(Ticket).count()
        if existing > 0:
            self._seeded = True
            return
        now = datetime.now(timezone.utc)
        tickets = []
        for i in range(count):
            severity = random.choice(_SEVERITIES)
            threat = random.choice(_THREAT_TYPES)
            tickets.append(
                Ticket(
                    title=_TITLES[i % len(_TITLES)],
                    threat_type=threat,
                    severity=severity,
                    status=None,
                    source_ip=random.choice(_IPS),
                    target_host=random.choice(_HOSTS),
                    description=_DESCRIPTIONS[i % len(_DESCRIPTIONS)],
                    created_at=now - timedelta(hours=random.randint(0, 72)),
                )
            )
        db.add_all(tickets)
        db.commit()
        self._seeded = True

    def get_all(self, db: Session) -> List[Ticket]:
        return (
            db.query(Ticket)
            .order_by(Ticket.created_at.desc())
            .all()
        )

    def get_open(self, db: Session) -> List[Ticket]:
        return (
            db.query(Ticket)
            .filter(or_(Ticket.status.is_(None), Ticket.status != "resolved"))
            .order_by(Ticket.created_at.desc())
            .all()
        )

    def update_status(self, db: Session, ticket_id: str, status: str | None) -> Ticket | None:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if ticket is None:
            return None
        ticket.status = status
        db.commit()
        db.refresh(ticket)
        return ticket


ticket_service = TicketService()
