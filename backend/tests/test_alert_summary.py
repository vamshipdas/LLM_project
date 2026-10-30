"""
Tests for Alert Summary and Alert Context Builder (Phase 1).
Validates:
- Plain language transformation with bracketed explanations
- Computed severity engine preservation
- Geolocation origin resolution & DEMO/INTERNAL/PUBLIC badges
- SOP step extraction and citation chips
- Trajectory prediction service top-3 computed probabilities
- Alert summary HTTP endpoint and caching
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app, _seed
from app.db import SessionLocal
from app.models.db_models import Ticket, User
from app.services.alert_context import alert_context_builder, _humanize_text, invalidate_alert_cache
from app.services.trajectory import predict_next_techniques
from app.services.auth_service import create_access_token


@pytest.fixture(scope="module")
def setup_data():
    _seed()
    db = SessionLocal()
    user = db.query(User).filter(User.username == "analyst").first()
    token = create_access_token(user.username, user.role.value)
    ticket = db.query(Ticket).first()
    db.close()
    return {"token": token, "ticket_id": ticket.id if ticket else "TKT-3A97B17048"}


def test_humanize_text_brackets():
    """Verify that technical terms are explained in brackets in plain language."""
    raw = "Attacker performed brute force and lateral movement."
    humanized = _humanize_text(raw)
    assert "brute force (someone guessing passwords repeatedly)" in humanized
    assert "lateral movement (jumping from one infected computer to others inside the network)" in humanized


def test_trajectory_prediction_computed_numbers():
    """Verify MITRE trajectory predictions are computed from ATT&CK graph."""
    res = predict_next_techniques(
        observed_technique="T1110",
        threat_type="brute_force",
        severity="HIGH",
    )
    assert len(res) == 3
    for pred in res:
        assert "technique_id" in pred
        assert "probability_pct" in pred
        assert 0 <= pred["probability_pct"] <= 100
        assert "rationale" in pred
        assert "name" in pred


def test_alert_context_builder_summary(setup_data):
    """Test unified summary generation for ticket alert."""
    ticket_id = setup_data["ticket_id"]
    db = SessionLocal()
    try:
        summary = alert_context_builder.build_summary(
            alert_type="ticket",
            alert_id=ticket_id,
            mode="simple",
            db=db,
        )
        assert summary["id"] == ticket_id
        assert summary["alert_type"] == "ticket"
        assert "what_happened" in summary
        assert "why_it_matters" in summary
        assert summary["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "severity_reason" in summary
        assert "origin" in summary
        assert summary["origin"]["badge"] in ("DEMO", "INTERNAL", "PUBLIC")
        assert "sop_actions" in summary
        assert len(summary["sop_actions"]["steps"]) > 0
        assert "trajectory" in summary
        assert len(summary["trajectory"]) == 3
        assert "sanitized_data_block" in summary
        assert "<ALERT_DATA>" in summary["sanitized_data_block"]
    finally:
        db.close()


def test_summary_api_endpoint(setup_data):
    """Test HTTP GET /api/v1/alerts/{alert_type}/{id}/summary."""
    client = TestClient(app)
    ticket_id = setup_data["ticket_id"]
    headers = {"Authorization": f"Bearer {setup_data['token']}"}

    resp = client.get(f"/api/v1/alerts/ticket/{ticket_id}/summary?mode=simple", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == ticket_id
    assert "what_happened" in data
    assert "origin" in data
    assert "trajectory" in data
    assert len(data["trajectory"]) == 3


def test_summary_cache_and_invalidation():
    """Verify summary caching and cache invalidation."""
    db = SessionLocal()
    try:
        s1 = alert_context_builder.build_summary("ip", "203.0.113.45", "simple", db=db)
        s2 = alert_context_builder.build_summary("ip", "203.0.113.45", "simple", db=db)
        assert s1 is s2  # Cached instance returned

        invalidate_alert_cache("ip", "203.0.113.45")
        s3 = alert_context_builder.build_summary("ip", "203.0.113.45", "simple", db=db)
        assert s1 is not s3  # Regenerated instance
    finally:
        db.close()
