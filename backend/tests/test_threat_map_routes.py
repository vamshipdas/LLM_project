import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db
from app.services.auth_service import create_access_token


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    token = create_access_token("analyst", "analyst")
    return {"Authorization": f"Bearer {token}"}


def test_get_home_location(client, auth_headers):
    resp = client.get("/api/settings/home-location", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "lat" in data
    assert "lon" in data
    assert "label" in data


def test_update_home_location(client, auth_headers):
    payload = {"lat": 51.5074, "lon": -0.1278, "label": "London SOC Office"}
    resp = client.put("/api/settings/home-location", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["lat"] == 51.5074
    assert data["lon"] == -0.1278
    assert data["label"] == "London SOC Office"

    # Verify get returns updated
    get_resp = client.get("/api/settings/home-location", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["label"] == "London SOC Office"


def test_get_threat_origins(client, auth_headers):
    resp = client.get("/api/threat-map/origins", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_threat_origin_detail(client, auth_headers):
    resp = client.get("/api/threat-map/origins/203.0.113.195", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "203.0.113.195"
    assert data["country"] == "Russian Federation"
    assert data["source"] == "demo"
