import os
from unittest.mock import patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.db_models import Base, IPGeoCache, AttackerIP
from app.services.ip_intel import (
    classify_ip,
    extract_ips_from_text,
    extract_ip_from_event,
    IPIntelService,
)


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_ip_classification_private():
    # RFC 1918
    for ip in ["192.168.1.1", "10.0.0.5", "172.16.50.2", "172.31.255.254"]:
        res = classify_ip(ip)
        assert res["is_valid"] is True
        assert res["is_routable"] is False
        assert res["category"] == "private"


def test_ip_classification_loopback_and_link_local():
    assert classify_ip("127.0.0.1")["category"] == "loopback"
    assert classify_ip("::1")["category"] == "loopback"
    assert classify_ip("169.254.1.1")["category"] == "link_local"
    assert classify_ip("fe80::1")["category"] == "link_local"


def test_ip_classification_documentation_ranges():
    # RFC 5737 and RFC 3849
    for ip in ["192.0.2.1", "198.51.100.23", "203.0.113.195", "2001:db8::1"]:
        res = classify_ip(ip)
        assert res["is_valid"] is True
        assert res["is_routable"] is False
        assert res["is_documentation"] is True
        assert res["category"] == "documentation"


def test_ip_classification_public():
    for ip in ["8.8.8.8", "1.1.1.1", "142.250.190.46", "2607:f8b0:4005:805::200e"]:
        res = classify_ip(ip)
        assert res["is_valid"] is True
        assert res["is_routable"] is True
        assert res["category"] == "public"


def test_private_and_documentation_never_hit_external_service(test_db):
    """
    CRITICAL ACCEPTANCE CRITERIA:
    Private, non-routable, and documentation IPs must NEVER trigger external HTTP requests.
    """
    service = IPIntelService()

    with patch("urllib.request.urlopen") as mock_url:
        # 1. Private RFC1918
        res_priv = service.geolocate_ip("192.168.1.50", test_db)
        assert res_priv["source"] == "internal"
        assert res_priv["country"] == "Internal Network"
        mock_url.assert_not_called()

        # 2. Loopback
        res_loop = service.geolocate_ip("127.0.0.1", test_db)
        assert res_loop["source"] == "internal"
        mock_url.assert_not_called()

        # 3. Documentation range (demo override)
        res_doc = service.geolocate_ip("203.0.113.195", test_db)
        assert res_doc["source"] == "demo"
        mock_url.assert_not_called()


def test_demo_overrides_loaded_correctly(test_db):
    service = IPIntelService()
    res = service.geolocate_ip("203.0.113.195", test_db)
    assert res["source"] == "demo"
    assert res["country"] == "Russian Federation"
    assert res["city"] == "Moscow"
    assert res["lat"] == 55.7558
    assert res["lon"] == 37.6173


def test_sqlite_geo_cache_ttl(test_db):
    service = IPIntelService()
    # First lookup populates cache
    geo1 = service.geolocate_ip("203.0.113.195", test_db)
    cached = test_db.query(IPGeoCache).filter(IPGeoCache.ip == "203.0.113.195").first()
    assert cached is not None
    assert cached.city == "Moscow"
    assert cached.expires_at is not None

    # Second lookup hits cache without reloading
    geo2 = service.geolocate_ip("203.0.113.195", test_db)
    assert geo2["city"] == "Moscow"


def test_extract_ips_from_text_and_event():
    text1 = 'Failed password for invalid user admin from 203.0.113.195 port 54101 ssh2'
    assert "203.0.113.195" in extract_ips_from_text(text1)

    text2 = 'Windows Event 4625 Source Network Address: 198.51.100.23'
    assert "198.51.100.23" in extract_ips_from_text(text2)

    evt = {
        "message": text1,
        "raw": text1,
        "source_ip": "203.0.113.195",
    }
    assert extract_ip_from_event(evt) == "203.0.113.195"


def test_process_and_link_ips(test_db):
    service = IPIntelService()
    events = [
        {
            "id": "EVT-1",
            "timestamp": "2026-10-21T21:04:10",
            "message": "Failed login from 203.0.113.195",
            "severity": "high",
        },
        {
            "id": "EVT-2",
            "timestamp": "2026-10-21T21:05:00",
            "message": "Accepted password for root from 203.0.113.195",
            "severity": "critical",
        },
    ]
    findings = [
        {
            "id": "FND-1",
            "title": "Brute Force Authentication",
            "description": "Failed logins from 203.0.113.195",
            "evidence": ["EVT-1"],
            "severity": "high",
        }
    ]

    linked = service.process_and_link_ips(test_db, events, upload_id="UPL-TEST", findings=findings)
    assert len(linked) == 1
    item = linked[0]
    assert item["ip"] == "203.0.113.195"
    assert item["max_severity"] == "critical"
    assert item["country"] == "Russian Federation"
    assert "FND-1" in item["linked_finding_ids"]
    assert item["event_count"] >= 2
