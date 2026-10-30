import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.request

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

from sqlalchemy.orm import Session

from app.config import settings
from app.models.db_models import AttackerIP, IPGeoCache, LogEvent, SystemSetting, utcnow

# Documentation & non-routable test networks
DOC_NETWORKS_V4 = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking (RFC 2544)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use (RFC 1112)
    ipaddress.ip_network("0.0.0.0/8"),         # "This host on this network"
]
DOC_NETWORKS_V6 = [
    ipaddress.ip_network("2001:db8::/32"),     # Documentation (RFC 3849)
    ipaddress.ip_network("100::/64"),          # Discard prefix (RFC 6666)
    ipaddress.ip_network("::/128"),            # Unspecified
]

# Common regex patterns to match candidate IPs in logs
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
)

# Specific log field extraction patterns
_SRC_ADDR_PATTERNS = [
    re.compile(r"Source Network Address:\s+([0-9a-fA-F\.\:]+)", re.IGNORECASE),
    re.compile(r"Source Address:\s+([0-9a-fA-F\.\:]+)", re.IGNORECASE),
    re.compile(r"\bfrom\s+([0-9a-fA-F\.\:]+)(?:\s+port\b|\b)", re.IGNORECASE),
    re.compile(r"\bSRC=([0-9a-fA-F\.\:]+)\b", re.IGNORECASE),
    re.compile(r"\bsrc_ip=([0-9a-fA-F\.\:]+)\b", re.IGNORECASE),
    re.compile(r"\bclient\s+([0-9a-fA-F\.\:]+)\b", re.IGNORECASE),
    re.compile(r"\bclient_ip=([0-9a-fA-F\.\:]+)\b", re.IGNORECASE),
    re.compile(r"\brhost=([0-9a-fA-F\.\:]+)\b", re.IGNORECASE),
]


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """
    Classify an IPv4 or IPv6 address prior to any lookup.
    Guarantees private and documentation IPs are tagged properly so they are
    NEVER sent to any external geolocation service.
    """
    cleaned = (ip_str or "").strip().strip("[]\"'")
    if not cleaned:
        return {
            "ip": ip_str,
            "is_valid": False,
            "is_routable": False,
            "is_documentation": False,
            "category": "invalid",
        }

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return {
            "ip": cleaned,
            "is_valid": False,
            "is_routable": False,
            "is_documentation": False,
            "category": "invalid",
        }

    # 1. Loopback
    if ip_obj.is_loopback:
        return {
            "ip": cleaned,
            "is_valid": True,
            "is_routable": False,
            "is_documentation": False,
            "category": "loopback",
        }

    # 2. Link-Local
    if ip_obj.is_link_local:
        return {
            "ip": cleaned,
            "is_valid": True,
            "is_routable": False,
            "is_documentation": False,
            "category": "link_local",
        }

    # 3. Multicast
    if ip_obj.is_multicast:
        return {
            "ip": cleaned,
            "is_valid": True,
            "is_routable": False,
            "is_documentation": False,
            "category": "multicast",
        }

    # 4. Reserved
    if ip_obj.is_reserved or ip_obj.is_unspecified:
        return {
            "ip": cleaned,
            "is_valid": True,
            "is_routable": False,
            "is_documentation": False,
            "category": "reserved",
        }

    # 5. Documentation / Test networks (RFC 5737 / RFC 3849 / etc.)
    if ip_obj.version == 4:
        for net in DOC_NETWORKS_V4:
            if ip_obj in net:
                return {
                    "ip": cleaned,
                    "is_valid": True,
                    "is_routable": False,
                    "is_documentation": True,
                    "category": "documentation",
                }
    else:
        for net in DOC_NETWORKS_V6:
            if ip_obj in net:
                return {
                    "ip": cleaned,
                    "is_valid": True,
                    "is_routable": False,
                    "is_documentation": True,
                    "category": "documentation",
                }

    # 6. Private (RFC 1918, RFC 4193, etc.)
    if ip_obj.is_private:
        return {
            "ip": cleaned,
            "is_valid": True,
            "is_routable": False,
            "is_documentation": False,
            "category": "private",
        }

    # 7. Public / Globally routable
    is_global = getattr(ip_obj, "is_global", None)
    if is_global is None:
        # Python versions where is_global might not be present
        is_global = not ip_obj.is_private and not ip_obj.is_reserved

    return {
        "ip": cleaned,
        "is_valid": True,
        "is_routable": bool(is_global),
        "is_documentation": False,
        "category": "public" if is_global else "non_routable",
    }


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract all valid IPv4 and IPv6 addresses found within raw log text or message.
    Prioritizes explicit source address patterns, then general IP regex.
    """
    if not text:
        return []

    found: List[str] = []
    seen: Set[str] = set()

    def add_if_valid(candidate: str):
        c = candidate.strip().strip("[]\"',;:")
        if not c or c in seen:
            return
        info = classify_ip(c)
        if info["is_valid"]:
            seen.add(c)
            found.append(c)

    # 1. Targeted patterns
    for pat in _SRC_ADDR_PATTERNS:
        for match in pat.finditer(text):
            add_if_valid(match.group(1))

    # 2. General IPv4
    for match in _IPV4_RE.finditer(text):
        add_if_valid(match.group(0))

    # 3. General IPv6
    for match in _IPV6_RE.finditer(text):
        add_if_valid(match.group(0))

    return found


def extract_ip_from_event(evt: Dict[str, Any]) -> Optional[str]:
    """
    Extract the primary external or source IP from a structured or raw event dictionary.
    """
    for field in ["source_ip", "src_ip", "client_ip", "attacker_ip"]:
        val = evt.get(field)
        if val:
            info = classify_ip(str(val))
            if info["is_valid"]:
                return str(val).strip()

    msg = evt.get("message", "")
    raw = evt.get("raw", "")
    combined = f"{msg} {raw}"
    ips = extract_ips_from_text(combined)
    if ips:
        # Prefer public or documentation IPs over private ones if both exist
        for candidate in ips:
            c_info = classify_ip(candidate)
            if c_info["category"] in ("public", "documentation"):
                return candidate
        return ips[0]

    # Host fallback if host looks like an IP
    host = evt.get("host", "")
    if host:
        info = classify_ip(host)
        if info["is_valid"]:
            return host.strip()

    return None


class ThreatMapBroadcaster:
    """Pub/Sub broadcaster for live Server-Sent Events (SSE)."""

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def broadcast(self, data: Dict[str, Any]) -> None:
        """Push origin payload to all active SSE listener queues."""
        for q in list(self._subscribers):
            try:
                q.put_nowait(data)
            except Exception:
                self._subscribers.discard(q)


threat_map_broadcaster = ThreatMapBroadcaster()


class IPIntelService:
    def __init__(self):
        self._demo_overrides: Dict[str, Dict[str, Any]] = {}
        self.load_demo_overrides()

    def load_demo_overrides(self) -> None:
        """Load fake geo overrides for documentation and demo IPs."""
        overrides_path = settings.DEMO_GEO_OVERRIDES_FILE
        if os.path.exists(overrides_path):
            try:
                with open(overrides_path, "r", encoding="utf-8") as f:
                    self._demo_overrides = json.load(f)
            except Exception as e:
                print(f"[WARN] Failed to load demo_geo_overrides.json: {e}")
                self._demo_overrides = {}
        else:
            self._demo_overrides = {}

    def get_home_location(self, db: Session) -> Dict[str, Any]:
        """Fetch home/asset protected coordinates from database or fallback to settings."""
        record = db.query(SystemSetting).filter(SystemSetting.key == "home_location").first()
        if record and record.value:
            try:
                data = json.loads(record.value)
                return {
                    "lat": float(data.get("lat", settings.DEFAULT_HOME_LAT)),
                    "lon": float(data.get("lon", settings.DEFAULT_HOME_LON)),
                    "label": str(data.get("label", settings.DEFAULT_HOME_LABEL)),
                }
            except Exception:
                pass
        return {
            "lat": settings.DEFAULT_HOME_LAT,
            "lon": settings.DEFAULT_HOME_LON,
            "label": settings.DEFAULT_HOME_LABEL,
        }

    def set_home_location(self, db: Session, lat: float, lon: float, label: Optional[str] = None) -> Dict[str, Any]:
        """Persist updated home/asset coordinates."""
        data = {
            "lat": float(lat),
            "lon": float(lon),
            "label": label or settings.DEFAULT_HOME_LABEL,
        }
        record = db.query(SystemSetting).filter(SystemSetting.key == "home_location").first()
        if not record:
            record = SystemSetting(key="home_location", value=json.dumps(data))
            db.add(record)
        else:
            record.value = json.dumps(data)
            record.updated_at = utcnow()
        db.commit()
        return data

    def resolve_ip(self, *args, **kwargs) -> Dict[str, Any]:
        """Flexible resolver accepting (ip, db) or (db, ip)."""
        if len(args) == 2:
            if isinstance(args[0], str):
                return self.geolocate_ip(args[0], args[1])
            return self.geolocate_ip(args[1], args[0])
        elif "ip" in kwargs and "db" in kwargs:
            return self.geolocate_ip(kwargs["ip"], kwargs["db"])
        raise ValueError("resolve_ip requires both 'ip' and 'db' arguments")

    def geolocate_ip(self, ip: str, db: Session) -> Dict[str, Any]:
        """
        Geolocate an IP address offline-first with strict security boundaries:
        1. Classify IP. If private/loopback/link-local: return internal without external lookup.
        2. Check SQLite cache with TTL (24h).
        3. Check demo overrides (for documentation ranges or demo IPs).
        4. Query local MaxMind GeoLite2 (.mmdb) offline database if public and available.
        5. Online fallback ONLY if ENABLE_ONLINE_GEOIP is explicitly enabled and IP is public.
        6. Cache result in SQLite.
        """
        classification = classify_ip(ip)
        category = classification["category"]

        # Private / loopback / link-local / multicast / reserved -> NEVER call external service
        if category in ("private", "loopback", "link_local", "multicast", "reserved", "invalid"):
            return {
                "ip": ip,
                "country": "Internal Network" if category == "private" else category.capitalize(),
                "country_code": "INT",
                "city": "RFC1918 / Non-Routable",
                "lat": None,
                "lon": None,
                "asn": "AS0",
                "org": "Internal / Non-Routable Infrastructure",
                "is_tor_or_vpn": False,
                "source": "internal",
                "classification": category,
            }

        # Check SQLite Cache first
        now = datetime.now(timezone.utc)
        cached = db.query(IPGeoCache).filter(IPGeoCache.ip == ip).first()
        if cached:
            # Check expiration (24h TTL)
            if cached.expires_at is None or cached.expires_at.replace(tzinfo=timezone.utc) > now:
                return {
                    "ip": cached.ip,
                    "country": cached.country,
                    "country_code": cached.country_code,
                    "city": cached.city,
                    "lat": cached.lat,
                    "lon": cached.lon,
                    "asn": cached.asn,
                    "org": cached.org,
                    "is_tor_or_vpn": cached.is_tor_or_vpn,
                    "source": cached.source,
                    "classification": cached.classification,
                }

        # Check demo overrides (especially useful for RFC 5737 documentation IPs)
        if ip in self._demo_overrides:
            demo_val = dict(self._demo_overrides[ip])
            demo_val["source"] = "demo"
            demo_val["classification"] = category
            self._save_cache(db, demo_val)
            return demo_val

        if classification["is_documentation"]:
            # If in documentation range without a specific override, generate deterministic demo coordinate
            demo_val = self._generate_fallback_demo_geo(ip, category)
            self._save_cache(db, demo_val)
            return demo_val

        # MaxMind GeoLite2 City (.mmdb) Offline lookup
        mmdb_res = self._lookup_mmdb(ip)
        if mmdb_res:
            mmdb_res["classification"] = category
            self._save_cache(db, mmdb_res)
            return mmdb_res

        # Optional online fallback ONLY if ENABLE_ONLINE_GEOIP=True and IP is routable public
        if settings.ENABLE_ONLINE_GEOIP and classification["is_routable"]:
            online_res = self._lookup_online(ip)
            if online_res:
                online_res["classification"] = category
                self._save_cache(db, online_res)
                return online_res

        # Fallback if no database and online disabled
        fallback = {
            "ip": ip,
            "country": "Unknown Origin",
            "country_code": "UNK",
            "city": "Unknown City",
            "lat": 0.0,
            "lon": 0.0,
            "asn": None,
            "org": "Public IP (GeoLite2 not loaded)",
            "is_tor_or_vpn": False,
            "source": "offline_unknown",
            "classification": category,
        }
        self._save_cache(db, fallback)
        return fallback

    def _generate_fallback_demo_geo(self, ip: str, category: str) -> Dict[str, Any]:
        """Deterministic location for unlisted documentation IPs."""
        # Simple hash to deterministic coordinates on earth
        h = sum(ord(c) for c in ip)
        lat = ((h * 17) % 120) - 60.0
        lon = ((h * 31) % 360) - 180.0
        return {
            "ip": ip,
            "country": "Demo Threat Origin",
            "country_code": "DM",
            "city": "Simulated Node",
            "lat": round(lat, 4),
            "lon": round(lon, 4),
            "asn": "AS64512",
            "org": "Demo Documentation Subnet",
            "is_tor_or_vpn": False,
            "source": "demo",
            "classification": category,
        }

    def _lookup_mmdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query local MaxMind GeoLite2 City database if available."""
        if not GEOIP2_AVAILABLE:
            return None

        db_path = settings.GEOIP_DB_PATH
        if not db_path or not os.path.exists(db_path):
            return None

        try:
            with geoip2.database.Reader(db_path) as reader:
                resp = reader.city(ip)
                asn = None
                org = None

                # Optional ASN lookup if ASN mmdb exists
                asn_path = settings.GEOIP_ASN_DB_PATH
                if asn_path and os.path.exists(asn_path):
                    try:
                        with geoip2.database.Reader(asn_path) as asn_reader:
                            asn_resp = asn_reader.asn(ip)
                            asn = f"AS{asn_resp.autonomous_system_number}"
                            org = asn_resp.autonomous_system_organization
                    except Exception:
                        pass

                return {
                    "ip": ip,
                    "country": resp.country.name or "Unknown Country",
                    "country_code": resp.country.iso_code or "UNK",
                    "city": resp.city.name or "Unknown City",
                    "lat": float(resp.location.latitude or 0.0),
                    "lon": float(resp.location.longitude or 0.0),
                    "asn": asn,
                    "org": org,
                    "is_tor_or_vpn": False,
                    "source": "mmdb",
                }
        except Exception as e:
            print(f"[WARN] GeoLite2 lookup error for {ip}: {e}")
            return None

    def _lookup_online(self, ip: str) -> Optional[Dict[str, Any]]:
        """Online fallback lookup via ip-api.com (only when enabled)."""
        # Extra safety check: NEVER allow private or documentation IPs here
        cls = classify_ip(ip)
        if not cls["is_routable"] or cls["is_documentation"]:
            return None

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,as,org"
            req = urllib.request.Request(url, headers={"User-Agent": "CyberLLM-SOC/1.0"})
            with urllib.request.urlopen(req, timeout=2.5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    if data.get("status") == "success":
                        as_field = data.get("as", "")
                        asn = as_field.split(" ")[0] if as_field else None
                        return {
                            "ip": ip,
                            "country": data.get("country", "Unknown Country"),
                            "country_code": data.get("countryCode", "UNK"),
                            "city": data.get("city", "Unknown City"),
                            "lat": float(data.get("lat", 0.0)),
                            "lon": float(data.get("lon", 0.0)),
                            "asn": asn,
                            "org": data.get("org") or data.get("as"),
                            "is_tor_or_vpn": False,
                            "source": "online",
                        }
        except Exception as e:
            print(f"[WARN] Online GeoIP lookup failed for {ip}: {e}")
        return None

    def _save_cache(self, db: Session, geo_data: Dict[str, Any]) -> None:
        """Cache resolved geolocation in SQLite with 24h TTL."""
        try:
            ip = geo_data["ip"]
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            existing = db.query(IPGeoCache).filter(IPGeoCache.ip == ip).first()
            if existing:
                existing.country = geo_data.get("country")
                existing.country_code = geo_data.get("country_code")
                existing.city = geo_data.get("city")
                existing.lat = geo_data.get("lat")
                existing.lon = geo_data.get("lon")
                existing.asn = geo_data.get("asn")
                existing.org = geo_data.get("org")
                existing.is_tor_or_vpn = geo_data.get("is_tor_or_vpn", False)
                existing.source = geo_data.get("source", "demo")
                existing.classification = geo_data.get("classification", "public")
                existing.cached_at = utcnow()
                existing.expires_at = expires_at
            else:
                db_record = IPGeoCache(
                    ip=ip,
                    country=geo_data.get("country"),
                    country_code=geo_data.get("country_code"),
                    city=geo_data.get("city"),
                    lat=geo_data.get("lat"),
                    lon=geo_data.get("lon"),
                    asn=geo_data.get("asn"),
                    org=geo_data.get("org"),
                    is_tor_or_vpn=geo_data.get("is_tor_or_vpn", False),
                    source=geo_data.get("source", "demo"),
                    classification=geo_data.get("classification", "public"),
                    cached_at=utcnow(),
                    expires_at=expires_at,
                )
                db.add(db_record)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[WARN] Failed to write IPGeoCache for {geo_data.get('ip')}: {e}")

    def process_and_link_ips(
        self,
        db: Session,
        events: List[Dict[str, Any]],
        upload_id: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extract IPs from all events and findings, geolocate them, persist AttackerIP records,
        and trigger SSE broadcasts for external origins with high/critical severity or findings.
        """
        if not events:
            return []

        # Map IP -> event ids, timestamps, severities
        ip_map: Dict[str, Dict[str, Any]] = {}

        severity_rank = {"low": 10, "medium": 20, "high": 30, "critical": 40}

        for evt in events:
            evt_id = evt.get("id") or ""
            ts = evt.get("timestamp") or ""
            sev = (evt.get("severity") or "low").lower()

            extracted = extract_ips_from_text(f"{evt.get('message', '')} {evt.get('raw', '')}")
            primary = extract_ip_from_event(evt)
            if primary and primary not in extracted:
                extracted.append(primary)

            for ip_str in extracted:
                info = classify_ip(ip_str)
                if not info["is_valid"]:
                    continue

                if ip_str not in ip_map:
                    ip_map[ip_str] = {
                        "ip": ip_str,
                        "events": [],
                        "severities": [],
                        "timestamps": [],
                        "finding_ids": set(),
                    }

                if evt_id:
                    ip_map[ip_str]["events"].append(evt_id)
                if sev:
                    ip_map[ip_str]["severities"].append(sev)
                if ts:
                    ip_map[ip_str]["timestamps"].append(ts)

        # Correlate findings evidence with IPs
        if findings:
            for f in findings:
                f_id = f.get("id")
                ev_list = f.get("evidence") or []
                f_sev = (f.get("severity") or "medium").lower()

                # If finding description contains an IP:
                found_in_desc = extract_ips_from_text(f"{f.get('title', '')} {f.get('description', '')}")
                for ip_str in found_in_desc:
                    if ip_str in ip_map:
                        ip_map[ip_str]["finding_ids"].add(f_id)
                        ip_map[ip_str]["severities"].append(f_sev)

                # Or match through evidence event IDs:
                ev_set = set(ev_list)
                for ip_str, data in ip_map.items():
                    if any(eid in ev_set for eid in data["events"]):
                        data["finding_ids"].add(f_id)
                        data["severities"].append(f_sev)

        results: List[Dict[str, Any]] = []

        for ip_str, meta in ip_map.items():
            # Geolocate
            geo = self.geolocate_ip(ip_str, db)

            # Max severity
            sevs = meta["severities"] or ["low"]
            max_sev = max(sevs, key=lambda s: severity_rank.get(s, 0))

            timestamps = [t for t in meta["timestamps"] if t]
            first_seen = min(timestamps) if timestamps else None
            last_seen = max(timestamps) if timestamps else None

            linked_finding_ids = list(meta["finding_ids"])
            linked_event_ids = list(dict.fromkeys(meta["events"]))  # preserve order dedupe

            # Check existing record in DB
            query = db.query(AttackerIP).filter(AttackerIP.ip == ip_str)
            if upload_id:
                query = query.filter(AttackerIP.upload_id == upload_id)
            else:
                query = query.filter(AttackerIP.upload_id.is_(None))

            record = query.first()
            if not record:
                record = AttackerIP(
                    ip=ip_str,
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
                    event_count=len(linked_event_ids) or 1,
                    max_severity=max_sev,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    linked_finding_ids=json.dumps(linked_finding_ids),
                    linked_event_ids=json.dumps(linked_event_ids),
                )
                db.add(record)
            else:
                # Merge
                existing_fids = set(json.loads(record.linked_finding_ids or "[]"))
                existing_fids.update(linked_finding_ids)
                existing_eids = list(dict.fromkeys(json.loads(record.linked_event_ids or "[]") + linked_event_ids))

                record.event_count = max(record.event_count, len(existing_eids))
                record.linked_finding_ids = json.dumps(list(existing_fids))
                record.linked_event_ids = json.dumps(existing_eids)
                if severity_rank.get(max_sev, 0) > severity_rank.get(record.max_severity, 0):
                    record.max_severity = max_sev
                if first_seen and (not record.first_seen or first_seen < record.first_seen):
                    record.first_seen = first_seen
                if last_seen and (not record.last_seen or last_seen > record.last_seen):
                    record.last_seen = last_seen
                record.updated_at = utcnow()

            db.commit()
            db.refresh(record)

            origin_dict = {
                "id": record.id,
                "ip": record.ip,
                "upload_id": record.upload_id,
                "classification": record.classification,
                "source": record.source,
                "country": record.country,
                "country_code": record.country_code,
                "city": record.city,
                "lat": record.lat,
                "lon": record.lon,
                "asn": record.asn,
                "org": record.org,
                "is_tor_or_vpn": record.is_tor_or_vpn,
                "event_count": record.event_count,
                "max_severity": record.max_severity,
                "first_seen": record.first_seen,
                "last_seen": record.last_seen,
                "linked_finding_ids": json.loads(record.linked_finding_ids or "[]"),
                "is_active": True,
            }
            results.append(origin_dict)

            # Broadcast via SSE if high+ severity or finding is associated
            is_high_risk = severity_rank.get(max_sev, 0) >= 30 or bool(linked_finding_ids)
            if is_high_risk:
                threat_map_broadcaster.broadcast(origin_dict)

        return results


ip_intel = IPIntelService()
