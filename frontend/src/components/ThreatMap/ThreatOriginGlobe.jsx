import React, { useState, useEffect, useRef, useMemo, lazy, Suspense } from 'react';
import {
  Globe as GlobeIcon,
  ShieldAlert,
  Radio,
  MapPin,
  RefreshCw,
  ExternalLink,
  Info,
  Maximize2,
  Minimize2,
  AlertTriangle,
  Layers,
  Crosshair
} from 'lucide-react';
import {
  getThreatMapOrigins,
  getHomeLocation,
  getThreatMapStreamUrl,
  updateHomeLocation
} from '../../api';

// Dynamically lazy-load react-globe.gl to keep initial bundle size lean
const Globe = lazy(() => import('react-globe.gl'));

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

function checkWebGL() {
  try {
    const canvas = document.createElement('canvas');
    return !!(
      window.WebGLRenderingContext &&
      (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))
    );
  } catch (e) {
    return false;
  }
}

export default function ThreatOriginGlobe({
  uploadId = null,
  onSelectAttacker = null,
  onSelectAlert = null,
  focusedOrigin = null,
  isCompact = false,
}) {
  const [origins, setOrigins] = useState([]);
  const [homeLocation, setHomeLocation] = useState({
    lat: 37.7749,
    lon: -122.4194,
    label: 'Protected SOC Asset',
  });
  const [selectedIP, setSelectedIP] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [useFlatFallback, setUseFlatFallback] = useState(false);
  const [isAutoRotating, setIsAutoRotating] = useState(true);
  const [showInternalOnly, setShowInternalOnly] = useState(false);
  const [dimensions, setDimensions] = useState({ width: 450, height: 350 });

  const containerRef = useRef(null);
  const globeEl = useRef(null);
  const toastTimeoutRef = useRef(null);

  // Check WebGL and prefers-reduced-motion
  useEffect(() => {
    const hasWebGL = checkWebGL();
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (!hasWebGL || mediaQuery.matches) {
      setUseFlatFallback(true);
    }
  }, []);

  // Responsive sizing
  useEffect(() => {
    if (!containerRef.current) return;
    const updateSize = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        setDimensions({
          width: clientWidth || (isCompact ? 320 : 480),
          height: clientHeight || (isCompact ? 280 : 380),
        });
      }
    };
    updateSize();
    const ro = new ResizeObserver(updateSize);
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, [isCompact]);

  // Fetch initial origins and home location
  const loadData = async () => {
    setIsLoading(true);
    try {
      const [originsData, homeData] = await Promise.all([
        getThreatMapOrigins(uploadId),
        getHomeLocation().catch(() => ({
          lat: 37.7749,
          lon: -122.4194,
          label: 'SOC HQ',
        })),
      ]);
      setOrigins(originsData || []);
      if (homeData) setHomeLocation(homeData);
    } catch (err) {
      console.error('Failed to load threat map origins:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [uploadId]);

  // Server-Sent Events stream for real-time threat origins
  useEffect(() => {
    let eventSource = null;
    try {
      const streamUrl = getThreatMapStreamUrl();
      eventSource = new EventSource(streamUrl);

      eventSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'origin_update' && payload.data) {
            const updated = payload.data;
            setOrigins((prev) => {
              const index = prev.findIndex((o) => o.ip === updated.ip);
              if (index >= 0) {
                const next = [...prev];
                next[index] = { ...next[index], ...updated };
                return next;
              }
              return [updated, ...prev];
            });

            // Trigger notification toast
            showToast(
              `New attacker origin: ${updated.ip} (${updated.country || 'Unknown'})`,
              updated.max_severity || 'high'
            );
          }
        } catch (e) {
          // keepalive ping or unparseable
        }
      };

      eventSource.onerror = () => {
        // browser will auto-reconnect
      };
    } catch (e) {
      console.warn('SSE stream error:', e);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  const showToast = (message, severity = 'high') => {
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    setToast({ message, severity });
    toastTimeoutRef.current = setTimeout(() => {
      setToast(null);
    }, 4500);
  };

  // Configure auto-rotate controls on globe mount
  useEffect(() => {
    if (globeEl.current) {
      const controls = globeEl.current.controls();
      if (controls) {
        controls.autoRotate = isAutoRotating;
        controls.autoRotateSpeed = 0.6;
        controls.enableZoom = true;
      }
    }
  }, [isAutoRotating, dimensions]);

  // Points with coordinates for 3D globe / 2D map
  const routableOrigins = useMemo(() => {
    return origins.filter((o) => o.lat != null && o.lon != null);
  }, [origins]);

  const privateOrigins = useMemo(() => {
    return origins.filter((o) => o.classification === 'private' || o.source === 'internal');
  }, [origins]);

  // Most severe / most recent origin for footer pill
  const prominentOrigin = useMemo(() => {
    if (!origins.length) return null;
    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    return [...origins].sort((a, b) => {
      const rankDiff =
        (severityRank[b.max_severity] || 0) - (severityRank[a.max_severity] || 0);
      if (rankDiff !== 0) return rankDiff;
      return (b.event_count || 0) - (a.event_count || 0);
    })[0];
  }, [origins]);

  // Build arcs from each attacker location to home location
  const arcsData = useMemo(() => {
    if (homeLocation.lat == null || homeLocation.lon == null) return [];
    return routableOrigins.map((origin) => ({
      startLat: origin.lat,
      startLng: origin.lon,
      endLat: homeLocation.lat,
      endLng: homeLocation.lon,
      color: [
        SEVERITY_COLORS[origin.max_severity] || '#f97316',
        'rgba(56, 189, 248, 0.7)',
      ],
      name: `${origin.ip} -> Home (${origin.country || 'Unknown'})`,
      origin,
    }));
  }, [routableOrigins, homeLocation]);

  // Glowing rings for active/live attackers
  const ringsData = useMemo(() => {
    return routableOrigins.map((origin) => ({
      lat: origin.lat,
      lng: origin.lon,
      maxR: 3.5,
      propagationSpeed: 1.5,
      repeatPeriod: 1200,
      color: (t) =>
        t > 0.8
          ? 'transparent'
          : `${SEVERITY_COLORS[origin.max_severity] || '#f97316'}${Math.floor((1 - t) * 200)
              .toString(16)
              .padStart(2, '0')}`,
    }));
  }, [routableOrigins]);

  // Label data including home location marker
  const labelsData = useMemo(() => {
    const list = routableOrigins.map((o) => ({
      lat: o.lat,
      lng: o.lon,
      text: `${o.city ? o.city + ', ' : ''}${o.country_code || o.country || ''}`,
      color: SEVERITY_COLORS[o.max_severity] || '#fb7185',
      size: 1.0,
      origin: o,
    }));

    if (homeLocation.lat != null && homeLocation.lon != null) {
      list.push({
        lat: homeLocation.lat,
        lng: homeLocation.lon,
        text: `★ ${homeLocation.label || 'SOC Asset'}`,
        color: '#38bdf8',
        size: 1.2,
        isHome: true,
      });
    }
    return list;
  }, [routableOrigins, homeLocation]);

  // Focus globe whenever focusedOrigin prop updates
  useEffect(() => {
    if (focusedOrigin && globeEl.current) {
      const lat = focusedOrigin.lat;
      const lon = focusedOrigin.lon != null ? focusedOrigin.lon : focusedOrigin.lng;
      if (lat != null && lon != null) {
        globeEl.current.pointOfView(
          { lat: Number(lat), lng: Number(lon), altitude: 1.8 },
          1000
        );
      }
    }
  }, [focusedOrigin]);

  const handlePointClick = (origin) => {
    setSelectedIP(origin.ip);
    if (onSelectAttacker) {
      onSelectAttacker(origin);
    }
    if (onSelectAlert) {
      onSelectAlert({
        type: 'ip',
        id: origin.ip,
        title: `Threat Origin: ${origin.ip} (${origin.country || 'Unknown'})`,
        severity: (origin.max_severity || 'HIGH').toUpperCase(),
        origin,
      });
    }
    if (globeEl.current && origin.lat != null && origin.lon != null) {
      globeEl.current.pointOfView(
        { lat: origin.lat, lng: origin.lon, altitude: 1.8 },
        1000
      );
    }
  };

  return (
    <div
      className={`threat-globe-card ${isCompact ? 'compact' : ''}`}
      ref={containerRef}
    >
      {/* Toast Notification for incoming SSE origin */}
      {toast && (
        <div className={`globe-toast severity-${toast.severity}`}>
          <Radio size={14} className="toast-pulse-icon" />
          <span>{toast.message}</span>
        </div>
      )}

      {/* Header Bar */}
      <div className="threat-globe-header">
        <div className="header-left">
          <div className="globe-title-badge">
            <GlobeIcon size={16} color="var(--accent-cyan)" />
            <h4 className="globe-title">THREAT ORIGIN GLOBE</h4>
          </div>
          <span className="resolved-count-pill">
            <span className="live-dot" />
            {origins.length} attacker IP{origins.length === 1 ? '' : 's'} resolved
          </span>
        </div>

        <div className="globe-actions">
          <button
            type="button"
            className={`btn-globe-tool ${useFlatFallback ? 'active' : ''}`}
            onClick={() => setUseFlatFallback(!useFlatFallback)}
            title={useFlatFallback ? 'Switch to 3D Globe' : 'Switch to 2D Map'}
          >
            <Layers size={14} />
            <span>{useFlatFallback ? '3D' : '2D'}</span>
          </button>

          {!useFlatFallback && (
            <button
              type="button"
              className={`btn-globe-tool ${isAutoRotating ? 'active' : ''}`}
              onClick={() => setIsAutoRotating(!isAutoRotating)}
              title={isAutoRotating ? 'Pause rotation' : 'Auto-rotate'}
            >
              <RefreshCw size={13} className={isAutoRotating ? 'spin-icon' : ''} />
            </button>
          )}
        </div>
      </div>

      {/* Visualization Canvas Area */}
      <div className="globe-viewport-container">
        {isLoading && (
          <div className="globe-loading-overlay">
            <RefreshCw size={24} className="spin-icon" color="var(--accent-cyan)" />
            <span>Resolving geolocation coordinates…</span>
          </div>
        )}

        {/* Empty state: small translucent overlay badge — never replaces the globe */}
        {!isLoading && routableOrigins.length === 0 && (
          <div className="globe-empty-overlay-badge">
            <Crosshair size={14} />
            <span>No external attacker IPs yet. Waiting for alerts…</span>
          </div>
        )}

        {useFlatFallback ? (
          /* 2D Flat Fallback View (Accessible & Lightweight) */
          <div className="flat-map-view">
            <svg
              className="flat-map-svg"
              viewBox="0 0 800 400"
              preserveAspectRatio="xMidYMid meet"
            >
              {/* Simplified world outline grid */}
              <defs>
                <radialGradient id="homeGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
                </radialGradient>
              </defs>
              <rect width="800" height="400" fill="#0b1120" rx="8" />
              {/* Lat/Lon grid lines */}
              <line x1="0" y1="200" x2="800" y2="200" stroke="#1e293b" strokeDasharray="4" />
              <line x1="400" y1="0" x2="400" y2="400" stroke="#1e293b" strokeDasharray="4" />

              {/* Arcs to Home Location in 2D */}
              {homeLocation.lat != null &&
                routableOrigins.map((origin) => {
                  const x1 = ((origin.lon + 180) / 360) * 800;
                  const y1 = ((90 - origin.lat) / 180) * 400;
                  const x2 = ((homeLocation.lon + 180) / 360) * 800;
                  const y2 = ((90 - homeLocation.lat) / 180) * 400;
                  const cx = (x1 + x2) / 2;
                  const cy = Math.min(y1, y2) - 40;
                  return (
                    <path
                      key={`arc-${origin.ip}`}
                      d={`M ${x1} ${y1} Q ${cx} ${cy} ${x2} ${y2}`}
                      fill="none"
                      stroke={SEVERITY_COLORS[origin.max_severity] || '#f97316'}
                      strokeWidth="1.5"
                      strokeDasharray="4 2"
                      opacity="0.75"
                    />
                  );
                })}

              {/* Home Location Marker */}
              {homeLocation.lat != null && (
                <g>
                  <circle
                    cx={((homeLocation.lon + 180) / 360) * 800}
                    cy={((90 - homeLocation.lat) / 180) * 400}
                    r="12"
                    fill="url(#homeGlow)"
                  />
                  <circle
                    cx={((homeLocation.lon + 180) / 360) * 800}
                    cy={((90 - homeLocation.lat) / 180) * 400}
                    r="4"
                    fill="#38bdf8"
                  />
                  <text
                    x={((homeLocation.lon + 180) / 360) * 800 + 8}
                    y={((90 - homeLocation.lat) / 180) * 400 + 4}
                    fill="#38bdf8"
                    fontSize="10"
                    fontWeight="600"
                  >
                    ★ SOC HQ
                  </text>
                </g>
              )}

              {/* Origin Pins */}
              {routableOrigins.map((origin) => {
                const x = ((origin.lon + 180) / 360) * 800;
                const y = ((90 - origin.lat) / 180) * 400;
                const color = SEVERITY_COLORS[origin.max_severity] || '#f97316';
                return (
                  <g
                    key={origin.ip}
                    className="flat-pin"
                    onClick={() => handlePointClick(origin)}
                    style={{ cursor: 'pointer' }}
                  >
                    <circle cx={x} cy={y} r="6" fill={color} opacity="0.9" />
                    <circle cx={x} cy={y} r="10" fill="none" stroke={color} strokeWidth="1" opacity="0.5" />
                    <text x={x + 8} y={y + 3} fill="#f1f5f9" fontSize="9">
                      {origin.ip} ({origin.country_code || origin.country})
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        ) : (
          /* 3D Night Earth WebGL Globe */
          <Suspense
            fallback={
              <div className="globe-loading-overlay">
                <RefreshCw size={24} className="spin-icon" color="var(--accent-cyan)" />
                <span>Initializing 3D Earth Globe…</span>
              </div>
            }
          >
            <Globe
              ref={globeEl}
              width={dimensions.width}
              height={dimensions.height}
              globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
              bumpImageUrl="//unpkg.com/three-globe/example/img/earth-topology.png"
              backgroundColor="rgba(0, 0, 0, 0)"
              atmosphereColor="#38bdf8"
              atmosphereAltitude={0.16}
              // Arcs
              arcsData={arcsData}
              arcColor="color"
              arcDashLength={0.4}
              arcDashGap={0.2}
              arcDashAnimateTime={2000}
              arcStroke={1.2}
              // Points
              pointsData={routableOrigins}
              pointLat="lat"
              pointLng="lon"
              pointColor={(d) => SEVERITY_COLORS[d.max_severity] || '#f97316'}
              pointAltitude={0.06}
              pointRadius={0.7}
              pointResolution={24}
              onPointClick={handlePointClick}
              // Rings
              ringsData={ringsData}
              ringLat="lat"
              ringLng="lng"
              ringMaxRadius="maxR"
              ringPropagationSpeed="propagationSpeed"
              ringRepeatPeriod="repeatPeriod"
              ringColor="color"
              // HTML / Tooltip
              pointLabel={(d) => `
                <div class="globe-tooltip-card">
                  <div class="tooltip-header">
                    <strong>${d.ip}</strong>
                    <span class="tooltip-sev badge-${d.max_severity}">${d.max_severity.toUpperCase()}</span>
                  </div>
                  <div class="tooltip-row">
                    <span>Origin:</span>
                    <span>${d.city ? d.city + ', ' : ''}${d.country || 'Unknown'}</span>
                  </div>
                  ${d.asn ? `<div class="tooltip-row"><span>ASN/Org:</span><span>${d.asn} ${d.org || ''}</span></div>` : ''}
                  <div class="tooltip-row">
                    <span>Events:</span>
                    <span>${d.event_count || 1}</span>
                  </div>
                  <div class="tooltip-source-tag ${d.source}">
                    ${d.source === 'demo' ? 'DEMO SIMULATION' : d.source.toUpperCase()}
                  </div>
                  <div class="tooltip-click-hint">Click to inspect trajectory</div>
                </div>
              `}
              // Labels
              labelsData={labelsData}
              labelLat="lat"
              labelLng="lng"
              labelText="text"
              labelColor="color"
              labelSize="size"
              labelDotRadius={0.4}
              labelAltitude={0.02}
            />
          </Suspense>
        )}
      </div>

      {/* Footer Pill & Overview */}
      <div className="threat-globe-footer">
        {prominentOrigin ? (
          <div className="footer-origin-pill">
            <span className="pill-pulse" style={{ backgroundColor: SEVERITY_COLORS[prominentOrigin.max_severity] }} />
            <span className="pill-label">Detected Origin:</span>
            <strong className="pill-country">
              {prominentOrigin.country || prominentOrigin.city || 'Unknown Origin'}
            </strong>
            {prominentOrigin.source === 'demo' && (
              <span className="badge-demo-override" title="Configured via demo_geo_overrides.json">
                DEMO
              </span>
            )}
            {prominentOrigin.classification === 'private' && (
              <span className="badge-internal-tag">Internal / non-routable</span>
            )}
          </div>
        ) : (
          <div className="footer-origin-pill muted">
            <MapPin size={12} />
            <span>Scanning telemetry for external origins…</span>
          </div>
        )}

        {/* Private / Internal IP Indicator if any */}
        {privateOrigins.length > 0 && (
          <div
            className="internal-ip-indicator"
            title={`${privateOrigins.length} non-routable / RFC1918 internal IPs retained safely without external lookups.`}
          >
            <ShieldAlert size={12} color="var(--accent-amber)" />
            <span>{privateOrigins.length} internal</span>
          </div>
        )}
      </div>
    </div>
  );
}
