import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Square,
  Radio,
  Search,
  Filter,
  Trash2,
  AlertTriangle,
  Activity,
  Layers,
  ArrowDownCircle,
  Pause,
  ArrowUpDown,
  ShieldAlert,
  Sparkles,
  CheckSquare
} from 'lucide-react';
import { getLiveLogsStreamUrl, stopLiveLogs } from '../../api';
import FindingsPanel from './FindingsPanel';
import ThreatOriginGlobe from '../ThreatMap/ThreatOriginGlobe';
import SeverityBadge from './SeverityBadge';
import SeverityLegend from './SeverityLegend';
import LogExplainerChat from './LogExplainerChat';

const MAX_DOM_ROWS = 500;

export default function RealTimeLogs({ onAskCyberLLM, onSelectAlert, focusedOrigin, showToast }) {
  const [isStreaming, setIsStreaming] = useState(false);
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [warningMessage, setWarningMessage] = useState(null);

  // Log Explainer state & multi-select
  const [isExplainerOpen, setIsExplainerOpen] = useState(false);
  const [selectedEventIds, setSelectedEventIds] = useState(new Set());
  const [attachedContext, setAttachedContext] = useState({
    eventIds: [],
    findingIds: [],
    rawEvents: [],
    findings: [],
    mode: 'live',
  });

  // Filters
  const [levelFilter, setLevelFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [sortBySeverity, setSortBySeverity] = useState(false);

  // Counters
  const [eventsPerSec, setEventsPerSec] = useState(0);
  const eventCounterRef = useRef(0);
  const tableBottomRef = useRef(null);
  const eventSourceRef = useRef(null);
  const shouldReconnectRef = useRef(false);

  // Calculate events per second every 1000ms
  useEffect(() => {
    const interval = setInterval(() => {
      setEventsPerSec(eventCounterRef.current);
      eventCounterRef.current = 0;
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll when new events arrive
  useEffect(() => {
    if (autoScroll && !sortBySeverity && tableBottomRef.current) {
      tableBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, autoScroll, sortBySeverity]);

  // Clean up EventSource on unmount
  useEffect(() => {
    return () => {
      shouldReconnectRef.current = false;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      stopLiveLogs().catch(() => {});
    };
  }, []);

  const startStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    shouldReconnectRef.current = true;
    setIsStreaming(true);
    setWarningMessage(null);

    const streamUrl = getLiveLogsStreamUrl();
    const es = new EventSource(streamUrl);
    eventSourceRef.current = es;

    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'log' && payload.data) {
          eventCounterRef.current += 1;
          setEvents((prev) => {
            const next = [...prev, payload.data];
            return next.length > MAX_DOM_ROWS ? next.slice(-MAX_DOM_ROWS) : next;
          });
        } else if (payload.type === 'finding' && payload.data) {
          setFindings((prev) => {
            const exists = prev.some((f) => f.id === payload.data.id || f.title === payload.data.title);
            if (exists) return prev;
            return [payload.data, ...prev];
          });
        } else if (payload.type === 'warning') {
          setWarningMessage(payload.message);
        }
      } catch (err) {
        console.error('Failed to parse SSE event:', err);
      }
    };

    es.onerror = (err) => {
      console.warn('SSE stream error or disconnected:', err);
      es.close();
      if (shouldReconnectRef.current) {
        setTimeout(() => {
          if (shouldReconnectRef.current) {
            startStream();
          }
        }, 3000);
      } else {
        setIsStreaming(false);
      }
    };
  };

  const stopStream = async () => {
    shouldReconnectRef.current = false;
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsStreaming(false);
    try {
      await stopLiveLogs();
    } catch (e) {
      console.error('Error stopping stream:', e);
    }
  };

  const toggleStream = () => {
    if (isStreaming) {
      stopStream();
    } else {
      startStream();
    }
  };

  const clearEvents = () => {
    setEvents([]);
    setFindings([]);
    setWarningMessage(null);
  };

  // Severity counts
  const criticalCount = events.filter((e) => (e.severity || '').toLowerCase() === 'critical').length;
  const highCount = events.filter((e) => (e.severity || '').toLowerCase() === 'high').length;
  const mediumCount = events.filter((e) => (e.severity || '').toLowerCase() === 'medium').length;
  const lowCount = events.filter((e) => (e.severity || '').toLowerCase() === 'low').length;

  const handleSeverityChipClick = (sev) => {
    setSeverityFilter((prev) => (prev === sev ? 'ALL' : sev));
  };

  // Filtered and sorted events
  let filteredEvents = events.filter((evt) => {
    if (levelFilter !== 'ALL' && evt.level !== levelFilter) return false;
    if (severityFilter !== 'ALL' && (evt.severity || 'low').toUpperCase() !== severityFilter) return false;
    if (sourceFilter && !evt.source?.toLowerCase().includes(sourceFilter.toLowerCase())) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchMsg = evt.message?.toLowerCase().includes(q);
      const matchSrc = evt.source?.toLowerCase().includes(q);
      const matchId = evt.event_id?.toLowerCase().includes(q);
      const matchSev = evt.severity?.toLowerCase().includes(q);
      if (!matchMsg && !matchSrc && !matchId && !matchSev) return false;
    }
    return true;
  });

  if (sortBySeverity) {
    filteredEvents = [...filteredEvents].sort((a, b) => (b.severity_score || 0) - (a.severity_score || 0));
  }

  // Multi-select handlers
  const handleToggleSelectAll = (checked) => {
    if (checked) {
      setSelectedEventIds(new Set(filteredEvents.map((e) => e.id)));
    } else {
      setSelectedEventIds(new Set());
    }
  };

  const handleToggleSelectEvent = (id) => {
    setSelectedEventIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Explain single event
  const handleExplainSingleEvent = (evt) => {
    setAttachedContext({
      eventIds: [evt.id],
      findingIds: [],
      rawEvents: [evt],
      findings: [],
      mode: 'live',
    });
    setIsExplainerOpen(true);
  };

  // Explain selected events
  const handleExplainSelected = () => {
    const selectedList = events.filter((e) => selectedEventIds.has(e.id));
    if (selectedList.length === 0) return;
    setAttachedContext({
      eventIds: selectedList.map((e) => e.id),
      findingIds: [],
      rawEvents: selectedList,
      findings: [],
      mode: 'live',
    });
    setIsExplainerOpen(true);
  };

  // Explain finding
  const handleExplainFinding = (fnd) => {
    setAttachedContext({
      eventIds: [],
      findingIds: [fnd.id],
      rawEvents: [],
      findings: [fnd],
      mode: 'live',
    });
    setIsExplainerOpen(true);
  };

  // Drag and drop / chip management
  const handleRemoveEventContext = (idOrIdx) => {
    setAttachedContext((prev) => ({
      ...prev,
      rawEvents: prev.rawEvents.filter((e, idx) => (e.id ? e.id !== idOrIdx : idx !== idOrIdx)),
      eventIds: prev.eventIds.filter((id) => id !== idOrIdx),
    }));
  };

  const handleRemoveFindingContext = (idOrIdx) => {
    setAttachedContext((prev) => ({
      ...prev,
      findings: prev.findings.filter((f, idx) => (f.id ? f.id !== idOrIdx : idx !== idOrIdx)),
      findingIds: prev.findingIds.filter((id) => id !== idOrIdx),
    }));
  };

  const handleAddEventContext = (evt) => {
    setAttachedContext((prev) => {
      const exists = prev.rawEvents.some((e) => e.id === evt.id);
      if (exists) return prev;
      return {
        ...prev,
        rawEvents: [...prev.rawEvents, evt],
        eventIds: [...prev.eventIds, evt.id],
      };
    });
    setIsExplainerOpen(true);
  };

  const handleAddFindingContext = (fnd) => {
    setAttachedContext((prev) => {
      const exists = prev.findings.some((f) => f.id === fnd.id);
      if (exists) return prev;
      return {
        ...prev,
        findings: [...prev.findings, fnd],
        findingIds: [...prev.findingIds, fnd.id],
      };
    });
    setIsExplainerOpen(true);
  };

  const handleClearContext = () => {
    setAttachedContext({
      eventIds: [],
      findingIds: [],
      rawEvents: [],
      findings: [],
      mode: 'live',
    });
    setSelectedEventIds(new Set());
  };

  return (
    <div className={`realtime-logs-workspace ${isExplainerOpen ? 'with-explainer-drawer' : ''}`}>
      {/* Top Controls Bar */}
      <div className="rt-controls-panel cyber-card">
        <div className="rt-stream-actions">
          <button
            type="button"
            className={`btn btn-toggle-stream ${isStreaming ? 'btn-live-active' : 'btn-primary'}`}
            onClick={toggleStream}
          >
            {isStreaming ? (
              <>
                <Square size={14} />
                <span>Stop Stream</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>Start Real-Time Stream</span>
              </>
            )}
          </button>

          {isStreaming && (
            <div className="live-indicator-badge">
              <span className="live-pulse"></span>
              <Radio size={14} />
              <span>LIVE COLLECTION ACTIVE</span>
            </div>
          )}

          <button
            type="button"
            className="btn btn-secondary btn-icon-text"
            onClick={clearEvents}
            title="Clear display buffer"
          >
            <Trash2 size={14} />
            <span>Clear</span>
          </button>

          <SeverityLegend />

          <button
            type="button"
            className={`btn btn-explainer-toggle ${isExplainerOpen ? 'active' : ''}`}
            onClick={() => setIsExplainerOpen((prev) => !prev)}
            title="Open Log Explainer Plain-Language Chat"
          >
            <Sparkles size={14} color="var(--accent-cyan)" />
            <span>Log Explainer</span>
            {attachedContext.rawEvents.length + attachedContext.findings.length > 0 && (
              <span className="explainer-context-counter">
                {attachedContext.rawEvents.length + attachedContext.findings.length}
              </span>
            )}
          </button>
        </div>

        {/* Live Counters with Clickable Severity Filters */}
        <div className="rt-stats-strip">
          <div className="stat-chip">
            <span className="stat-chip-label">Throughput</span>
            <span className="stat-chip-val cyan">{eventsPerSec} evt/s</span>
          </div>
          <div className="stat-chip">
            <span className="stat-chip-label">Buffered</span>
            <span className="stat-chip-val">{events.length}</span>
          </div>
          <div
            className={`stat-chip clickable-chip ${severityFilter === 'CRITICAL' ? 'chip-active-critical' : ''}`}
            onClick={() => handleSeverityChipClick('CRITICAL')}
            title="Click to filter by Critical severity"
          >
            <span className="stat-chip-label">Critical</span>
            <span className={`stat-chip-val ${criticalCount > 0 ? 'rose' : ''}`}>{criticalCount}</span>
          </div>
          <div
            className={`stat-chip clickable-chip ${severityFilter === 'HIGH' ? 'chip-active-high' : ''}`}
            onClick={() => handleSeverityChipClick('HIGH')}
            title="Click to filter by High severity"
          >
            <span className="stat-chip-label">High</span>
            <span className={`stat-chip-val ${highCount > 0 ? 'orange' : ''}`}>{highCount}</span>
          </div>
          <div
            className={`stat-chip clickable-chip ${severityFilter === 'MEDIUM' ? 'chip-active-medium' : ''}`}
            onClick={() => handleSeverityChipClick('MEDIUM')}
            title="Click to filter by Medium severity"
          >
            <span className="stat-chip-label">Medium</span>
            <span className={`stat-chip-val ${mediumCount > 0 ? 'amber' : ''}`}>{mediumCount}</span>
          </div>
          <div
            className={`stat-chip clickable-chip ${severityFilter === 'LOW' ? 'chip-active-low' : ''}`}
            onClick={() => handleSeverityChipClick('LOW')}
            title="Click to filter by Low severity"
          >
            <span className="stat-chip-label">Low</span>
            <span className="stat-chip-val emerald">{lowCount}</span>
          </div>
          <div className="stat-chip">
            <span className="stat-chip-label">Findings</span>
            <span className={`stat-chip-val ${findings.length > 0 ? 'purple' : ''}`}>{findings.length}</span>
          </div>
        </div>
      </div>

      {/* Warning message banner */}
      {warningMessage && (
        <div className="warning-banner">
          <AlertTriangle size={16} color="var(--accent-amber)" />
          <span>{warningMessage}</span>
        </div>
      )}

      {/* Main Content Area: Split Table + Side Findings */}
      <div className="rt-content-split">
        {/* Left: Events Stream Table */}
        <div className="rt-table-container cyber-card">
          {/* Filters Bar */}
          <div className="rt-filters-bar">
            {/* Severity Filter */}
            <div className="filter-group">
              <ShieldAlert size={14} color="var(--accent-rose)" />
              <select
                className="select-cyber"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Level Filter */}
            <div className="filter-group">
              <Filter size={14} color="var(--text-dim)" />
              <select
                className="select-cyber"
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
              >
                <option value="ALL">All Levels</option>
                <option value="CRITICAL">Critical Level</option>
                <option value="ERROR">Error Level</option>
                <option value="WARNING">Warning Level</option>
                <option value="INFO">Info Level</option>
                <option value="DEBUG">Debug Level</option>
              </select>
            </div>

            <div className="filter-input-wrap">
              <Layers size={14} color="var(--text-dim)" />
              <input
                type="text"
                placeholder="Filter source..."
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
              />
            </div>

            <div className="filter-input-wrap search-flex">
              <Search size={14} color="var(--text-dim)" />
              <input
                type="text"
                placeholder="Search event messages, IDs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            {/* Sort by severity toggle */}
            <label className="autoscroll-toggle">
              <input
                type="checkbox"
                checked={sortBySeverity}
                onChange={(e) => setSortBySeverity(e.target.checked)}
              />
              <ArrowUpDown size={13} color={sortBySeverity ? 'var(--accent-cyan)' : 'var(--text-dim)'} />
              <span>Sort Severity</span>
            </label>

            <label className="autoscroll-toggle">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
              />
              {autoScroll ? <ArrowDownCircle size={14} color="var(--accent-cyan)" /> : <Pause size={14} />}
              <span>Auto-scroll</span>
            </label>
          </div>

          {/* Table */}
          <div className="events-table-wrapper">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th style={{ width: '40px', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      aria-label="Select all events"
                      checked={filteredEvents.length > 0 && selectedEventIds.size === filteredEvents.length}
                      onChange={(e) => handleToggleSelectAll(e.target.checked)}
                    />
                  </th>
                  <th style={{ width: '110px' }}>Time</th>
                  <th style={{ width: '80px' }}>Level</th>
                  <th style={{ width: '125px' }}>Severity</th>
                  <th style={{ width: '125px' }}>Source</th>
                  <th style={{ width: '80px' }}>Event ID</th>
                  <th>Message</th>
                  <th style={{ width: '85px', textAlign: 'center' }}>Explain</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="table-empty-row">
                      {isStreaming
                        ? 'Waiting for incoming events…'
                        : 'Stream paused. Click "Start Real-Time Stream" to capture host logs.'}
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((evt) => {
                    const timeStr = evt.timestamp?.split('T')[1]?.substring(0, 8) || evt.timestamp || '';
                    const isSelected = selectedEventIds.has(evt.id);
                    return (
                      <tr
                        key={evt.id}
                        className={`row-severity-${(evt.severity || 'low').toLowerCase()} ${isSelected ? 'row-selected' : ''}`}
                        draggable="true"
                        onClick={(e) => {
                          if (e.target.tagName === 'INPUT' || e.target.closest('button')) return;
                          if (onSelectAlert) {
                            onSelectAlert({
                              type: 'log',
                              id: evt.id,
                              title: `Log Event #${evt.event_id || ''} (${evt.source || 'Host'})`,
                              severity: evt.severity,
                              event: evt,
                            });
                          }
                        }}
                        onDragStart={(e) => {
                          e.dataTransfer.setData('application/x-soc-log-event', JSON.stringify(evt));
                          e.dataTransfer.setData('text/plain', `Log Event #${evt.event_id || ''}: ${evt.message}`);
                        }}
                        title="Click to view alert intelligence, or drag to Log Explainer"
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ textAlign: 'center' }}>
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleToggleSelectEvent(evt.id)}
                            aria-label={`Select event ${evt.id}`}
                          />
                        </td>
                        <td className="cell-time">{timeStr}</td>
                        <td>
                          <span className={`level-pill level-${evt.level?.toLowerCase()}`}>
                            {evt.level}
                          </span>
                        </td>
                        <td>
                          <SeverityBadge
                            severity={evt.severity}
                            score={evt.severity_score}
                            reasons={evt.severity_reasons}
                            showScore={true}
                          />
                        </td>
                        <td className="cell-source" title={evt.source}>{evt.source}</td>
                        <td className="cell-event-id">{evt.event_id || '—'}</td>
                        <td className="cell-message">{evt.message}</td>
                        <td style={{ textAlign: 'center' }}>
                          <button
                            type="button"
                            className="btn-row-explain"
                            onClick={() => handleExplainSingleEvent(evt)}
                            title="Explain this log in simple terms"
                          >
                            <Sparkles size={12} color="var(--accent-cyan)" />
                            <span>Explain</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
            <div ref={tableBottomRef} />
          </div>
        </div>

        {/* Right: Live Findings Drawer */}
        <div className="rt-findings-sidebar">
          <ThreatOriginGlobe
            onSelectAlert={onSelectAlert}
            focusedOrigin={focusedOrigin}
          />
          <FindingsPanel
            findings={findings}
            onAskCyberLLM={onAskCyberLLM}
            onExplainFinding={handleExplainFinding}
            onSelectAlert={onSelectAlert}
            showToast={showToast}
          />
        </div>
      </div>

      {/* Collapsible Log Explainer Chatbot Drawer */}
      <LogExplainerChat
        isOpen={isExplainerOpen}
        onClose={() => setIsExplainerOpen(false)}
        attachedContext={attachedContext}
        onRemoveEvent={handleRemoveEventContext}
        onRemoveFinding={handleRemoveFindingContext}
        onClearContext={handleClearContext}
        onAddEventContext={handleAddEventContext}
        onAddFindingContext={handleAddFindingContext}
        onAskCyberLLM={onAskCyberLLM}
      />
    </div>
  );
}
