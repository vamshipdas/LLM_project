import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCheck,
  AlertCircle,
  Play,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  BarChart2,
  Clock,
  Layers,
  FileText,
  ShieldAlert,
  ArrowUpDown
} from 'lucide-react';
import { uploadLogFile, getUploadEvents, analyzeUploadLog } from '../../api';
import FindingsPanel from './FindingsPanel';
import ThreatOriginGlobe from '../ThreatMap/ThreatOriginGlobe';
import SeverityBadge from './SeverityBadge';
import SeverityLegend from './SeverityLegend';
import LogExplainerChat from './LogExplainerChat';

export default function UploadLogs({ onAskCyberLLM, onSelectAlert, focusedOrigin, showToast }) {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [errorMessage, setErrorMessage] = useState(null);

  // Log Explainer & selection state
  const [isExplainerOpen, setIsExplainerOpen] = useState(false);
  const [selectedEventIds, setSelectedEventIds] = useState(new Set());
  const [attachedContext, setAttachedContext] = useState({
    eventIds: [],
    findingIds: [],
    rawEvents: [],
    findings: [],
    uploadId: null,
    mode: 'upload',
  });

  // Uploaded dataset state
  const [uploadSummary, setUploadSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);

  // Events pagination & filters
  const [events, setEvents] = useState([]);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [totalEvents, setTotalEvents] = useState(0);
  const [levelFilter, setLevelFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sortBySeverity, setSortBySeverity] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoadingEvents, setIsLoadingEvents] = useState(false);

  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      handleFileUpload(files[0]);
    }
  };

  const handleFileSelect = (e) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileUpload(files[0]);
    }
  };

  const handleFileUpload = async (file) => {
    if (file.size > 20 * 1024 * 1024) {
      setErrorMessage(`File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max limit is 20 MB.`);
      return;
    }

    setErrorMessage(null);
    setIsUploading(true);
    setUploadProgress(25);

    try {
      const summary = await uploadLogFile(file);
      setUploadProgress(100);
      setUploadSummary(summary);
      setFindings(summary.findings || []);
      setEvents(summary.events_sample || []);
      setTotalEvents(summary.total_events || 0);
      setPage(1);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to upload and parse log file.');
    } finally {
      setIsUploading(false);
    }
  };

  const fetchEvents = async (
    newPage,
    newLevel = levelFilter,
    newSev = severityFilter,
    newSort = sortBySeverity,
    newQ = searchQuery
  ) => {
    if (!uploadSummary) return;
    setIsLoadingEvents(true);
    try {
      const res = await getUploadEvents(uploadSummary.id, {
        page: newPage,
        pageSize,
        level: newLevel,
        severity: newSev,
        sortBySeverity: newSort,
        q: newQ,
      });
      setEvents(res.events || []);
      setTotalEvents(res.total || 0);
      setPage(newPage);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setIsLoadingEvents(false);
    }
  };

  const handleFilterChange = (lvl) => {
    setLevelFilter(lvl);
    fetchEvents(1, lvl, severityFilter, sortBySeverity, searchQuery);
  };

  const handleSeverityFilterChange = (sev) => {
    setSeverityFilter(sev);
    fetchEvents(1, levelFilter, sev, sortBySeverity, searchQuery);
  };

  const handleSortBySeverityChange = (checked) => {
    setSortBySeverity(checked);
    fetchEvents(1, levelFilter, severityFilter, checked, searchQuery);
  };

  const handleSearchChange = (q) => {
    setSearchQuery(q);
    fetchEvents(1, levelFilter, severityFilter, sortBySeverity, q);
  };

  const handleAnalyze = async () => {
    if (!uploadSummary) return;
    setIsAnalyzing(true);
    try {
      const res = await analyzeUploadLog(uploadSummary.id);
      setAnalysisResult(res);
      setFindings(res.findings || []);
    } catch (err) {
      alert('Analysis failed: ' + err.message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const totalPages = Math.ceil(totalEvents / pageSize) || 1;

  // Multi-select handlers
  const handleToggleSelectAll = (checked) => {
    if (checked) {
      setSelectedEventIds(new Set(events.map((e) => e.id)));
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
      uploadId: uploadSummary?.id || null,
      mode: 'upload',
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
      uploadId: uploadSummary?.id || null,
      mode: 'upload',
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
      uploadId: uploadSummary?.id || null,
      mode: 'upload',
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
      uploadId: uploadSummary?.id || null,
      mode: 'upload',
    });
    setSelectedEventIds(new Set());
  };

  return (
    <div className={`upload-logs-workspace ${isExplainerOpen ? 'with-explainer-drawer' : ''}`}>
      {/* Upload Drop Zone */}
      <div
        className={`upload-drop-zone cyber-card ${isDragging ? 'drag-over' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          type="file"
          ref={fileInputRef}
          style={{ display: 'none' }}
          accept=".log,.txt,.csv,.json,.jsonl,.evtx,.syslog"
          onChange={handleFileSelect}
        />

        <div className="drop-zone-content">
          <div className="drop-icon-wrap">
            <UploadCloud size={36} color="var(--accent-cyan)" />
          </div>
          <div className="drop-text-wrap">
            <h3>Drag & Drop Log Files Here</h3>
            <p>
              Supports <strong>.log, .txt, .csv, .json, .jsonl, .evtx (Windows Event Logs)</strong> and Syslog formats (Max: 20 MB)
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary btn-select-file"
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploading}
          >
            <FileText size={15} />
            <span>Select File from Disk</span>
          </button>
        </div>

        {/* Upload Progress Bar */}
        {isUploading && (
          <div className="upload-progress-tray">
            <div className="progress-bar-bg">
              <div className="progress-bar-fill" style={{ width: `${uploadProgress}%` }}></div>
            </div>
            <span>Parsing and indexing events with deterministic severity mapping…</span>
          </div>
        )}

        {errorMessage && (
          <div className="upload-error-banner">
            <AlertCircle size={16} />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>

      {/* Dataset Summary & Action Bar */}
      {uploadSummary && (
        <div className="upload-dashboard">
          {/* Summary Banner */}
          <div className="summary-overview-strip cyber-card">
            <div className="overview-item">
              <span className="overview-label">File Name</span>
              <span className="overview-value cyan">{uploadSummary.filename}</span>
            </div>
            <div className="overview-item">
              <span className="overview-label">Total Events</span>
              <span className="overview-value">{uploadSummary.total_events?.toLocaleString()}</span>
            </div>
            <div className="overview-item">
              <span className="overview-label">File Size</span>
              <span className="overview-value">
                {(uploadSummary.file_size / 1024).toFixed(1)} KB
              </span>
            </div>
            {uploadSummary.time_range?.start && (
              <div className="overview-item">
                <span className="overview-label">Time Window</span>
                <span className="overview-value" style={{ fontSize: '0.8rem' }}>
                  {uploadSummary.time_range.start.split('T')[0]} to {uploadSummary.time_range.end?.split('T')[0]}
                </span>
              </div>
            )}

            <div className="overview-actions" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
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
              <button
                type="button"
                className="btn btn-primary btn-analyze-rag"
                disabled={isAnalyzing}
                onClick={handleAnalyze}
              >
                <Sparkles size={16} />
                <span>{isAnalyzing ? 'Correlating with SOPs…' : 'Analyze with CyberLLM (RAG)'}</span>
              </button>
            </div>
          </div>

          {/* Breakdown Pills Row: Levels & Severities */}
          <div className="breakdown-pills-row">
            {/* Severity Breakdown */}
            <div className="severity-breakdown-tray">
              <span className="tray-label">Severity Breakdown:</span>
              <div className="breakdown-chip sev-chip-critical" onClick={() => handleSeverityFilterChange('critical')}>
                <span>CRITICAL:</span>
                <strong>{uploadSummary.severities_count?.CRITICAL || 0}</strong>
              </div>
              <div className="breakdown-chip sev-chip-high" onClick={() => handleSeverityFilterChange('high')}>
                <span>HIGH:</span>
                <strong>{uploadSummary.severities_count?.HIGH || 0}</strong>
              </div>
              <div className="breakdown-chip sev-chip-medium" onClick={() => handleSeverityFilterChange('medium')}>
                <span>MEDIUM:</span>
                <strong>{uploadSummary.severities_count?.MEDIUM || 0}</strong>
              </div>
              <div className="breakdown-chip sev-chip-low" onClick={() => handleSeverityFilterChange('low')}>
                <span>LOW:</span>
                <strong>{uploadSummary.severities_count?.LOW || 0}</strong>
              </div>
            </div>

            {/* Top Sources */}
            <div className="top-sources-tray">
              <span className="tray-label">Top Sources:</span>
              {Object.entries(uploadSummary.top_sources || {}).map(([src, count]) => (
                <span key={src} className="source-pill">
                  {src} ({count})
                </span>
              ))}
            </div>
          </div>

          {/* Analysis Banner result if available */}
          {analysisResult && (
            <div className="analysis-summary-banner cyber-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles size={18} color="var(--accent-cyan)" />
                <strong>RAG Analysis Complete:</strong>
                <span>{analysisResult.summary}</span>
              </div>
            </div>
          )}

          {/* Split View: Events Table + Findings Panel */}
          <div className="upload-content-split">
            {/* Events Table Container */}
            <div className="upload-events-container cyber-card">
              {/* Filter & Pagination header */}
              <div className="events-controls-header">
                {/* Severity Filter */}
                <div className="filter-group">
                  <ShieldAlert size={14} color="var(--accent-rose)" />
                  <select
                    className="select-cyber"
                    value={severityFilter}
                    onChange={(e) => handleSeverityFilterChange(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                {/* Level Filter */}
                <div className="filter-group">
                  <Filter size={14} color="var(--text-dim)" />
                  <select
                    className="select-cyber"
                    value={levelFilter}
                    onChange={(e) => handleFilterChange(e.target.value)}
                  >
                    <option value="">All Levels</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="ERROR">Error</option>
                    <option value="WARNING">Warning</option>
                    <option value="INFO">Info</option>
                    <option value="DEBUG">Debug</option>
                  </select>
                </div>

                {/* Multi-select Action */}
                {selectedEventIds.size > 0 && (
                  <button
                    type="button"
                    className="btn btn-explain-selected"
                    onClick={handleExplainSelected}
                    title="Explain selected events together"
                  >
                    <Sparkles size={13} />
                    <span>Explain Selected ({selectedEventIds.size})</span>
                  </button>
                )}

                {/* Sort by severity */}
                <label className="autoscroll-toggle">
                  <input
                    type="checkbox"
                    checked={sortBySeverity}
                    onChange={(e) => handleSortBySeverityChange(e.target.checked)}
                  />
                  <ArrowUpDown size={13} color={sortBySeverity ? 'var(--accent-cyan)' : 'var(--text-dim)'} />
                  <span>Sort Severity</span>
                </label>

                <div className="search-wrap-full">
                  <Search size={14} color="var(--text-dim)" />
                  <input
                    type="text"
                    placeholder="Search messages, IDs, sources..."
                    value={searchQuery}
                    onChange={(e) => handleSearchChange(e.target.value)}
                  />
                </div>

                <div className="pagination-bar">
                  <button
                    type="button"
                    className="btn btn-icon"
                    disabled={page <= 1 || isLoadingEvents}
                    onClick={() => fetchEvents(page - 1)}
                  >
                    <ChevronLeft size={16} />
                  </button>
                  <span className="page-indicator">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    type="button"
                    className="btn btn-icon"
                    disabled={page >= totalPages || isLoadingEvents}
                    onClick={() => fetchEvents(page + 1)}
                  >
                    <ChevronRight size={16} />
                  </button>
                </div>
              </div>

              {/* Paginated Table with Severity */}
              <div className="events-table-wrapper">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th style={{ width: '40px', textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          aria-label="Select all events"
                          checked={events.length > 0 && selectedEventIds.size === events.length}
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
                    {events.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="table-empty-row">
                          {isLoadingEvents ? 'Loading events…' : 'No events match the current filter.'}
                        </td>
                      </tr>
                    ) : (
                      events.map((evt) => {
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
                            <td className="cell-source">{evt.source}</td>
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
              </div>
            </div>

            {/* Findings Panel */}
            <div className="upload-findings-sidebar">
              <ThreatOriginGlobe
                uploadId={uploadSummary?.id}
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
        </div>
      )}

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
