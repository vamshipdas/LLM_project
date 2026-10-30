import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  Globe,
  FileText,
  CheckCircle2,
  AlertTriangle,
  TrendingUp,
  Copy,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sparkles,
  MessageSquare,
  Clock,
  Layers,
  MapPin,
  Check,
  RotateCcw,
  CheckSquare
} from 'lucide-react';
import { getAlertSummary, updateAlertStatus, createTicketFromFinding } from '../../api';

const SEVERITY_COLORS = {
  CRITICAL: '#fb7185',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

export default function AlertDetailDrawer({
  isOpen,
  onClose,
  alertData, // { type: 'ticket'|'finding'|'log'|'ip', id: string, title?: string, origin?: object }
  onOpenInWorkspace = null,
  onFocusGlobe = null,
  onStatusUpdated = null,
}) {
  const [activeTab, setActiveTab] = useState('summary'); // 'summary' | 'ask_bot'
  const [mode, setMode] = useState('simple'); // 'simple' | 'technical'
  const [summary, setSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [isTechExpanded, setIsTechExpanded] = useState(false);

  // Load summary when drawer opens or alert/mode changes
  useEffect(() => {
    if (!isOpen || !alertData?.id) return;

    let isCancelled = false;
    setIsLoading(true);
    setError(null);

    getAlertSummary(alertData.type || 'ticket', alertData.id, mode)
      .then((data) => {
        if (!isCancelled) {
          setSummary(data);
          // If globe focus callback available and origin has coordinates, focus globe
          if (onFocusGlobe && data.origin?.lat != null && data.origin?.lon != null) {
            onFocusGlobe(data.origin);
          }
        }
      })
      .catch((err) => {
        if (!isCancelled) {
          console.error('Failed to load alert summary:', err);
          setError(err.message || 'Failed to load alert intelligence summary.');
        }
      })
      .finally(() => {
        if (!isCancelled) setIsLoading(false);
      });

    return () => {
      isCancelled = true;
    };
  }, [isOpen, alertData?.type, alertData?.id, mode]);

  if (!isOpen) return null;

  const currentStatus = summary?.status || alertData?.status || 'open';
  const currentSeverity = (summary?.severity || alertData?.severity || 'MEDIUM').toUpperCase();
  const sevColor = SEVERITY_COLORS[currentSeverity] || '#eab308';

  const handleStatusChange = async (newStatus) => {
    if (!alertData?.id) return;
    setIsUpdatingStatus(true);
    try {
      await updateAlertStatus(alertData.type || 'ticket', alertData.id, newStatus);
      setSummary((prev) => (prev ? { ...prev, status: newStatus } : prev));
      if (onStatusUpdated) {
        onStatusUpdated(alertData.id, newStatus);
      }
    } catch (err) {
      alert(`Could not update alert status: ${err.message}`);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleCopySummary = () => {
    if (!summary) return;
    const textToCopy = `[${summary.severity}] ${summary.title} (${summary.id})
Status: ${summary.status.toUpperCase()}
What happened: ${summary.what_happened}
Why it matters: ${summary.why_it_matters}
Severity Reason: ${summary.severity_reason}
Origin: ${summary.origin?.ip || 'N/A'} (${summary.origin?.country || 'Unknown'})
Next Steps:
${(summary.sop_actions?.steps || []).join('\n')}`;

    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenWorkspace = () => {
    if (onOpenInWorkspace && summary) {
      const prompt = `Investigate alert ${summary.id}: ${summary.title}
Severity: ${summary.severity}
Origin: ${summary.origin?.ip || 'N/A'} (${summary.origin?.country || 'Unknown'})
Details: ${summary.what_happened}
Why it matters: ${summary.why_it_matters}`;
      onOpenInWorkspace(prompt);
      onClose();
    }
  };

  return (
    <div className="alert-drawer-backdrop" onClick={onClose}>
      <div
        className="alert-detail-drawer"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Alert Detail Panel"
      >
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-header-top">
            <div className="alert-meta-badges">
              <span className="alert-id-tag">
                {alertData?.type?.toUpperCase() || 'ALERT'}: {alertData?.id}
              </span>
              <span
                className="alert-sev-badge"
                style={{
                  backgroundColor: `${sevColor}22`,
                  color: sevColor,
                  border: `1px solid ${sevColor}44`,
                }}
              >
                <span className="badge-pulse-dot" style={{ backgroundColor: sevColor }} />
                {currentSeverity}
              </span>
            </div>

            <div className="drawer-header-actions">
              {/* Mode Toggle (Simple / Technical) */}
              <div className="mode-toggle-pill" title="Toggle between simplified plain language and technical view">
                <button
                  type="button"
                  className={`toggle-opt ${mode === 'simple' ? 'active' : ''}`}
                  onClick={() => setMode('simple')}
                >
                  Simple
                </button>
                <button
                  type="button"
                  className={`toggle-opt ${mode === 'technical' ? 'active' : ''}`}
                  onClick={() => setMode('technical')}
                >
                  Technical
                </button>
              </div>

              {/* Close Button */}
              <button
                type="button"
                className="btn-drawer-close"
                onClick={onClose}
                aria-label="Close drawer"
              >
                <X size={18} />
              </button>
            </div>
          </div>

          <h2 className="drawer-title">{summary?.title || alertData?.title || 'Investigating Alert'}</h2>

          {/* Status Dropdown */}
          <div className="drawer-status-bar">
            <div className="status-selector-wrap">
              <span className="status-label">Status:</span>
              <select
                className={`drawer-status-select status-${currentStatus}`}
                value={currentStatus}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={isUpdatingStatus}
              >
                <option value="open">Open (Untriaged)</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>

            {summary?.origin?.country && summary.origin.country !== 'Unknown' && (
              <button
                type="button"
                className="btn-focus-globe"
                onClick={() => onFocusGlobe && summary.origin && onFocusGlobe(summary.origin)}
                title="Fly globe to attacker origin"
              >
                <Globe size={13} color="var(--accent-cyan)" />
                <span>Fly to {summary.origin.country}</span>
              </button>
            )}
          </div>

          {/* Drawer Navigation Tabs */}
          <div className="drawer-tabs">
            <button
              type="button"
              className={`drawer-tab-btn ${activeTab === 'summary' ? 'active' : ''}`}
              onClick={() => setActiveTab('summary')}
            >
              <FileText size={14} />
              <span>Summary</span>
            </button>
            <button
              type="button"
              className={`drawer-tab-btn ${activeTab === 'ask_bot' ? 'active' : ''}`}
              onClick={() => setActiveTab('ask_bot')}
            >
              <MessageSquare size={14} color="var(--accent-cyan)" />
              <span>Ask Bot</span>
              <span className="tab-context-chip">{alertData?.id}</span>
            </button>
          </div>
        </div>

        {/* Drawer Body Content */}
        <div className="drawer-body">
          {isLoading ? (
            <div className="drawer-loading-state">
              <span className="drawer-spinner" />
              <p>Analyzing telemetry and correlating organizational SOPs…</p>
            </div>
          ) : error ? (
            <div className="drawer-error-state">
              <AlertTriangle size={28} color="var(--accent-rose)" />
              <h4>Unable to load alert intelligence</h4>
              <p>{error}</p>
            </div>
          ) : activeTab === 'summary' && summary ? (
            <div className="summary-tab-content">
              {/* 1. What Happened */}
              <div className="summary-card">
                <div className="card-header-label">
                  <Sparkles size={14} color="var(--accent-cyan)" />
                  <h4>What Happened</h4>
                </div>
                <p className="plain-text-statement">{summary.what_happened}</p>
              </div>

              {/* 2. Why It Matters */}
              <div className="summary-card">
                <div className="card-header-label">
                  <ShieldAlert size={14} color="var(--accent-amber)" />
                  <h4>Why It Matters</h4>
                </div>
                <p className="plain-text-statement">{summary.why_it_matters}</p>
              </div>

              {/* 3. Severity & Reason */}
              <div className="summary-card sev-summary-card">
                <div className="card-header-label">
                  <Layers size={14} style={{ color: sevColor }} />
                  <h4>Assessed Severity</h4>
                </div>
                <div className="sev-detail-row">
                  <span
                    className="sev-indicator-pill"
                    style={{
                      backgroundColor: `${sevColor}22`,
                      color: sevColor,
                      border: `1px solid ${sevColor}55`,
                    }}
                  >
                    {summary.severity} ({summary.severity_score}/100)
                  </span>
                  <span className="sev-reason-text">{summary.severity_reason}</span>
                </div>
              </div>

              {/* 4. Where It Came From (Origin Geo Card) */}
              <div className="summary-card origin-card">
                <div className="card-header-label">
                  <MapPin size={14} color="var(--accent-cyan)" />
                  <h4>Where It Came From</h4>
                  {summary.origin?.badge && (
                    <span className={`origin-badge-pill ${summary.origin.badge.toLowerCase()}`}>
                      {summary.origin.badge}
                    </span>
                  )}
                </div>
                <div className="origin-details-grid">
                  <div className="origin-item">
                    <span className="item-label">Source IP:</span>
                    <strong className="item-value cyan">{summary.origin?.ip || 'Internal / N/A'}</strong>
                  </div>
                  <div className="origin-item">
                    <span className="item-label">Geolocation:</span>
                    <span className="item-value">
                      {summary.origin?.city && summary.origin.city !== 'Unknown' ? `${summary.origin.city}, ` : ''}
                      {summary.origin?.country || 'Unknown'}
                    </span>
                  </div>
                  <div className="origin-item">
                    <span className="item-label">Network / ASN:</span>
                    <span className="item-value">{summary.origin?.asn || 'AS0'} — {summary.origin?.org || 'Local'}</span>
                  </div>
                  <div className="origin-item">
                    <span className="item-label">Classification:</span>
                    <span className="item-value capitalize">{summary.origin?.classification || 'Public'}</span>
                  </div>
                </div>
              </div>

              {/* 5. What To Do First (SOP Steps & Citations) */}
              <div className="summary-card sop-card">
                <div className="card-header-label">
                  <CheckSquare size={14} color="var(--accent-emerald)" />
                  <h4>What To Do First</h4>
                  {summary.sop_actions?.has_matching_sop && (
                    <span className="sop-matched-badge">Verified Organizational SOP</span>
                  )}
                </div>
                <div className="sop-steps-list">
                  {(summary.sop_actions?.steps || []).map((step, idx) => (
                    <div key={idx} className="sop-step-row">
                      <span className="step-num">{idx + 1}</span>
                      <p className="step-text">{step.replace(/^\d+\.\s*/, '')}</p>
                    </div>
                  ))}
                </div>

                {summary.sop_actions?.citations?.length > 0 && (
                  <div className="sop-citations-strip">
                    <span className="citation-lead">Official Citations:</span>
                    {summary.sop_actions.citations.map((c, i) => (
                      <span key={i} className="sop-citation-chip" title={`Relevance score: ${c.similarity}`}>
                        {c.title}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* 6. Is It Likely Real? (False Positive Likelihood) */}
              <div className="summary-card likelihood-card">
                <div className="card-header-label">
                  <AlertTriangle size={14} color={summary.likelihood?.confidence === 'High' ? 'var(--accent-rose)' : 'var(--accent-amber)'} />
                  <h4>Is It Likely Real?</h4>
                </div>
                <div className="likelihood-status-strip">
                  <span className={`verdict-pill ${summary.severity === 'CRITICAL' || summary.severity === 'HIGH' ? 'verdict-malicious' : 'verdict-benign'}`}>
                    {summary.likelihood?.verdict}
                  </span>
                  <span className="confidence-pill">
                    Confidence: <strong>{summary.likelihood?.confidence}</strong>
                  </span>
                </div>
                <ul className="likelihood-reasons-list">
                  {(summary.likelihood?.reasons || []).map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>

              {/* 7. What Might Happen Next (Trajectory Prediction) */}
              <div className="summary-card trajectory-card">
                <div className="card-header-label">
                  <TrendingUp size={14} color="var(--accent-cyan)" />
                  <h4>What Might Happen Next</h4>
                  <span className="trajectory-tag">ATT&CK Trajectory Graph</span>
                </div>
                <p className="trajectory-intro">
                  Predicted next techniques computed from observed evidence and Cyber Kill Chain transition paths:
                </p>
                <div className="trajectory-list">
                  {(summary.trajectory || []).map((item, idx) => (
                    <div key={idx} className="trajectory-item">
                      <div className="trajectory-header">
                        <div className="technique-meta">
                          <span className="tech-id-badge">{item.technique_id}</span>
                          <strong className="tech-name">{item.name}</strong>
                          <span className="tech-tactic">{item.tactic}</span>
                        </div>
                        <span className="tech-prob-pct">{item.probability_pct}%</span>
                      </div>
                      <div className="trajectory-bar-bg">
                        <div
                          className="trajectory-bar-fill"
                          style={{
                            width: `${item.probability_pct}%`,
                            backgroundColor:
                              item.probability_pct > 70
                                ? 'var(--accent-rose)'
                                : item.probability_pct > 40
                                ? 'var(--accent-amber)'
                                : 'var(--accent-cyan)',
                          }}
                        />
                      </div>
                      <div className="trajectory-rationale">{item.rationale}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 8. Expandable Technical Details */}
              <div className="summary-card technical-accordion-card">
                <button
                  type="button"
                  className="accordion-trigger"
                  onClick={() => setIsTechExpanded(!isTechExpanded)}
                  aria-expanded={isTechExpanded}
                >
                  <div className="card-header-label">
                    <FileText size={14} color="var(--text-muted)" />
                    <h4>Technical Telemetry & Evidence</h4>
                  </div>
                  {isTechExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                </button>

                {isTechExpanded && (
                  <div className="accordion-content">
                    <div className="tech-meta-grid">
                      <div>
                        <span className="tech-meta-lbl">MITRE ATT&CK:</span>
                        <code className="tech-code">{summary.technical_details?.mitre_technique || 'N/A'}</code>
                      </div>
                      <div>
                        <span className="tech-meta-lbl">Target Host:</span>
                        <span className="tech-val">{summary.technical_details?.target_host || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="tech-meta-lbl">Linked Events:</span>
                        <span className="tech-val">{summary.technical_details?.linked_events?.length || 0} events</span>
                      </div>
                      <div>
                        <span className="tech-meta-lbl">Timeline:</span>
                        <span className="tech-val">
                          {summary.technical_details?.timeline?.first_seen
                            ? new Date(summary.technical_details.timeline.first_seen).toLocaleTimeString()
                            : 'N/A'}
                        </span>
                      </div>
                    </div>

                    {summary.technical_details?.linked_events?.length > 0 && (
                      <div className="linked-events-list">
                        <h5>Correlated Log Events (Secrets Redacted)</h5>
                        {summary.technical_details.linked_events.slice(0, 10).map((evt, idx) => (
                          <div key={idx} className="raw-event-row">
                            <span className="raw-time">{evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '—'}</span>
                            <span className={`raw-level level-${(evt.level || 'info').toLowerCase()}`}>{evt.level}</span>
                            <span className="raw-source">{evt.source}</span>
                            <span className="raw-msg">{evt.message}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          ) : activeTab === 'ask_bot' ? (
            /* Part 2 / Part 3 Ask Bot Placeholder (Wired in Next Phases) */
            <div className="ask-bot-tab-content">
              <div className="bot-welcome-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Sparkles size={16} color="var(--accent-cyan)" />
                  <strong>Alert Assistant</strong>
                </div>
                <p>Chat with CyberLLM about this specific alert. Context is automatically attached.</p>
              </div>
              <div className="bot-coming-prompt">
                <MessageSquare size={32} color="var(--accent-cyan)" style={{ margin: '0 auto 12px' }} />
                <p>Proceeding to Phase 2 & 3: Alert-scoped chat engine and interactive questions.</p>
              </div>
            </div>
          ) : null}
        </div>

        {/* Drawer Action Buttons Footer */}
        <div className="drawer-footer">
          <div className="drawer-footer-actions">
            <button
              type="button"
              className="btn btn-secondary btn-icon-text"
              onClick={handleCopySummary}
              disabled={!summary}
            >
              {copied ? <Check size={14} color="var(--accent-emerald)" /> : <Copy size={14} />}
              <span>{copied ? 'Copied!' : 'Copy Summary'}</span>
            </button>

            {currentStatus !== 'resolved' && (
              <button
                type="button"
                className="btn btn-secondary btn-icon-text"
                onClick={() => handleStatusChange('resolved')}
                disabled={isUpdatingStatus}
              >
                <CheckCircle2 size={14} color="var(--accent-emerald)" />
                <span>Mark Resolved</span>
              </button>
            )}

            <button
              type="button"
              className="btn btn-primary btn-icon-text"
              onClick={handleOpenWorkspace}
              title="Open this alert in Incident Workspace for full investigation"
            >
              <ExternalLink size={14} />
              <span>Open in Workspace</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
