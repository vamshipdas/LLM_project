import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  FileText,
  MessageSquare,
  Ticket,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  CheckCircle,
  Clock,
  Tag,
  Sparkles
} from 'lucide-react';
import { createTicketFromFinding } from '../../api';
import AlertEmailIndicator from '../AlertEmailIndicator';

export default function FindingsPanel({ findings = [], onAskCyberLLM, onExplainFinding, onSelectAlert, showToast }) {

  const [expandedEvidence, setExpandedEvidence] = useState({});
  const [expandedCitations, setExpandedCitations] = useState({});
  const [ticketStatuses, setTicketStatuses] = useState({});
  const [isCreatingTicket, setIsCreatingTicket] = useState({});

  const toggleEvidence = (id) => {
    setExpandedEvidence((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleCitations = (id) => {
    setExpandedCitations((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCreateTicket = async (fnd) => {
    setIsCreatingTicket((prev) => ({ ...prev, [fnd.id]: true }));
    try {
      const res = await createTicketFromFinding({
        finding_id: fnd.id,
        title: fnd.title,
        category: fnd.category,
        severity: fnd.severity,
        description: `${fnd.description}\n\nMITRE: ${fnd.mitre_technique || 'N/A'}\nRecommended SOP: ${fnd.sop_recommendation || 'See SOP'}`,
      });
      setTicketStatuses((prev) => ({ ...prev, [fnd.id]: res.ticket_id }));
    } catch (err) {
      alert('Failed to create ticket: ' + err.message);
    } finally {
      setIsCreatingTicket((prev) => ({ ...prev, [fnd.id]: false }));
    }
  };

  if (!findings || findings.length === 0) {
    return (
      <div className="findings-empty">
        <CheckCircle size={32} color="var(--accent-emerald)" />
        <h4>No Active Security Findings</h4>
        <p>No rule violations or high-confidence anomalies detected in the current log stream.</p>
      </div>
    );
  }

  const getSeverityBadgeClass = (severity) => {
    const s = (severity || 'medium').toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-high';
    if (s === 'medium') return 'badge-medium';
    return 'badge-low';
  };

  return (
    <div className="findings-panel-container">
      <div className="findings-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={18} color="var(--accent-rose)" />
          <h3>Security Findings ({findings.length})</h3>
        </div>
        <span className="findings-hint">RAG Correlated with Organizational SOPs</span>
      </div>

      <div className="findings-list">
        {findings.map((fnd) => {
          const ticketId = fnd.ticket_id || ticketStatuses[fnd.id];
          const hasEvidence = fnd.evidence && fnd.evidence.length > 0;
          const hasCitations = fnd.sop_citations && fnd.sop_citations.length > 0;

          return (
            <div
              key={fnd.id}
              className="finding-card draggable-finding"
              draggable="true"
              onClick={(e) => {
                if (e.target.closest('button')) return;
                if (onSelectAlert) {
                  onSelectAlert({
                    type: 'finding',
                    id: fnd.id,
                    title: fnd.title,
                    threat_type: fnd.category,
                    severity: fnd.severity,
                    finding: fnd,
                  });
                }
              }}
              onDragStart={(e) => {
                e.dataTransfer.setData('application/x-soc-finding', JSON.stringify(fnd));
                e.dataTransfer.setData('text/plain', `Finding: ${fnd.title}`);
              }}
              title="Click for Alert Detail, or drag to Log Explainer"
            >
              <div className="finding-card-top">
                <div className="finding-tags">
                  <span className={`badge ${getSeverityBadgeClass(fnd.severity)}`}>
                    {fnd.severity?.toUpperCase()}
                  </span>
                  <AlertEmailIndicator
                    alertId={fnd.id}
                    severity={fnd.severity}
                    showToast={showToast}
                  />
                  {fnd.mitre_technique && (
                    <span className="badge badge-mitre">
                      <Tag size={10} style={{ marginRight: '4px' }} />
                      MITRE {fnd.mitre_technique}
                    </span>
                  )}
                  <span className="badge badge-category">{fnd.category}</span>
                </div>
                {fnd.first_seen && (
                  <span className="finding-time">
                    <Clock size={12} /> {fnd.first_seen.split('T')[1]?.substring(0, 8) || fnd.first_seen}
                  </span>
                )}
              </div>

              <h4 className="finding-title">{fnd.title}</h4>
              <p className="finding-desc">{fnd.description}</p>

              {/* Evidence Section */}
              {hasEvidence && (
                <div className="finding-evidence-block">
                  <button
                    type="button"
                    className="btn-toggle-evidence"
                    onClick={() => toggleEvidence(fnd.id)}
                  >
                    {expandedEvidence[fnd.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    <span>Evidence ({fnd.evidence.length} events)</span>
                  </button>
                  {expandedEvidence[fnd.id] && (
                    <div className="evidence-list">
                      {fnd.evidence.map((eid, idx) => (
                        <div key={idx} className="evidence-item">
                          <code>{eid}</code>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Recommended SOP steps */}
              {fnd.sop_recommendation && (
                <div className="finding-sop-box">
                  <div className="sop-box-title">
                    <FileText size={14} color="var(--accent-cyan)" />
                    <span>Recommended SOP Procedure</span>
                  </div>
                  <div className="sop-box-content">
                    {fnd.sop_recommendation}
                  </div>

                  {/* SOP Citations */}
                  {hasCitations && (
                    <div className="sop-citations-wrapper">
                      <button
                        type="button"
                        className="btn-toggle-citations"
                        onClick={() => toggleCitations(fnd.id)}
                      >
                        {expandedCitations[fnd.id] ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                        <span>SOP Source Citations ({fnd.sop_citations.length})</span>
                      </button>
                      {expandedCitations[fnd.id] && (
                        <div className="citations-tray">
                          {fnd.sop_citations.map((c, i) => (
                            <div key={i} className="citation-pill">
                              <span className="cit-sop">{c.sop_id}</span>
                              <span className="cit-sec">§{c.section}</span>
                              <p className="cit-excerpt">{c.excerpt}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Actions row */}
              <div className="finding-actions">
                <button
                  type="button"
                  className="btn btn-explain-finding"
                  onClick={() => onExplainFinding && onExplainFinding(fnd)}
                  title="Explain this finding in simple terms"
                >
                  <Sparkles size={13} color="var(--accent-cyan)" />
                  <span>Explain in simple terms</span>
                </button>

                <button
                  type="button"
                  className="btn btn-ask-ai"
                  onClick={() =>
                    onAskCyberLLM &&
                    onAskCyberLLM(
                      `How do I handle this finding: [${fnd.title}]? ${fnd.description}. What are the step-by-step SOP containment and remediation procedures?`
                    )
                  }
                  title="Open Chat with this finding pre-filled"
                >
                  <MessageSquare size={13} />
                  <span>Ask CyberLLM</span>
                </button>

                {ticketId ? (
                  <div className="ticket-linked-badge">
                    <Ticket size={13} />
                    <span>Ticket: {ticketId}</span>
                  </div>
                ) : (
                  <button
                    type="button"
                    className="btn btn-create-ticket"
                    disabled={isCreatingTicket[fnd.id]}
                    onClick={() => handleCreateTicket(fnd)}
                  >
                    <Ticket size={13} />
                    <span>{isCreatingTicket[fnd.id] ? 'Creating…' : 'Create ticket'}</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
