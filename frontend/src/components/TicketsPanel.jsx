import React, { useEffect, useState } from 'react';
import {
  AlertCircle, Bug, CheckCircle2, CircleDot, Cpu, Download, Flame,
  GripVertical, MessageSquare, MoreHorizontal, RotateCcw, ShieldAlert,
} from 'lucide-react';
import { listTickets, updateTicketStatus } from '../api';
import ThreatOriginGlobe from './ThreatMap/ThreatOriginGlobe';
import AlertEmailIndicator from './AlertEmailIndicator';


const ICON_MAP = {
  ransomware: <Flame size={14} color="#fb7185" />,
  phishing: <AlertCircle size={14} color="#38bdf8" />,
  brute_force: <Cpu size={14} color="#fbbf24" />,
  malware: <Bug size={14} color="#facc15" />,
  data_exfiltration: <Download size={14} color="#22c55e" />,
  unauthorized_access: <ShieldAlert size={14} color="#a855f7" />,
};

const SEVERITY_COLOR = {
  CRITICAL: '#fb7185',
  HIGH: '#f59e0b',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
};

const TICKET_FILTERS = [
  ['unresolved', 'Unresolved'],
  ['in_progress', 'In progress'],
  ['resolved', 'Resolved'],
];

function ticketToPrompt(ticket) {
  return [
    `Investigate SOC ticket ${ticket.id}: ${ticket.title}`,
    `Threat type: ${ticket.threat_type}`,
    `Severity: ${ticket.severity}`,
    `Status: ${ticket.status || 'not set (untriaged)'}`,
    `Source IP: ${ticket.source_ip || 'unknown'}`,
    `Target host: ${ticket.target_host || 'unknown'}`,
    `Details: ${ticket.description}`,
    'Assess the incident, use the company SOP knowledge tool when relevant, and recommend prioritized next actions.',
  ].join('\n');
}

export default function TicketsPanel({ onUseTicket, onSelectAlert, showToast }) {
  const [tickets, setTickets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [openActionsId, setOpenActionsId] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);
  const [filter, setFilter] = useState('unresolved');
  const [selectedTicketId, setSelectedTicketId] = useState(null);

  useEffect(() => {
    listTickets().then(setTickets).finally(() => setIsLoading(false));
  }, []);

  const setStatus = async (ticket, status) => {
    setUpdatingId(ticket.id);
    try {
      const updated = await updateTicketStatus(ticket.id, status);
      setTickets((current) => current.map((item) => item.id === ticket.id ? updated : item));
      return updated;
    } catch (error) {
      alert(`Could not update ticket: ${error.message}`);
      return null;
    } finally {
      setUpdatingId(null);
      setOpenActionsId(null);
    }
  };

  const investigate = async (ticket) => {
    const updated = ticket.status === 'in_progress' ? ticket : await setStatus(ticket, 'in_progress');
    if (updated) onUseTicket(ticketToPrompt(updated));
  };

  const counts = Object.fromEntries(TICKET_FILTERS.map(([status]) => [
    status,
    tickets.filter((ticket) => status === 'unresolved' ? !ticket.status : ticket.status === status).length,
  ]));
  const visibleTickets = tickets.filter((ticket) => (
    filter === 'unresolved' ? !ticket.status : ticket.status === filter
  ));

  if (isLoading) {
    return <aside className="tickets-panel tickets-panel--loading">Loading tickets…</aside>;
  }

  return (
    <aside className="tickets-panel">
      <div className="tickets-panel__header">
        <ShieldAlert size={18} color="#38bdf8" />
        <div>
          <strong>Incoming Tickets</strong>
          <span>{tickets.filter((ticket) => ticket.status !== 'resolved').length} active · drag into chat</span>
        </div>
      </div>

      <div className="ticket-filters" aria-label="Filter tickets">
        {TICKET_FILTERS.map(([status, label]) => (
          <button
            key={status}
            type="button"
            aria-pressed={filter === status}
            onClick={() => {
              setFilter(status);
              setOpenActionsId(null);
            }}
          >
            {label} <span>{counts[status]}</span>
          </button>
        ))}
      </div>

      <div className="tickets-list">
        {visibleTickets.length === 0 ? (
          <div className="tickets-empty">No {TICKET_FILTERS.find(([status]) => status === filter)[1].toLowerCase()} tickets.</div>
        ) : visibleTickets.map((ticket) => (
          <article
            key={ticket.id}
            className={`ticket-card ticket-card--${ticket.status || 'untriaged'}${openActionsId === ticket.id ? ' ticket-card--actions-open' : ''}`}
            draggable={openActionsId !== ticket.id}
            onClick={(e) => {
              if (e.target.closest('button') || e.target.closest('.ticket-actions-menu')) return;
              if (onSelectAlert) {
                onSelectAlert({
                  type: 'ticket',
                  id: ticket.id,
                  title: ticket.title,
                  threat_type: ticket.threat_type,
                  severity: ticket.severity,
                  status: ticket.status,
                  source_ip: ticket.source_ip,
                });
              }
            }}
            onDragStart={(event) => {
              const prompt = ticketToPrompt(ticket);
              event.dataTransfer.effectAllowed = 'copy';
              event.dataTransfer.setData('application/x-soc-ticket', prompt);
              event.dataTransfer.setData('text/plain', prompt);
            }}
          >
            <div className="ticket-card__header">
              <div className="ticket-card__id">
                <GripVertical className="ticket-grip" size={14} />
                {ICON_MAP[ticket.threat_type] || <ShieldAlert size={14} color="#a855f7" />}
                <span>{ticket.id}</span>
              </div>

              <div className="ticket-card__controls">
                <AlertEmailIndicator
                  alertId={ticket.id}
                  severity={ticket.severity}
                  showToast={showToast}
                />
                <span style={{ color: SEVERITY_COLOR[ticket.severity] || '#94a3b8' }}>
                  {ticket.severity}
                </span>
                <button
                  type="button"
                  className="ticket-actions-trigger"
                  aria-label={`Actions for ${ticket.id}`}
                  aria-expanded={openActionsId === ticket.id}
                  onClick={() => setOpenActionsId(openActionsId === ticket.id ? null : ticket.id)}
                >
                  <MoreHorizontal size={16} />
                </button>

                {openActionsId === ticket.id && (
                  <div className="ticket-actions-menu" onPointerDown={(event) => event.stopPropagation()}>
                    <button type="button" onClick={() => investigate(ticket)} disabled={updatingId === ticket.id}>
                      <MessageSquare size={14} /> Investigate with agent
                    </button>
                    {ticket.status !== 'in_progress' && (
                      <button type="button" onClick={() => setStatus(ticket, 'in_progress')} disabled={updatingId === ticket.id}>
                        <CircleDot size={14} /> Mark in progress
                      </button>
                    )}
                    {ticket.status !== 'resolved' && (
                      <button type="button" onClick={() => setStatus(ticket, 'resolved')} disabled={updatingId === ticket.id}>
                        <CheckCircle2 size={14} /> Mark resolved
                      </button>
                    )}
                    {ticket.status && (
                      <button type="button" onClick={() => setStatus(ticket, null)} disabled={updatingId === ticket.id}>
                        <RotateCcw size={14} /> Reset to untriaged
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>

            <h3>{ticket.title}</h3>
            <div className="ticket-card__meta">
              <span>Host: {ticket.target_host || '—'}</span>
              <span>Src: {ticket.source_ip || '—'}</span>
            </div>

            {selectedTicketId === ticket.id && (
              <div
                className="ticket-globe-wrapper"
                style={{ marginTop: '10px' }}
                onClick={(e) => e.stopPropagation()}
              >
                <ThreatOriginGlobe isCompact={true} />
              </div>
            )}
          </article>
        ))}
      </div>
    </aside>
  );
}
