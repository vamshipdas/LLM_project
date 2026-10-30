import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  X,
  Send,
  Trash2,
  FileText,
  AlertTriangle,
  ShieldAlert,
  ChevronRight,
  ExternalLink,
  Ticket,
  Bot,
  User,
  SlidersHorizontal,
  HelpCircle,
  Plus
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { sendChatLogExplainer, clearLogChatMessages, createTicketFromFinding } from '../../api';
import SeverityBadge from './SeverityBadge';

export default function LogExplainerChat({
  isOpen,
  onClose,
  attachedContext = { eventIds: [], findingIds: [], rawEvents: [], findings: [], uploadId: null, mode: 'live' },
  onRemoveEvent,
  onRemoveFinding,
  onClearContext,
  onAddEventContext,
  onAddFindingContext,
  onAskCyberLLM,
}) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [detailLevel, setDetailLevel] = useState('simple'); // 'simple' | 'technical'
  const [sessionId] = useState(() => `lchat-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`);
  const [suggestedQuestions, setSuggestedQuestions] = useState([
    'Explain this log in simple terms',
    'Is this normal or dangerous?',
    'What should I do first?',
    'Summarize the recent activity',
  ]);
  const [isCreatingTicket, setIsCreatingTicket] = useState(false);

  const endRef = useRef(null);
  const inputRef = useRef(null);

  // Auto scroll to bottom
  useEffect(() => {
    if (isOpen) {
      endRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isSending, isOpen]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen]);

  // Handle Drag & Drop inside chat drawer
  const handleDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const eventJson = e.dataTransfer.getData('application/x-soc-log-event');
    const findingJson = e.dataTransfer.getData('application/x-soc-finding');

    if (eventJson) {
      try {
        const evt = JSON.parse(eventJson);
        onAddEventContext?.(evt);
      } catch (err) {
        console.error('Failed to parse dropped event:', err);
      }
    } else if (findingJson) {
      try {
        const fnd = JSON.parse(findingJson);
        onAddFindingContext?.(fnd);
      } catch (err) {
        console.error('Failed to parse dropped finding:', err);
      }
    }
  };

  const handleSendMessage = async (textToSend, customContext = null) => {
    const text = (textToSend || input).trim();
    if (!text || isSending) return;

    setInput('');
    setIsSending(true);

    const now = new Date().toISOString();
    const activeCtx = customContext || attachedContext;

    // Add user message
    const userMsg = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: text,
      created_at: now,
      contextSnapshot: {
        eventsCount: activeCtx.rawEvents?.length || activeCtx.eventIds?.length || 0,
        findingsCount: activeCtx.findings?.length || activeCtx.findingIds?.length || 0,
      },
    };

    setMessages((prev) => [...prev, userMsg]);

    try {
      const payload = {
        message: text,
        sessionId: sessionId,
        detailLevel: detailLevel,
        context: {
          event_ids: activeCtx.eventIds || [],
          finding_ids: activeCtx.findingIds || [],
          upload_id: activeCtx.uploadId || null,
          mode: activeCtx.mode || 'live',
          raw_events: activeCtx.rawEvents || [],
        },
      };

      const res = await sendChatLogExplainer(payload);

      const assistantMsg = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: res.answer,
        severity_summary: res.severity_summary,
        citations: res.citations || [],
        suggested_questions: res.suggested_questions || [],
        created_at: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
      if (res.suggested_questions && res.suggested_questions.length > 0) {
        setSuggestedQuestions(res.suggested_questions);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: 'assistant',
          content: `Unable to complete log analysis: ${err.message}. Please check your connection or try again.`,
          isError: true,
          created_at: new Date().toISOString(),
        },
      ]);
    } finally {
      setIsSending(false);
      inputRef.current?.focus();
    }
  };

  const handleClearChat = async () => {
    try {
      await clearLogChatMessages(sessionId);
    } catch (e) {
      // Ignore if session had no messages yet
    }
    setMessages([]);
    onClearContext?.();
  };

  const handleCreateTicketFromMsg = async (msg) => {
    setIsCreatingTicket(true);
    try {
      const sev = msg.severity_summary?.severity || 'medium';
      const firstLine = msg.content.split('\n')[0] || 'Log Event Investigation';
      const res = await createTicketFromFinding({
        title: `[Explainer] ${firstLine.substring(0, 80)}`,
        category: 'Log Analysis',
        severity: sev,
        description: `${msg.content}\n\nGenerated by Log Explainer (Session: ${sessionId})`,
      });
      alert(`Incident Ticket created successfully: ${res.ticket_id}`);
    } catch (err) {
      alert(`Failed to create ticket: ${err.message}`);
    } finally {
      setIsCreatingTicket(false);
    }
  };

  const handleHandoffToWorkspace = (msg) => {
    if (!onAskCyberLLM) return;
    const handoffText = `Incident context investigated via Log Explainer:\n\n${msg.content}\n\nWhat are the next operational steps to contain and remediate this across our environment?`;
    onAskCyberLLM(handoffText);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (!isOpen) return null;

  const totalAttached =
    (attachedContext.rawEvents?.length || attachedContext.eventIds?.length || 0) +
    (attachedContext.findings?.length || attachedContext.findingIds?.length || 0);

  return (
    <aside
      className="log-explainer-drawer"
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* Header */}
      <div className="explainer-header">
        <div className="explainer-title-group">
          <div className="explainer-sparkle-badge">
            <Sparkles size={18} color="var(--accent-cyan)" />
          </div>
          <div>
            <div className="explainer-title-row">
              <h3>Log Explainer</h3>
              <span className="explainer-pill-bot">SOC Agent</span>
            </div>
            <span className="explainer-subtitle">Plain-English Translation & SOP RAG</span>
          </div>
        </div>

        <div className="explainer-header-actions">
          {/* Simple vs Technical toggle */}
          <div className="toggle-segmented" title="Toggle Plain-Language vs Technical View">
            <button
              type="button"
              className={`seg-btn ${detailLevel === 'simple' ? 'active' : ''}`}
              onClick={() => setDetailLevel('simple')}
            >
              Simple
            </button>
            <button
              type="button"
              className={`seg-btn ${detailLevel === 'technical' ? 'active' : ''}`}
              onClick={() => setDetailLevel('technical')}
            >
              Technical
            </button>
          </div>

          <button
            type="button"
            className="btn-icon-subtle"
            title="Clear Chat History"
            onClick={handleClearChat}
          >
            <Trash2 size={15} />
          </button>

          <button
            type="button"
            className="btn-icon-subtle"
            title="Close Drawer"
            onClick={onClose}
          >
            <X size={17} />
          </button>
        </div>
      </div>

      {/* Attached Context Chips Bar */}
      <div className="attached-context-tray">
        <div className="context-tray-header">
          <span className="context-label">
            Active Context ({totalAttached})
          </span>
          {totalAttached > 0 && (
            <button
              type="button"
              className="btn-link-clear"
              onClick={onClearContext}
            >
              Clear all
            </button>
          )}
        </div>

        {totalAttached === 0 ? (
          <div className="dropzone-hint">
            <span>Drag & drop log rows or finding cards here, or click <strong>✨ Explain</strong></span>
          </div>
        ) : (
          <div className="context-chips-scroll">
            {/* Finding chips */}
            {attachedContext.findings?.map((f, idx) => (
              <div key={`f-${f.id || idx}`} className="context-chip chip-finding">
                <ShieldAlert size={12} color="var(--accent-rose)" />
                <span className="chip-text" title={f.title}>Finding: {f.title}</span>
                <button
                  type="button"
                  className="chip-remove"
                  onClick={() => onRemoveFinding?.(f.id || idx)}
                  aria-label="Remove finding context"
                >
                  <X size={11} />
                </button>
              </div>
            ))}

            {/* Event chips */}
            {attachedContext.rawEvents?.map((e, idx) => (
              <div key={`e-${e.id || idx}`} className="context-chip chip-event">
                <FileText size={12} color="var(--accent-cyan)" />
                <span className="chip-text" title={e.message}>
                  {e.event_id ? `Event #${e.event_id}` : e.source || 'Log'}: {e.message?.substring(0, 24)}...
                </span>
                <button
                  type="button"
                  className="chip-remove"
                  onClick={() => onRemoveEvent?.(e.id || idx)}
                  aria-label="Remove event context"
                >
                  <X size={11} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Messages Thread */}
      <div className="explainer-thread">
        {messages.length === 0 ? (
          <div className="explainer-empty-state">
            <div className="empty-sparkle-circle">
              <Sparkles size={28} color="var(--accent-cyan)" />
            </div>
            <h4>Ask anything about your logs</h4>
            <p>
              I translate complex Windows event IDs, Linux authentication failures, and system alerts
              into plain English with approved organizational SOP next steps.
            </p>
            <div className="offline-ready-indicator">
              <span className="dot-online" />
              <span>Offline knowledge base ready · FAISS SOP retrieval active</span>
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`explainer-bubble-row ${msg.role === 'user' ? 'row-user' : 'row-assistant'}`}
            >
              <div className="bubble-avatar">
                {msg.role === 'user' ? <User size={14} /> : <Bot size={15} />}
              </div>

              <div className="bubble-content-wrap">
                <div className="bubble-meta">
                  <span className="bubble-author">
                    {msg.role === 'user' ? 'Analyst' : 'Log Explainer'}
                  </span>
                  <span className="bubble-time">
                    {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>

                <div className={`bubble-card ${msg.isError ? 'bubble-card-error' : ''}`}>
                  {/* Assistant Severity Header Pill */}
                  {msg.role === 'assistant' && msg.severity_summary && (
                    <div className="explainer-severity-strip">
                      <div className="sev-strip-left">
                        <span className="sev-strip-label">Calculated Severity:</span>
                        <SeverityBadge
                          severity={msg.severity_summary.severity}
                          score={msg.severity_summary.score}
                          reasons={msg.severity_summary.reasons}
                          showScore={true}
                        />
                      </div>
                      <span className="sev-strip-score">Score: {msg.severity_summary.score}/100</span>
                    </div>
                  )}

                  {/* Body Text / Markdown */}
                  <div className="bubble-markdown-body">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {msg.content}
                    </ReactMarkdown>
                  </div>

                  {/* SOP Citations */}
                  {msg.role === 'assistant' && msg.citations && msg.citations.length > 0 && (
                    <div className="explainer-citations-box">
                      <div className="cit-box-title">
                        <FileText size={13} color="var(--accent-cyan)" />
                        <span>Referenced SOP Procedures ({msg.citations.length})</span>
                      </div>
                      <div className="cit-cards-grid">
                        {msg.citations.map((c, i) => (
                          <div key={i} className="cit-card">
                            <div className="cit-card-header">
                              <span className="cit-sop-badge">{c.sop_id}</span>
                              <span className="cit-sec-badge">§{c.section}</span>
                              <span className="cit-sim">Match: {(c.similarity_score * 100).toFixed(0)}%</span>
                            </div>
                            <p className="cit-text">{c.excerpt}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Assistant Actions: Create Ticket & Ask in Incident Workspace */}
                  {msg.role === 'assistant' && !msg.isError && (
                    <div className="explainer-msg-actions">
                      <button
                        type="button"
                        className="btn-msg-action"
                        onClick={() => handleCreateTicketFromMsg(msg)}
                        disabled={isCreatingTicket}
                        title="Create an official incident ticket from this explanation"
                      >
                        <Ticket size={13} />
                        <span>Create ticket</span>
                      </button>

                      <button
                        type="button"
                        className="btn-msg-action btn-msg-action-primary"
                        onClick={() => handleHandoffToWorkspace(msg)}
                        title="Send this analysis to the main Incident Workspace chat"
                      >
                        <ExternalLink size={13} />
                        <span>Ask in Incident Workspace</span>
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        )}

        {/* Typing indicator */}
        {isSending && (
          <div className="explainer-bubble-row row-assistant">
            <div className="bubble-avatar">
              <Bot size={15} />
            </div>
            <div className="bubble-content-wrap">
              <div className="bubble-card bubble-typing-card">
                <span className="typing-indicator">
                  <i />
                  <i />
                  <i />
                </span>
                <span className="typing-text">Analyzing telemetry and cross-referencing SOPs…</span>
              </div>
            </div>
          </div>
        )}

        <div ref={endRef} />
      </div>

      {/* Suggested Questions Pills */}
      {suggestedQuestions.length > 0 && !isSending && (
        <div className="suggested-questions-tray">
          <div className="suggested-title">
            <HelpCircle size={12} />
            <span>Suggested Questions:</span>
          </div>
          <div className="suggested-chips-scroll">
            {suggestedQuestions.map((q, idx) => (
              <button
                key={idx}
                type="button"
                className="btn-suggested-chip"
                onClick={() => handleSendMessage(q)}
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Chat Composer */}
      <div className="explainer-composer-wrap">
        <div className="composer-inner">
          <textarea
            ref={inputRef}
            className="composer-textarea"
            rows={1}
            placeholder={
              totalAttached > 0
                ? `Ask about the ${totalAttached} attached items or type a question…`
                : 'Ask about this log, threat severity, or SOP procedure…'
            }
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isSending}
          />
          <button
            type="button"
            className="btn-composer-send"
            disabled={!input.trim() || isSending}
            onClick={() => handleSendMessage()}
            aria-label="Send message"
          >
            <Send size={15} />
          </button>
        </div>
        <div className="composer-footer-hints">
          <span>Press <strong>Enter</strong> to send · <strong>Shift + Enter</strong> for newline</span>
          <span className="mode-indicator">Mode: {detailLevel === 'simple' ? 'Simple (ELI5)' : 'Technical'}</span>
        </div>
      </div>
    </aside>
  );
}
