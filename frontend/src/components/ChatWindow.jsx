import React, { useEffect, useRef, useState } from 'react';
import { ArrowUp, Bot, ShieldAlert, User } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { getChatMessages, streamChatMessage } from '../api';

export default function ChatWindow({ sessionId, input, onInputChange, onMessageSent }) {
  const [messages, setMessages] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const endRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    getChatMessages(sessionId)
      .then((savedMessages) => {
        if (!cancelled) setMessages(savedMessages);
      })
      .catch((err) => {
        if (!cancelled) console.error('Failed to load saved chat:', err);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => { cancelled = true; };
  }, [sessionId]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: isSending ? 'auto' : 'smooth' });
  }, [messages, isSending]);

  useEffect(() => {
    const textarea = inputRef.current;
    if (!textarea) return;
    textarea.style.height = 'auto';
    textarea.style.height = `${Math.min(textarea.scrollHeight, 180)}px`;
  }, [input]);

  const handleTicketDrop = (event) => {
    const prompt = event.dataTransfer.getData('application/x-soc-ticket');
    if (!prompt) return;
    event.preventDefault();
    onInputChange(prompt);
    inputRef.current?.focus();
  };

  const handleSend = async (event) => {
    event.preventDefault();
    if (!input.trim() || isSending) return;

    const userText = input.trim();
    const now = Date.now();
    const assistantId = `assistant-${now}`;
    onInputChange('');
    setIsSending(true);
    setMessages((current) => [
      ...current,
      { id: `user-${now}`, role: 'user', content: userText, created_at: new Date().toISOString() },
      { id: assistantId, role: 'assistant', content: '', created_at: new Date().toISOString(), streaming: true },
    ]);

    try {
      const response = await streamChatMessage(sessionId, userText, (streamEvent) => {
        setMessages((current) => current.map((message) => {
          if (message.id !== assistantId) return message;
          if (streamEvent.type === 'delta') {
            return { ...message, content: message.content + streamEvent.content };
          }
          if (streamEvent.type === 'sources') {
            return { ...message, sources: streamEvent.sources };
          }
          if (streamEvent.type === 'done') {
            return { ...message, streaming: false };
          }
          return message;
        }));
      });
      onMessageSent?.(response);
    } catch (err) {
      setMessages((current) => current.map((message) => (
        message.id === assistantId
          ? { ...message, streaming: false, content: `Sorry, I could not get a response: ${err.message}` }
          : message
      )));
    } finally {
      setIsSending(false);
      inputRef.current?.focus();
    }
  };

  const handleComposerKeyDown = (event) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      event.currentTarget.form?.requestSubmit();
    }
  };

  return (
    <section
      className="chat-panel"
      onDragOver={(event) => event.preventDefault()}
      onDrop={handleTicketDrop}
    >
      <header className="chat-header">
        <span className="chat-header__icon"><ShieldAlert size={18} /></span>
        <div>
          <strong>SOC Agent</strong>
          <span><i className="status-dot" /> Online · SOP tools available</span>
        </div>
      </header>

      <div className="chat-thread" aria-live="polite">
        {isLoading && <div className="chat-empty"><p>Loading saved conversation…</p></div>}
        {!isLoading && messages.length === 0 && (
          <div className="chat-empty">
            <div className="chat-empty__icon"><ShieldAlert size={28} /></div>
            <h2>How can I help with this incident?</h2>
            <p>Ask a question, investigate an alert, or drag a ticket into the conversation.</p>
            <div className="prompt-examples">
              <span>Contain a ransomware host</span>
              <span>Investigate suspicious sign-in</span>
              <span>Respond to reported phishing</span>
            </div>
          </div>
        )}

        {messages.map((message) => (
          <article key={message.id} className={`message-row message-row--${message.role}`}>
            <div className="message-avatar" aria-hidden="true">
              {message.role === 'user' ? <User size={16} /> : <Bot size={17} />}
            </div>
            <div className="message-body">
              <div className="message-author">{message.role === 'user' ? 'You' : 'SOC Agent'}</div>
              <div className="message-bubble">
                {message.role === 'assistant' ? (
                  message.content
                    ? <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                    : <span className="typing-indicator"><i /><i /><i /></span>
                ) : message.content}
                {message.streaming && message.content && <span className="streaming-cursor" />}
              </div>

              {message.role === 'assistant' && message.sources?.length > 0 && (
                <details className="message-sources">
                  <summary>{message.sources.length} SOP source{message.sources.length === 1 ? '' : 's'}</summary>
                  {message.sources.map((source, index) => (
                    <div key={`${source.sop_id}-${source.section}-${index}`}>
                      <strong>{source.sop_id} §{source.section}</strong>
                      <p>{source.excerpt}</p>
                    </div>
                  ))}
                </details>
              )}

              <time>{new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time>
            </div>
          </article>
        ))}
        <div ref={endRef} />
      </div>

      <div className="chat-composer-wrap">
        <form className="chat-composer" onSubmit={handleSend}>
          <textarea
            ref={inputRef}
            id="agent-input"
            name="message"
            aria-label="Message SOC Agent"
            rows={1}
            placeholder="Message SOC Agent or drop a ticket…"
            value={input}
            onChange={(event) => onInputChange(event.target.value)}
            onKeyDown={handleComposerKeyDown}
            disabled={isSending}
          />
          <button type="submit" disabled={isSending || !input.trim()} aria-label="Send message">
            <ArrowUp size={18} />
          </button>
        </form>
        <p>Enter to send · Shift + Enter for a new line</p>
      </div>
    </section>
  );
}
