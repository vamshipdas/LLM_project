import React, { useState, useEffect } from 'react';
import { Mail, RefreshCw, Check, AlertCircle } from 'lucide-react';
import { getAlertNotificationStatus, resendAlertNotification } from '../api';

export default function AlertEmailIndicator({ alertId, severity, showToast }) {
  const [status, setStatus] = useState(null); // 'sent' | 'failed' | 'skipped' | 'none'
  const [isResending, setIsResending] = useState(false);

  const sev = String(severity || '').toLowerCase();
  const isEligible = sev === 'critical' || sev === 'high';

  useEffect(() => {
    if (!isEligible || !alertId) return;

    let isCancelled = false;
    getAlertNotificationStatus(alertId)
      .then((data) => {
        if (!isCancelled && data) {
          setStatus(data.status || 'none');
        }
      })
      .catch(() => {
        if (!isCancelled) setStatus('none');
      });

    return () => {
      isCancelled = true;
    };
  }, [alertId, isEligible]);

  if (!isEligible) return null;

  const handleResend = async (e) => {
    e.stopPropagation();
    e.preventDefault();
    setIsResending(true);
    try {
      const res = await resendAlertNotification(alertId);
      if (res.status === 'sent') {
        setStatus('sent');
        showToast && showToast('success', `Alert email dispatched to ${res.recipients.join(', ')}.`);
      } else {
        setStatus('failed');
        showToast && showToast('error', `Email dispatch failed: ${res.error || res.reason || 'Unknown error'}`);
      }
    } catch (err) {
      setStatus('failed');
      showToast && showToast('error', `Resend failed: ${err.message}`);
    } finally {
      setIsResending(false);
    }
  };

  if (status === 'sent') {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          fontSize: '0.68rem',
          fontWeight: 600,
          color: '#4ade80',
          background: 'rgba(34, 197, 94, 0.12)',
          border: '1px solid rgba(34, 197, 94, 0.3)',
          padding: '2px 6px',
          borderRadius: '4px',
        }}
        title="Email notification sent to analyst"
      >
        <Mail size={11} />
        Email sent
      </span>
    );
  }

  if (status === 'failed' || status === 'none' || status === 'skipped') {
    const isFailed = status === 'failed';
    const label = isFailed ? 'Email failed' : (status === 'skipped' ? 'Email grouped' : 'Email pending');
    const color = isFailed ? '#f87171' : '#facc15';
    const bg = isFailed ? 'rgba(239, 68, 68, 0.12)' : 'rgba(234, 179, 8, 0.12)';
    const border = isFailed ? 'rgba(239, 68, 68, 0.3)' : 'rgba(234, 179, 8, 0.3)';

    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '0.68rem',
          fontWeight: 600,
          color: color,
          background: bg,
          border: `1px solid ${border}`,
          padding: '2px 6px',
          borderRadius: '4px',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
          <Mail size={11} />
          {label}
        </span>
        <button
          type="button"
          onClick={handleResend}
          disabled={isResending}
          style={{
            background: 'rgba(255, 255, 255, 0.1)',
            border: 'none',
            color: '#fff',
            borderRadius: '3px',
            padding: '1px 5px',
            cursor: isResending ? 'not-allowed' : 'pointer',
            fontSize: '0.65rem',
            fontWeight: 700,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '2px',
          }}
          title="Resend notification email"
        >
          {isResending ? (
            <RefreshCw size={9} className="spin-animate" />
          ) : (
            'Resend'
          )}
        </button>
      </span>
    );
  }

  return null;
}

