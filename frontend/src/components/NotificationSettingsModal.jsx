import React, { useState, useEffect } from 'react';
import {
  Bell,
  Mail,
  CheckCircle2,
  AlertTriangle,
  X,
  Send,
  RefreshCw,
  Clock,
  Shield,
  ExternalLink,
  Info
} from 'lucide-react';
import {
  getNotificationSettings,
  updateNotificationSettings,
  sendTestNotification,
  getNotificationLogs
} from '../api';

export default function NotificationSettingsModal({ isOpen, onClose, user, showToast }) {
  const [settings, setSettings] = useState({
    enabled: true,
    min_severity: 'high',
    recipients: ['vamshipdas@gmail.com'],
    cooldown_seconds: 300,
    smtp_configured: false,
    smtp_host: 'smtp.gmail.com',
    smtp_port: 587,
    sender_email: 'vamshipdas@gmail.com',
  });
  const [recipientsInput, setRecipientsInput] = useState('vamshipdas@gmail.com');
  const [senderEmailInput, setSenderEmailInput] = useState('vamshipdas@gmail.com');
  const [smtpPasswordInput, setSmtpPasswordInput] = useState('');
  const [logs, setLogs] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isSendingTest, setIsSendingTest] = useState(false);
  const [activeTab, setActiveTab] = useState('config'); // 'config' | 'logs'

  const isAdmin = true; // Enabled for both Analyst and Admin roles

  useEffect(() => {
    if (!isOpen) return;

    loadSettingsAndLogs();
  }, [isOpen]);

  const loadSettingsAndLogs = async () => {
    setIsLoading(true);
    try {
      const [fetchedSettings, fetchedLogs] = await Promise.all([
        getNotificationSettings().catch((err) => {
          console.warn('Failed to load notification settings:', err);
          return null;
        }),
        getNotificationLogs(50).catch((err) => {
          console.warn('Failed to load notification logs:', err);
          return [];
        }),
      ]);

      if (fetchedSettings) {
        setSettings(fetchedSettings);
        setRecipientsInput((fetchedSettings.recipients || []).join(', '));
        if (fetchedSettings.sender_email) {
          setSenderEmailInput(fetchedSettings.sender_email);
        }
      }
      if (fetchedLogs) {
        setLogs(fetchedLogs);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSaveSettings = async (e) => {
    e?.preventDefault();
    if (!isAdmin) {
      showToast && showToast('error', 'Admin role required to modify settings.');
      return;
    }

    setIsSaving(true);
    try {
      const parsedRecipients = recipientsInput
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean);

      const payload = {
        enabled: settings.enabled,
        min_severity: settings.min_severity,
        recipients: parsedRecipients,
        cooldown_seconds: parseInt(settings.cooldown_seconds, 10) || 300,
      };
      if (senderEmailInput.trim()) {
        payload.sender_email = senderEmailInput.trim();
      }
      if (smtpPasswordInput.trim()) {
        payload.smtp_password = smtpPasswordInput.trim();
      }

      const updated = await updateNotificationSettings(payload);
      if (smtpPasswordInput.trim()) {
        setSmtpPasswordInput('');
      }

      setSettings(updated);
      setRecipientsInput((updated.recipients || []).join(', '));
      showToast && showToast('success', 'Notification settings saved successfully!');
    } catch (err) {
      showToast && showToast('error', `Failed to save settings: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleSendTestEmail = async () => {
    setIsSendingTest(true);
    try {
      const res = await sendTestNotification();
      if (res.status === 'sent') {
        showToast && showToast('success', `Test email sent to ${res.recipients.join(', ')}! Check your inbox.`);
      } else {
        showToast && showToast('error', `Test email failed: ${res.message}`);
      }
      // Refresh logs
      const updatedLogs = await getNotificationLogs(50);
      setLogs(updatedLogs);
    } catch (err) {
      showToast && showToast('error', `Failed to send test email: ${err.message}`);
    } finally {
      setIsSendingTest(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
      padding: '20px'
    }}>
      <div
        className="notif-modal-container"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#0d1322', border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '12px', width: '100%', maxWidth: '780px', maxHeight: '88vh',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6)'
        }}
      >
        {/* Header */}
        <div style={{
          padding: '16px 24px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          background: 'rgba(15, 23, 42, 0.7)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444',
              borderRadius: '8px', padding: '6px', display: 'flex'
            }}>
              <Bell size={18} color="#ef4444" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#f8fafc', fontWeight: 700 }}>
                Critical Alert Email Notifications
              </h3>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Automated SMTP dispatch to analysts on critical security events
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={onClose}
              style={{
                background: 'transparent', border: 'none', color: 'var(--text-muted)',
                cursor: 'pointer', padding: '4px', display: 'flex', borderRadius: '4px'
              }}
              title="Close"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* Tab switcher */}
        <div style={{
          display: 'flex', borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          padding: '0 24px', background: 'rgba(15, 23, 42, 0.3)'
        }}>
          <button
            onClick={() => setActiveTab('config')}
            style={{
              padding: '12px 16px', background: 'transparent', border: 'none',
              borderBottom: activeTab === 'config' ? '2px solid #38bdf8' : '2px solid transparent',
              color: activeTab === 'config' ? '#38bdf8' : 'var(--text-muted)',
              fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer', display: 'flex',
              alignItems: 'center', gap: '8px'
            }}
          >
            <Shield size={15} />
            Configuration &amp; Controls
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            style={{
              padding: '12px 16px', background: 'transparent', border: 'none',
              borderBottom: activeTab === 'logs' ? '2px solid #38bdf8' : '2px solid transparent',
              color: activeTab === 'logs' ? '#38bdf8' : 'var(--text-muted)',
              fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer', display: 'flex',
              alignItems: 'center', gap: '8px'
            }}
          >
            <Clock size={15} />
            Recent Send Audit Log ({logs.length})
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
          {activeTab === 'config' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* SMTP Status banner */}
              <div style={{
                background: settings.smtp_configured ? 'rgba(34, 197, 94, 0.1)' : 'rgba(234, 179, 8, 0.1)',
                border: `1px solid ${settings.smtp_configured ? 'rgba(34, 197, 94, 0.3)' : 'rgba(234, 179, 8, 0.3)'}`,
                borderRadius: '8px', padding: '12px 16px', display: 'flex', alignItems: 'center',
                justifyContent: 'space-between', gap: '12px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {settings.smtp_configured ? (
                    <CheckCircle2 size={18} color="#22c55e" />
                  ) : (
                    <AlertTriangle size={18} color="#eab308" />
                  )}
                  <div style={{ fontSize: '0.82rem' }}>
                    <strong style={{ color: settings.smtp_configured ? '#86efac' : '#fde047' }}>
                      {settings.smtp_configured ? 'SMTP Configured' : 'SMTP Credentials Needed'}
                    </strong>
                    <div style={{ color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                      Host: <code>{settings.smtp_host}:{settings.smtp_port}</code> (STARTTLS) &bull; Sender: <code>{settings.sender_email}</code>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleSendTestEmail}
                  disabled={isSendingTest}
                  style={{
                    background: '#0284c7', border: 'none', color: '#fff',
                    padding: '8px 14px', borderRadius: '6px', fontSize: '0.8rem',
                    fontWeight: 600, cursor: isSendingTest ? 'not-allowed' : 'pointer',
                    display: 'flex', alignItems: 'center', gap: '6px',
                    opacity: isSendingTest ? 0.7 : 1
                  }}
                >
                  <Send size={14} />
                  {isSendingTest ? 'Sending Test…' : 'Send Test Email'}
                </button>
              </div>

              {/* Form Controls */}
              <form onSubmit={handleSaveSettings} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {/* On/Off toggle */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '14px 16px', background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: '8px'
                }}>
                  <div>
                    <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#f1f5f9' }}>
                      Enable Critical Alert Emails
                    </div>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                      Automatically notify on critical tickets, findings, and high-confidence log anomalies
                    </div>
                  </div>
                  <label className="switch" style={{ position: 'relative', display: 'inline-block', width: '44px', height: '24px' }}>
                    <input
                      type="checkbox"
                      checked={settings.enabled}
                      disabled={!isAdmin}
                      onChange={(e) => setSettings((s) => ({ ...s, enabled: e.target.checked }))}
                      style={{ opacity: 0, width: 0, height: 0 }}
                    />
                    <span style={{
                      position: 'absolute', cursor: isAdmin ? 'pointer' : 'not-allowed', top: 0, left: 0, right: 0, bottom: 0,
                      backgroundColor: settings.enabled ? '#0284c7' : '#334155', borderRadius: '24px',
                      transition: '0.3s'
                    }}>
                      <span style={{
                        position: 'absolute', content: '""', height: '18px', width: '18px', left: settings.enabled ? '23px' : '3px',
                        bottom: '3px', backgroundColor: '#fff', borderRadius: '50%', transition: '0.3s'
                      }} />
                    </span>
                  </label>
                </div>

                {/* Recipient list */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                    Analyst Recipient Addresses (comma-separated):
                  </label>
                  <input
                    type="text"
                    value={recipientsInput}
                    disabled={!isAdmin}
                    onChange={(e) => setRecipientsInput(e.target.value)}
                    placeholder="e.g. vamshipdas@gmail.com, analyst2@org.com"
                    style={{
                      width: '100%', padding: '10px 12px', background: '#090d16',
                      border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '6px',
                      color: '#f8fafc', fontSize: '0.85rem'
                    }}
                  />
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    Only verified emails on this allowlist will receive alerts. Defaults to <code>vamshipdas@gmail.com</code>.
                  </div>
                </div>

                {/* Sender Gmail Address field */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                    Sender Gmail Account Address:
                  </label>
                  <input
                    type="email"
                    value={senderEmailInput}
                    onChange={(e) => setSenderEmailInput(e.target.value)}
                    placeholder="e.g. vamshipdas@gmail.com"
                    style={{
                      width: '100%', padding: '10px 12px', background: '#090d16',
                      border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '6px',
                      color: '#f8fafc', fontSize: '0.85rem'
                    }}
                  />
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    The Gmail account from which alert emails will be dispatched using STARTTLS.
                  </div>
                </div>

                {/* SMTP App Password field */}
                <div>
                  <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                    Gmail App Password (16-characters, for {senderEmailInput || 'your account'}):
                  </label>
                  <input
                    type="password"
                    value={smtpPasswordInput}
                    onChange={(e) => setSmtpPasswordInput(e.target.value)}
                    placeholder={settings.smtp_configured ? "•••••••••••••••• (Configured — enter new to replace)" : "Enter 16-character App Password (e.g. abcd efgh ijkl mnop)"}
                    style={{
                      width: '100%', padding: '10px 12px', background: '#090d16',
                      border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '6px',
                      color: '#f8fafc', fontSize: '0.85rem'
                    }}
                  />
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    Generate at <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>myaccount.google.com/apppasswords</a>. Spaces are automatically stripped.
                  </div>
                </div>

                {/* Minimum severity & Cooldown row */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                      Minimum Alert Severity:
                    </label>
                    <select
                      value={settings.min_severity}
                      disabled={!isAdmin}
                      onChange={(e) => setSettings((s) => ({ ...s, min_severity: e.target.value }))}
                      style={{
                        width: '100%', padding: '9px 12px', background: '#090d16',
                        border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '6px',
                        color: '#f8fafc', fontSize: '0.85rem'
                      }}
                    >
                      <option value="high">High and Critical (Active)</option>
                      <option value="critical">Critical only</option>
                      <option value="medium">Medium, High and Critical</option>
                      <option value="low">All Alerts (Low to Critical)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '6px' }}>
                      Grouping / Cooldown Window (seconds):
                    </label>
                    <input
                      type="number"
                      min="10"
                      max="3600"
                      value={settings.cooldown_seconds}
                      disabled={!isAdmin}
                      onChange={(e) => setSettings((s) => ({ ...s, cooldown_seconds: e.target.value }))}
                      style={{
                        width: '100%', padding: '9px 12px', background: '#090d16',
                        border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '6px',
                        color: '#f8fafc', fontSize: '0.85rem'
                      }}
                    />
                  </div>
                </div>

                {!isAdmin && (
                  <div style={{
                    fontSize: '0.76rem', color: '#eab308', display: 'flex', alignItems: 'center',
                    gap: '6px', background: 'rgba(234, 179, 8, 0.08)', padding: '8px 12px', borderRadius: '6px'
                  }}>
                    <Info size={14} />
                    You are signed in as an Analyst. Administrator privileges are required to edit these settings.
                  </div>
                )}

                {isAdmin && (
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
                    <button
                      type="submit"
                      disabled={isSaving}
                      style={{
                        background: '#0284c7', border: 'none', color: '#fff',
                        padding: '10px 20px', borderRadius: '6px', fontWeight: 700,
                        fontSize: '0.85rem', cursor: isSaving ? 'not-allowed' : 'pointer',
                        opacity: isSaving ? 0.7 : 1
                      }}
                    >
                      {isSaving ? 'Saving…' : 'Save Notification Settings'}
                    </button>
                  </div>
                )}
              </form>
            </div>
          ) : (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Audit record of recent notification dispatches
                </span>
                <button
                  type="button"
                  onClick={loadSettingsAndLogs}
                  style={{
                    background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.12)',
                    color: '#38bdf8', padding: '4px 10px', borderRadius: '6px', fontSize: '0.75rem',
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px'
                  }}
                >
                  <RefreshCw size={12} /> Refresh
                </button>
              </div>

              {logs.length === 0 ? (
                <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                  No notification logs recorded yet. Trigger a test email or critical alert to see history.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.78rem', textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '8px' }}>Time</th>
                        <th style={{ padding: '8px' }}>Alert ID</th>
                        <th style={{ padding: '8px' }}>Title</th>
                        <th style={{ padding: '8px' }}>Status</th>
                        <th style={{ padding: '8px' }}>Recipients</th>
                        <th style={{ padding: '8px' }}>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map((log) => {
                        let statusColor = '#22c55e';
                        let statusBg = 'rgba(34, 197, 94, 0.15)';
                        if (log.status === 'failed') {
                          statusColor = '#ef4444';
                          statusBg = 'rgba(239, 68, 68, 0.15)';
                        } else if (log.status === 'skipped') {
                          statusColor = '#eab308';
                          statusBg = 'rgba(234, 179, 8, 0.15)';
                        }

                        return (
                          <tr key={log.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                            <td style={{ padding: '8px', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                              {new Date(log.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                            </td>
                            <td style={{ padding: '8px', fontFamily: 'monospace', color: '#38bdf8' }}>
                              {log.alert_id}
                            </td>
                            <td style={{ padding: '8px', color: '#f1f5f9', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {log.alert_title}
                            </td>
                            <td style={{ padding: '8px' }}>
                              <span style={{
                                background: statusBg, color: statusColor, padding: '2px 8px',
                                borderRadius: '4px', fontWeight: 700, fontSize: '0.72rem', textTransform: 'uppercase'
                              }}>
                                {log.status}
                              </span>
                            </td>
                            <td style={{ padding: '8px', color: '#cbd5e1', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {log.recipients}
                            </td>
                            <td style={{ padding: '8px', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                              {log.error_message || (log.grouped_count > 1 ? `${log.grouped_count} grouped` : 'Delivered')}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

