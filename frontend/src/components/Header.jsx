import React from 'react';
import { LogOut, ShieldAlert, MessageSquare, Terminal, Bell } from 'lucide-react';

export default function Header({ user, onLogout, currentView = 'workspace', onViewChange, onOpenNotifications }) {

  return (
    <header className="app-header" style={{
      background: 'rgba(10, 15, 26, 0.92)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(56, 189, 248, 0.15)',
      padding: '10px 24px',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '20px',
    }}>
      {/* Brand logo & title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{
          background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(168, 85, 247, 0.25))',
          border: '1px solid rgba(56, 189, 248, 0.45)',
          padding: '7px',
          borderRadius: '9px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 14px rgba(56, 189, 248, 0.25)'
        }}>
          <ShieldAlert size={20} color="#38bdf8" />
        </div>
        <div className="brand-copy">
          <h1 style={{ fontSize: '1.05rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#f8fafc' }}>
            Sentinel Desk
          </h1>
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            CyberLLM • SOC Incident Response & Telemetry
          </p>
        </div>
      </div>

      {/* Center Navigation Tabs: Workspace vs Log Analysis */}
      <nav className="header-nav-tabs">
        <button
          type="button"
          className={`nav-tab-btn ${currentView === 'workspace' ? 'nav-tab-active' : ''}`}
          onClick={() => onViewChange && onViewChange('workspace')}
        >
          <MessageSquare size={16} />
          <span>Incident Workspace</span>
        </button>

        <button
          type="button"
          className={`nav-tab-btn ${currentView === 'logs' ? 'nav-tab-active' : ''}`}
          onClick={() => onViewChange && onViewChange('logs')}
        >
          <Terminal size={16} />
          <span>Log Analysis</span>
          <span className="nav-new-pill">NEW</span>
        </button>
      </nav>

      {/* User profile & signout */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <button
          className="header-notif-btn"
          type="button"
          onClick={onOpenNotifications}
          style={{
            background: 'rgba(56, 189, 248, 0.1)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            color: '#38bdf8',
            borderRadius: '8px',
            padding: '6px 12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '0.8rem',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          title="Alert Notifications & Settings"
        >
          <Bell size={14} />
          <span>Alerts &amp; SMTP</span>
        </button>

        <div className="user-role-badge">
          <span className="user-dot"></span>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#e2e8f0' }}>{user?.username}</span>
          <span style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', background: 'rgba(56, 189, 248, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
            {user?.role}
          </span>
        </div>

        <button
          className="header-signout"
          type="button"
          onClick={onLogout}
          aria-label={`Sign out ${user?.username || ''}`.trim()}
          title="Sign out"
        >
          <LogOut size={15} />
        </button>
      </div>
    </header>
  );
}
