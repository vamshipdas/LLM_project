import React, { useState } from 'react';
import { Activity, UploadCloud, Terminal, Shield } from 'lucide-react';
import RealTimeLogs from './RealTimeLogs';
import UploadLogs from './UploadLogs';

export default function LogAnalysis({ onAskCyberLLM, onSelectAlert, focusedOrigin, showToast }) {
  const [activeTab, setActiveTab] = useState('realtime'); // 'realtime' | 'upload'

  return (
    <div className="log-analysis-shell">
      {/* Module Title & Mode Switcher Bar */}
      <div className="log-analysis-top-nav">
        <div className="module-title-wrap">
          <div className="module-icon-badge">
            <Terminal size={20} color="var(--accent-cyan)" />
          </div>
          <div>
            <h2 className="module-title">Log Analysis & Threat Correlation</h2>
            <p className="module-subtitle">
              Live host telemetry ingestion and forensic file analysis grounded in organizational SOPs
            </p>
          </div>
        </div>

        {/* TWO PROMINENT MODE BUTTONS */}
        <div className="mode-toggle-group">
          <button
            type="button"
            className={`btn-mode-toggle ${activeTab === 'realtime' ? 'active-mode' : ''}`}
            onClick={() => setActiveTab('realtime')}
          >
            <Activity size={18} />
            <div className="btn-mode-copy">
              <span className="mode-title">Real-Time Logs</span>
              <span className="mode-desc">Live OS Telemetry</span>
            </div>
          </button>

          <button
            type="button"
            className={`btn-mode-toggle ${activeTab === 'upload' ? 'active-mode' : ''}`}
            onClick={() => setActiveTab('upload')}
          >
            <UploadCloud size={18} />
            <div className="btn-mode-copy">
              <span className="mode-title">Upload Logs</span>
              <span className="mode-desc">EVTX, Syslog, JSON, CSV</span>
            </div>
          </button>
        </div>
      </div>

      {/* Main View Area */}
      <div className="log-analysis-main-area">
        {activeTab === 'realtime' ? (
          <RealTimeLogs
            onAskCyberLLM={onAskCyberLLM}
            onSelectAlert={onSelectAlert}
            focusedOrigin={focusedOrigin}
            showToast={showToast}
          />
        ) : (
          <UploadLogs
            onAskCyberLLM={onAskCyberLLM}
            onSelectAlert={onSelectAlert}
            focusedOrigin={focusedOrigin}
            showToast={showToast}
          />
        )}
      </div>
    </div>
  );
}

