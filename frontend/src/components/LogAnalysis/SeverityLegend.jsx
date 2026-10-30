import React, { useState, useEffect } from 'react';
import { HelpCircle, X, ShieldAlert, AlertCircle, AlertTriangle, ShieldCheck } from 'lucide-react';
import { getSeverityRules } from '../../api';

export default function SeverityLegend() {
  const [isOpen, setIsOpen] = useState(false);
  const [rulesData, setRulesData] = useState(null);

  useEffect(() => {
    if (isOpen && !rulesData) {
      getSeverityRules()
        .then((data) => setRulesData(data))
        .catch(() => {});
    }
  }, [isOpen, rulesData]);

  return (
    <div className="severity-legend-container">
      <button
        type="button"
        className="btn btn-legend-trigger"
        onClick={() => setIsOpen(!isOpen)}
        title="View Severity Classification Guide"
      >
        <HelpCircle size={14} />
        <span>Severity Legend</span>
      </button>

      {isOpen && (
        <div className="severity-legend-popover cyber-card">
          <div className="legend-popover-header">
            <h4>Security Severity Classification</h4>
            <button
              type="button"
              className="btn-close-popover"
              onClick={() => setIsOpen(false)}
            >
              <X size={14} />
            </button>
          </div>

          <div className="legend-tiers">
            <div className="legend-tier tier-critical">
              <div className="tier-badge">
                <ShieldAlert size={14} />
                <span>CRITICAL (Score: 90-100)</span>
              </div>
              <p>Confirmed compromise, audit log deletion (anti-forensics), ransomware/malware execution, or disabled endpoint defenses.</p>
            </div>

            <div className="legend-tier tier-high">
              <div className="tier-badge">
                <AlertCircle size={14} />
                <span>HIGH (Score: 70-89)</span>
              </div>
              <p>Brute-force authentication bursts (5+ attempts), new persistence services/scheduled tasks, admin privilege escalation, or suspicious PowerShell execution.</p>
            </div>

            <div className="legend-tier tier-medium">
              <div className="tier-badge">
                <AlertTriangle size={14} />
                <span>MEDIUM (Score: 40-69)</span>
              </div>
              <p>Warnings, isolated logon failures, connection refused bursts, or network port scan probes.</p>
            </div>

            <div className="legend-tier tier-low">
              <div className="tier-badge">
                <ShieldCheck size={14} />
                <span>LOW (Score: 0-39)</span>
              </div>
              <p>Routine operating system activity, normal service state transitions, DHCP leases, informational notices.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
