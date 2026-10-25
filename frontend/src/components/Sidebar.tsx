import React from 'react';
import {
  ShieldAlert,
  Gauge,
  Crosshair,
  ListOrdered,
  FileSearch,
  Vault,
  BarChart3,
  Server,
  Activity,
  Terminal,
  Clock
} from 'lucide-react';
import { CollectorStatus, InvestigationCase } from '../types';

interface SidebarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  collectorStatus: CollectorStatus | null;
  activeCase: InvestigationCase | null;
  lastEventTime: string | null;
  totalEventsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  setCurrentTab,
  collectorStatus,
  activeCase,
  lastEventTime,
  totalEventsCount
}) => {
  const isVmOnline = collectorStatus && collectorStatus.connected_collectors_count > 0;

  const navItems = [
    { id: 'command-center', label: 'Command Center', icon: Activity, badge: null },
    { id: 'readiness', label: 'Forensic Readiness', icon: Gauge, badge: null },
    { id: 'detection', label: 'Threat & ATT&CK Intel', icon: Crosshair, badge: null },
    { id: 'prioritization', label: 'Evidence Prioritization', icon: ListOrdered, badge: 'Core' },
    { id: 'investigation', label: 'Incident Investigation', icon: FileSearch, badge: activeCase ? 'Active' : null },
    { id: 'vault', label: 'Evidence Vault', icon: Vault, badge: 'SHA-256' },
    { id: 'evaluation', label: 'Research Evaluation', icon: BarChart3, badge: 'Thesis' },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div style={{ padding: '20px 18px', borderBottom: '1px solid var(--border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '2px',
            backgroundColor: 'var(--teal-dim)',
            border: '1px solid var(--teal-dim-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--teal-glow)'
          }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, letterSpacing: '0.08em', color: '#FFF' }}>
              THREXIS
            </div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Forensic Readiness OS
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <div style={{ flex: 1, padding: '16px 10px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <div style={{ padding: '4px 10px 8px', fontSize: '10.5px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Workstation Sections
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '9px 12px',
                borderRadius: '2px',
                border: 'none',
                backgroundColor: isActive ? 'var(--teal-dim)' : 'transparent',
                color: isActive ? 'var(--teal-glow)' : 'var(--text-secondary)',
                fontWeight: isActive ? 600 : 400,
                fontSize: '12.5px',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                textAlign: 'left'
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'var(--bg-surface-hover)';
                  e.currentTarget.style.color = 'var(--text-primary)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = 'var(--text-secondary)';
                }
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Icon size={16} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`badge ${isActive ? 'badge-teal' : 'badge-neutral'}`} style={{ fontSize: '9.5px', padding: '1px 5px' }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Telemetry & VM Status Drawer */}
      <div style={{
        padding: '14px 16px',
        backgroundColor: 'var(--bg-surface)',
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        flexDirection: 'column',
        gap: '10px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '7px', fontSize: '11px', color: 'var(--text-secondary)' }}>
            <Server size={13} />
            <span>Ubuntu VirtualBox:</span>
          </div>
          <span className={`badge ${isVmOnline ? 'badge-teal' : 'badge-neutral'}`}>
            <span className={`pulse-indicator ${isVmOnline ? '' : 'pulse-red'}`} style={{ width: '6px', height: '6px' }}></span>
            {isVmOnline ? 'ONLINE' : 'STANDBY'}
          </span>
        </div>

        {activeCase && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px' }}>
            <span style={{ color: 'var(--text-muted)' }}>Investigation:</span>
            <span className="mono badge badge-amber" style={{ fontSize: '10px' }}>
              {activeCase.case_id}
            </span>
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px' }}>
          <span style={{ color: 'var(--text-muted)' }}>Total Telemetry:</span>
          <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
            {totalEventsCount} events
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '10.5px', color: 'var(--text-muted)' }}>
          <Clock size={11} />
          <span>Last sync: {lastEventTime ? new Date(lastEventTime).toLocaleTimeString() : 'Awaiting stream'}</span>
        </div>
      </div>
    </aside>
  );
};
