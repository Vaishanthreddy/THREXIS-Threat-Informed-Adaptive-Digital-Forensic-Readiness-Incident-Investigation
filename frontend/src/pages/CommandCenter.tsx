import React, { useState } from 'react';
import {
  Gauge,
  Activity,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ArrowRight,
  ExternalLink,
  Layers,
  FileText
} from 'lucide-react';
import {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  CollectorStatus,
  InvestigationCase
} from '../types';

interface CommandCenterProps {
  readiness: ReadinessAssessment | null;
  events: SecurityEvent[];
  alerts: DetectionAlert[];
  collectorStatus: CollectorStatus | null;
  activeCase: InvestigationCase | null;
  onNavigate: (tab: string) => void;
}

export const CommandCenter: React.FC<CommandCenterProps> = ({
  readiness,
  events,
  alerts,
  collectorStatus,
  activeCase,
  onNavigate
}) => {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const isVmOnline = collectorStatus && collectorStatus.connected_collectors_count > 0;
  const highSeverityAlerts = alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');
  const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000);
  const eventsInLast5Min = events.filter(e => new Date(e.timestamp) >= fiveMinAgo).length;

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* Top Row: Readiness Instrument & Operational Telemetry Metrics */}
      <div className="grid-2">
        {/* A. Forensic Readiness Instrument */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Gauge size={16} style={{ color: 'var(--teal-glow)' }} />
              Forensic Readiness Instrument
            </span>
            {readiness && (
              <span className="badge badge-teal">
                {readiness.category}
              </span>
            )}
          </div>

          {readiness ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '14px', marginBottom: '12px' }}>
                <span className="mono" style={{ fontSize: '38px', fontWeight: 700, color: 'var(--teal-glow)' }}>
                  {readiness.score.toFixed(1)}%
                </span>
                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                  <div>Source Coverage: <b style={{ color: '#FFF' }}>{readiness.coverage_percentage}%</b> ({readiness.sources.length - readiness.gaps_count}/{readiness.sources.length} sources)</div>
                  <div>Evidence Gaps: <b style={{ color: readiness.gaps_count > 0 ? 'var(--amber-oxide)' : 'var(--teal-glow)' }}>{readiness.gaps_count} sources deficient</b></div>
                </div>
              </div>

              {/* Segmented Horizontal Readiness Instrument */}
              <div style={{ marginBottom: '14px' }}>
                <div style={{
                  height: '10px',
                  width: '100%',
                  backgroundColor: 'var(--border-subtle)',
                  borderRadius: '5px',
                  overflow: 'hidden',
                  display: 'flex',
                  gap: '2px'
                }}>
                  {readiness.sources.map((s, idx) => {
                    const factorColor = s.factor >= 0.85 ? 'var(--teal-core)' : (s.factor >= 0.5 ? '#EAB308' : '#475569');
                    return (
                      <div
                        key={idx}
                        title={`${s.source_name}: factor ${s.factor} (weight: ${s.weight})`}
                        style={{
                          flex: s.weight,
                          backgroundColor: factorColor,
                          transition: 'all 0.3s ease'
                        }}
                      />
                    );
                  })}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  <span>0% (Blindspot)</span>
                  <span className="mono">Σ(wᵢ × sᵢ) / Σ(wᵢ) = {readiness.weighted_sum.toFixed(2)} / {readiness.total_weight.toFixed(2)}</span>
                  <span>100% (Fully Validated)</span>
                </div>
              </div>

              <div style={{
                padding: '9px 12px',
                backgroundColor: 'var(--bg-surface-elevated)',
                borderRadius: '4px',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}>
                <span>Threat Context: <b style={{ color: 'var(--text-primary)' }}>{readiness.threat_context}</b></span>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: '11px', padding: '3px 8px' }}
                  onClick={() => onNavigate('readiness')}
                >
                  Inspect Scoring Engine <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ) : (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Readiness Not Assessed (Awaiting source status)
            </div>
          )}
        </div>

        {/* B. Live Security Monitoring Status */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Activity size={16} style={{ color: 'var(--teal-glow)' }} />
              Live Security Telemetry & Collector
            </span>
            <span className={`badge ${isVmOnline ? 'badge-teal' : 'badge-neutral'}`}>
              <span className={`pulse-indicator ${isVmOnline ? '' : 'pulse-red'}`} style={{ width: '6px', height: '6px' }}></span>
              VM {isVmOnline ? 'CONNECTED' : 'WAITING'}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '12px', marginBottom: '14px' }}>
            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px' }}>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Ingested Events</div>
              <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: '#FFF' }}>{events.length}</div>
              <div style={{ fontSize: '10.5px', color: 'var(--teal-glow)' }}>{eventsInLast5Min} received in last 5m</div>
            </div>

            <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px' }}>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Detections</div>
              <div className="mono" style={{ fontSize: '24px', fontWeight: 700, color: alerts.length > 0 ? 'var(--red-oxide-bright)' : '#FFF' }}>
                {alerts.length}
              </div>
              <div style={{ fontSize: '10.5px', color: highSeverityAlerts.length > 0 ? 'var(--red-oxide-bright)' : 'var(--text-muted)' }}>
                {highSeverityAlerts.length} high/critical severity
              </div>
            </div>
          </div>

          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Collector Host:</span>
              <span className="mono" style={{ color: '#FFF' }}>
                {collectorStatus?.collectors[0]?.hostname || 'ubuntu-vbox-lab-01'} ({collectorStatus?.collectors[0]?.ip_address || '192.168.56.101'})
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Agent Protocol:</span>
              <span className="mono">HTTP/1.1 Ingestion API (Key Authenticated, SHA-256 Deduplicated)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Active Incident & MITRE ATT&CK Intelligence */}
      <div className="grid-2">
        {/* Incident Overview Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <AlertTriangle size={16} style={{ color: alerts.length > 0 ? 'var(--red-oxide-bright)' : 'var(--teal-glow)' }} />
              Active Incident Response Case
            </span>
            {activeCase ? (
              <span className="badge badge-amber">{activeCase.case_id}</span>
            ) : (
              <span className="badge badge-neutral">NO ACTIVE INCIDENT</span>
            )}
          </div>

          {activeCase ? (
            <div>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#FFF', marginBottom: '6px' }}>
                {activeCase.title}
              </div>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginBottom: '12px', lineHeight: 1.5 }}>
                {activeCase.summary}
              </p>

              <div style={{
                padding: '10px 12px',
                backgroundColor: 'var(--bg-surface-elevated)',
                borderLeft: '3px solid var(--teal-core)',
                borderRadius: '0 4px 4px 0',
                marginBottom: '14px'
              }}>
                <div style={{ fontSize: '10px', color: 'var(--teal-glow)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '3px' }}>
                  Next Investigative Action:
                </div>
                <div style={{ fontSize: '11.5px', color: '#FFF' }}>
                  Execute Adaptive Prioritization to preserve SSH auth and session logs within collection budget, then record SHA-256 custody manifest in Evidence Vault.
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => onNavigate('investigation')}
                  style={{ fontSize: '11.5px' }}
                >
                  <FileText size={13} />
                  Open Case Investigation
                </button>
                <button
                  className="btn btn-secondary"
                  onClick={() => onNavigate('prioritization')}
                  style={{ fontSize: '11.5px' }}
                >
                  Run Evidence Prioritization <ArrowRight size={12} />
                </button>
              </div>
            </div>
          ) : (
            <div style={{ padding: '20px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
              <ShieldCheck size={32} style={{ margin: '0 auto 8px', color: 'var(--teal-core)' }} />
              <div>Target environment operating within baseline parameters.</div>
              <div style={{ fontSize: '11px', marginTop: '4px' }}>No active security alerts or brute-force anomalies detected.</div>
            </div>
          )}
        </div>

        {/* MITRE ATT&CK Context Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Layers size={16} style={{ color: 'var(--teal-glow)' }} />
              Threat Context (MITRE ATT&CK Enterprise)
            </span>
            <span className="badge badge-teal">T1110 Primary</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600, fontSize: '13px' }}>
                  T1110: Brute Force
                </span>
                <span className="badge badge-neutral">Credential Access</span>
              </div>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Adversaries attempt repeated access when credentials are unknown. Grounded mapping directly aligns with observed SSH authentication failure sequences.
              </p>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
              <span>Behavioral Confidence:</span>
              <span className="badge badge-teal">EVIDENTIARY GROUNDED (HIGH)</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
              <span>Crucial Evidence Sources:</span>
              <span className="mono" style={{ color: '#FFF' }}>SSH auth logs, utmp/btmp sessions</span>
            </div>

            <button
              className="btn btn-secondary"
              onClick={() => onNavigate('detection')}
              style={{ alignSelf: 'flex-start', marginTop: '4px', fontSize: '11px' }}
            >
              Browse Complete ATT&CK Matrix <ArrowRight size={12} />
            </button>
          </div>
        </div>
      </div>

      {/* Bottom Section: Live Activity Telemetry Feed */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={16} style={{ color: 'var(--teal-glow)' }} />
            Live Monitored Telemetry Stream ({events.length} observed events)
          </span>
          <span className="badge badge-neutral">Chronological Order</span>
        </div>

        {events.length > 0 ? (
          <div className="data-table-container" style={{ maxHeight: '280px', overflowY: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Host</th>
                  <th>Source</th>
                  <th>Event Type</th>
                  <th>User</th>
                  <th>Source IP</th>
                  <th>Raw Message Summary</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 15).map((evt) => {
                  const isFail = evt.event_type === 'ssh_auth_failure';
                  return (
                    <tr key={evt.event_id}>
                      <td className="mono" style={{ fontSize: '11px' }}>
                        {new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className="mono" style={{ color: '#FFF' }}>{evt.host}</td>
                      <td><span className="badge badge-neutral">{evt.source}</span></td>
                      <td>
                        <span className={`badge ${isFail ? 'badge-red' : 'badge-neutral'}`}>
                          {evt.event_type}
                        </span>
                      </td>
                      <td className="mono" style={{ color: evt.user === 'root' ? 'var(--red-oxide-bright)' : '#FFF' }}>
                        {evt.user || 'N/A'}
                      </td>
                      <td className="mono">{evt.source_ip || 'N/A'}</td>
                      <td style={{ maxWidth: '360px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={evt.message}>
                        {evt.message}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: '10.5px', padding: '2px 7px' }}
                          onClick={() => setSelectedEvent(evt)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Awaiting live telemetry stream. Start the Ubuntu collector agent (python3 threxis_collector.py) to stream real network events directly to THREXIS.
          </div>
        )}
      </div>

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div style={{
            width: '640px',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-medium)',
            borderRadius: '6px',
            padding: '20px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
              <span style={{ fontSize: '14px', fontWeight: 600, color: '#FFF' }}>
                Event Inspection: {selectedEvent.event_id}
              </span>
              <button className="btn btn-secondary" onClick={() => setSelectedEvent(null)}>Close</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div><b>Host:</b> {selectedEvent.host}</div>
              <div><b>Timestamp:</b> {selectedEvent.timestamp}</div>
              <div><b>Event Type:</b> <span className="badge badge-amber">{selectedEvent.event_type}</span></div>
              <div><b>Target User:</b> {selectedEvent.user || 'N/A'}</div>
              <div><b>Source IP:</b> {selectedEvent.source_ip || 'N/A'} (Port {selectedEvent.source_port || 'N/A'})</div>
              <div><b>SHA-256 Provenance Hash:</b> <span className="mono" style={{ fontSize: '10.5px', color: 'var(--teal-glow)' }}>{selectedEvent.sha256}</span></div>
              <div style={{ marginTop: '8px' }}><b>Raw Log Line:</b></div>
              <pre style={{
                backgroundColor: 'var(--bg-core)',
                padding: '10px',
                borderRadius: '4px',
                color: '#CBD5E1',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap'
              }}>
                {selectedEvent.raw_log}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
