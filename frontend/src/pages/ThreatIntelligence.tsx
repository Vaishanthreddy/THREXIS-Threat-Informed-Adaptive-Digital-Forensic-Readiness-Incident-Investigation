import React, { useState } from 'react';
import {
  Crosshair,
  ExternalLink,
  ShieldAlert,
  Sliders,
  CheckCircle2,
  AlertCircle,
  FileSearch,
  Search
} from 'lucide-react';
import { DetectionAlert, MitreTechnique } from '../types';

interface ThreatIntelligenceProps {
  alerts: DetectionAlert[];
  techniques: MitreTechnique[];
  onNavigateToInvestigation: () => void;
}

export const ThreatIntelligence: React.FC<ThreatIntelligenceProps> = ({
  alerts,
  techniques,
  onNavigateToInvestigation
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(techniques[0] || null);
  const [selectedAlert, setSelectedAlert] = useState<DetectionAlert | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredTechniques = techniques.filter(t =>
    t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.tactics.some(tac => tac.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      
      {/* Live Alerts Section */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <ShieldAlert size={16} style={{ color: alerts.length > 0 ? 'var(--red-oxide-bright)' : 'var(--teal-glow)' }} />
            Active Threat Detection Alerts ({alerts.length} Triggered)
          </span>
          <span className="badge badge-neutral">Deterministic Correlation</span>
        </div>

        {alerts.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Detection Rule</th>
                  <th>Severity</th>
                  <th>MITRE Technique</th>
                  <th>Tactic</th>
                  <th>Target User</th>
                  <th>Source IP</th>
                  <th>Event Count</th>
                  <th>Last Observed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alt) => (
                  <tr key={alt.alert_id}>
                    <td className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600 }}>
                      {alt.alert_id}
                    </td>
                    <td style={{ color: '#FFF', fontWeight: 500 }}>{alt.rule_name}</td>
                    <td>
                      <span className={`badge ${alt.severity === 'CRITICAL' || alt.severity === 'HIGH' ? 'badge-red' : 'badge-amber'}`}>
                        {alt.severity}
                      </span>
                    </td>
                    <td className="mono" style={{ color: 'var(--teal-glow)' }}>
                      {alt.technique_id}
                    </td>
                    <td><span className="badge badge-neutral">{alt.tactic}</span></td>
                    <td className="mono">{alt.target_user || 'N/A'}</td>
                    <td className="mono">{alt.source_ip || 'N/A'}</td>
                    <td className="mono" style={{ fontWeight: 600, color: '#FFF' }}>
                      {alt.event_count} events
                    </td>
                    <td className="mono" style={{ fontSize: '11px' }}>
                      {new Date(alt.last_event_at).toLocaleTimeString()}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '6px' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: '10.5px', padding: '2px 7px' }}
                          onClick={() => setSelectedAlert(alt)}
                        >
                          Rationale
                        </button>
                        <button
                          className="btn btn-primary"
                          style={{ fontSize: '10.5px', padding: '2px 7px' }}
                          onClick={onNavigateToInvestigation}
                        >
                          <FileSearch size={11} /> Investigate
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '28px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No alerts triggered. Threshold has not been reached for SSH authentication failures or unauthorized sudo attempts.
          </div>
        )}
      </div>

      {/* MITRE ATT&CK Knowledge Base Explorer */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Crosshair size={16} style={{ color: 'var(--teal-glow)' }} />
            MITRE ATT&CK Enterprise Threat Intelligence Matrix
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ position: 'relative' }}>
              <Search size={13} style={{ position: 'absolute', left: '8px', top: '7px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search technique or tactic..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  backgroundColor: 'var(--bg-surface-elevated)',
                  border: '1px solid var(--border-medium)',
                  borderRadius: '4px',
                  padding: '4px 8px 4px 26px',
                  color: '#FFF',
                  fontSize: '11.5px',
                  fontFamily: 'var(--font-sans)',
                  width: '200px'
                }}
              />
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '16px' }}>
          {/* Technique list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '420px', overflowY: 'auto', paddingRight: '4px' }}>
            {filteredTechniques.map((tech) => {
              const isSelected = selectedTechnique?.id === tech.id;
              const hasAlert = alerts.some(a => a.technique_id.startsWith(tech.id));
              return (
                <div
                  key={tech.id}
                  onClick={() => setSelectedTechnique(tech)}
                  style={{
                    padding: '10px 12px',
                    borderRadius: '4px',
                    backgroundColor: isSelected ? 'var(--teal-dim)' : 'var(--bg-surface-elevated)',
                    border: `1px solid ${isSelected ? 'var(--teal-dim-border)' : 'var(--border-subtle)'}`,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                    <span className="mono" style={{ color: isSelected ? 'var(--teal-glow)' : '#FFF', fontWeight: 600, fontSize: '12px' }}>
                      {tech.id}
                    </span>
                    {hasAlert && <span className="badge badge-red" style={{ fontSize: '9px' }}>ACTIVE DETECT</span>}
                  </div>
                  <div style={{ fontSize: '12px', color: isSelected ? '#FFF' : 'var(--text-secondary)', fontWeight: 500 }}>
                    {tech.name}
                  </div>
                  <div style={{ display: 'flex', gap: '4px', marginTop: '4px', flexWrap: 'wrap' }}>
                    {tech.tactics.map((t, idx) => (
                      <span key={idx} className="badge badge-neutral" style={{ fontSize: '9.5px', padding: '1px 5px' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Technique Detail View */}
          {selectedTechnique ? (
            <div style={{
              backgroundColor: 'var(--bg-surface-elevated)',
              borderRadius: '6px',
              padding: '16px',
              border: '1px solid var(--border-medium)',
              display: 'flex',
              flexDirection: 'column',
              gap: '14px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="mono badge badge-teal" style={{ fontSize: '13px', padding: '2px 8px' }}>
                      {selectedTechnique.id}
                    </span>
                    <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#FFF' }}>
                      {selectedTechnique.name}
                    </h2>
                  </div>
                  <div style={{ display: 'flex', gap: '6px', marginTop: '6px' }}>
                    {selectedTechnique.tactics.map((tac, i) => (
                      <span key={i} className="badge badge-neutral">{tac}</span>
                    ))}
                  </div>
                </div>

                <a
                  href={selectedTechnique.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary"
                  style={{ fontSize: '11px', textDecoration: 'none' }}
                >
                  Official ATT&CK Page <ExternalLink size={12} />
                </a>
              </div>

              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Technique Description
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                  {selectedTechnique.description}
                </p>
              </div>

              {selectedTechnique.subtechniques && selectedTechnique.subtechniques.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                    Grounded Subtechniques
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedTechnique.subtechniques.map((sub) => (
                      <div key={sub.id} style={{ padding: '8px 10px', backgroundColor: 'var(--bg-core)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600, fontSize: '11.5px' }}>{sub.id}</span>
                          <span style={{ color: '#FFF', fontWeight: 500, fontSize: '12px' }}>{sub.name}</span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{sub.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Detection Methods
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedTechnique.detection_methods}
                </div>
              </div>

              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Required Digital Forensic Evidence Sources
                </div>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  {selectedTechnique.evidence_sources.map((src, i) => (
                    <span key={i} className="badge badge-teal" style={{ fontSize: '11px' }}>
                      {src}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Select a MITRE technique to inspect details and required forensic sources.
            </div>
          )}
        </div>
      </div>

      {/* Rationale Modal */}
      {selectedAlert && (
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
            width: '620px',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-medium)',
            borderRadius: '6px',
            padding: '22px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
              <span style={{ fontSize: '14px', fontWeight: 600, color: '#FFF' }}>
                Mapping Rationale: {selectedAlert.alert_id}
              </span>
              <button className="btn btn-secondary" onClick={() => setSelectedAlert(null)}>Close</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div><b>Rule:</b> {selectedAlert.rule_name} ({selectedAlert.rule_id})</div>
              <div><b>Assigned ATT&CK Technique:</b> <span className="mono badge badge-teal">{selectedAlert.technique_id} - {selectedAlert.technique_name}</span></div>
              <div><b>Tactic:</b> {selectedAlert.tactic}</div>
              <div><b>Detection Explanation:</b> {selectedAlert.explanation}</div>
              
              <div style={{ marginTop: '8px', padding: '12px', backgroundColor: 'var(--bg-core)', borderRadius: '4px', borderLeft: '3px solid var(--teal-core)' }}>
                <div style={{ fontSize: '11px', color: 'var(--teal-glow)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Transparent Evidentiary Rationale:
                </div>
                <div style={{ color: '#E2E8F0', lineHeight: 1.55 }}>
                  {selectedAlert.rationale}
                </div>
              </div>

              <div>
                <b>Supporting Event IDs:</b>
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '4px' }}>
                  {selectedAlert.supporting_event_ids.map((id, i) => (
                    <span key={i} className="mono badge badge-neutral" style={{ fontSize: '10px' }}>
                      {id}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
