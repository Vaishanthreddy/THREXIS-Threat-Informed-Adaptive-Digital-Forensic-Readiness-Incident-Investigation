import React, { useState } from 'react';
import {
  Gauge,
  HelpCircle,
  AlertOctagon,
  CheckCircle,
  ArrowUpRight,
  TrendingUp,
  FileCheck2,
  RefreshCw
} from 'lucide-react';
import { ReadinessAssessment, EvidenceSource } from '../types';
import { api } from '../services/api';

interface ForensicReadinessProps {
  readiness: ReadinessAssessment | null;
  onRefresh: () => void;
}

export const ForensicReadiness: React.FC<ForensicReadinessProps> = ({
  readiness,
  onRefresh
}) => {
  const [updatingSource, setUpdatingSource] = useState<string | null>(null);
  const [statusChangeMessage, setStatusChangeMessage] = useState<string | null>(null);

  const handleStatusChange = async (sourceKey: string, newStatus: string) => {
    setUpdatingSource(sourceKey);
    try {
      await api.updateSourceStatus(sourceKey, newStatus);
      setStatusChangeMessage(`Updated ${sourceKey} status to '${newStatus}'. Recalculating weighted readiness.`);
      onRefresh();
      setTimeout(() => setStatusChangeMessage(null), 4000);
    } catch (err: any) {
      console.error(err);
    } finally {
      setUpdatingSource(null);
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'validated': return 'badge-teal';
      case 'collected': return 'badge-blue';
      case 'available': return 'badge-amber';
      case 'unavailable':
      case 'missing': return 'badge-red';
      default: return 'badge-neutral';
    }
  };

  if (!readiness) {
    return (
      <div className="page-container" style={{ textAlign: 'center', padding: '60px' }}>
        <Gauge size={40} style={{ color: 'var(--text-muted)', margin: '0 auto 12px' }} />
        <div style={{ fontSize: '15px', color: '#FFF' }}>Readiness Assessment Not Assessed</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '6px' }}>
          Connect Ubuntu telemetry agent or load baseline configuration to compute weighted forensic readiness.
        </div>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      
      {/* Top Banner: Scientific Model & Core Score */}
      <div className="card" style={{ borderLeft: '4px solid var(--teal-core)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--teal-glow)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Operational Readiness Model
            </div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: '#FFF', marginTop: '2px' }}>
              Threat-Informed Forensic Readiness: {readiness.score.toFixed(1)}%
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '750px', lineHeight: 1.5 }}>
              Measures the degree to which digital evidence is readily preserved, accessible, and cryptographically verifiable
              to reconstruct incidents without compromising ongoing enterprise operations.
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <div style={{ textAlign: 'right', padding: '8px 14px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>CATEGORY</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--teal-glow)' }}>{readiness.category}</div>
            </div>
            <div style={{ textAlign: 'right', padding: '8px 14px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px' }}>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>SOURCE COVERAGE</div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: '#FFF' }}>{readiness.coverage_percentage}%</div>
            </div>
          </div>
        </div>

        {/* Mathematical Model Card Callout */}
        <div style={{
          marginTop: '16px',
          padding: '12px 14px',
          backgroundColor: 'var(--bg-core)',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '11.5px'
        }}>
          <div>
            <span style={{ color: 'var(--text-muted)' }}>Mathematical Formula: </span>
            <span className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600 }}>{readiness.formula}</span>
          </div>
          <div style={{ display: 'flex', gap: '16px', color: 'var(--text-secondary)' }}>
            <span>Numerator: Σ(wᵢ × sᵢ) = <b>{readiness.weighted_sum.toFixed(3)}</b></span>
            <span>Denominator: Σ(wᵢ) = <b>{readiness.total_weight.toFixed(3)}</b></span>
            <span>Active Threats: <b>{readiness.threat_context}</b></span>
          </div>
        </div>

        {statusChangeMessage && (
          <div style={{ marginTop: '10px', padding: '8px 12px', backgroundColor: 'var(--teal-dim)', border: '1px solid var(--teal-dim-border)', borderRadius: '4px', fontSize: '11.5px', color: 'var(--teal-glow)' }}>
            {statusChangeMessage}
          </div>
        )}
      </div>

      {/* Evidence Source Status Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Gauge size={16} style={{ color: 'var(--teal-glow)' }} />
            Monitored Evidence Sources & Readiness Factors (wᵢ × sᵢ)
          </span>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Model factors: Available (0.60) | Collected (0.85) | Validated (1.00) | Missing (0.00)
          </span>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Evidence Source</th>
                <th>Category</th>
                <th>Threat Weight (wᵢ)</th>
                <th>Status</th>
                <th>Factor (sᵢ)</th>
                <th>Weighted Contribution</th>
                <th>Acquisition Cost</th>
                <th>Technical State / Source Path</th>
                <th>Simulate Lifecycle</th>
              </tr>
            </thead>
            <tbody>
              {readiness.sources.map((s) => {
                return (
                  <tr key={s.source_key}>
                    <td style={{ fontWeight: 600, color: '#FFF' }}>
                      {s.source_name}
                    </td>
                    <td><span className="badge badge-neutral">{s.category}</span></td>
                    <td className="mono" style={{ color: s.weight >= 0.85 ? 'var(--teal-glow)' : '#FFF' }}>
                      {s.weight.toFixed(2)}
                    </td>
                    <td>
                      <span className={`badge ${getStatusBadgeClass(s.status)}`}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono">{(s.factor).toFixed(2)}</td>
                    <td className="mono" style={{ fontWeight: 600, color: '#FFF' }}>
                      {(s.weight * s.factor).toFixed(3)}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-muted)' }}>{s.collection_cost.toFixed(1)} units</td>
                    <td style={{ fontSize: '11px', color: 'var(--text-secondary)', maxWidth: '240px' }}>
                      {s.details}
                    </td>
                    <td>
                      <select
                        style={{
                          backgroundColor: 'var(--bg-surface-elevated)',
                          border: '1px solid var(--border-medium)',
                          color: 'var(--text-primary)',
                          padding: '3px 6px',
                          borderRadius: '4px',
                          fontSize: '11px',
                          fontFamily: 'var(--font-sans)',
                          cursor: 'pointer'
                        }}
                        value={s.status}
                        disabled={updatingSource === s.source_key}
                        onChange={(e) => handleStatusChange(s.source_key, e.target.value)}
                      >
                        <option value="missing">Missing (0.00)</option>
                        <option value="unavailable">Unavailable (0.00)</option>
                        <option value="available">Available (0.60)</option>
                        <option value="collected">Collected (0.85)</option>
                        <option value="validated">Validated (1.00)</option>
                        <option value="not_applicable">Not Applicable</option>
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Readiness Gaps & Remediation Recommendations */}
      <div className="grid-2">
        {/* Gap Analysis */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <AlertOctagon size={16} style={{ color: 'var(--amber-oxide)' }} />
              Forensic Readiness Gap Analysis ({readiness.gaps.length} Gaps)
            </span>
            <span className="badge badge-amber">Deficiencies &lt; 0.85</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {readiness.gaps.map((gap, idx) => (
              <div
                key={idx}
                style={{
                  padding: '10px 12px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderRadius: '4px',
                  borderLeft: `3px solid ${gap.weight >= 0.85 ? 'var(--red-oxide-bright)' : 'var(--amber-oxide)'}`
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontWeight: 600, color: '#FFF', fontSize: '12.5px' }}>{gap.source_name}</span>
                  <span className="mono badge badge-red" style={{ fontSize: '10px' }}>
                    Penalty: -{gap.penalty.toFixed(2)} pts
                  </span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  Current Status: <b style={{ textTransform: 'uppercase' }}>{gap.status}</b> (factor {gap.current_factor})
                </div>
                <div style={{ fontSize: '11px', color: 'var(--teal-glow)', marginTop: '4px' }}>
                  Remediation: {gap.remediation}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Priority Remediation Recommendations */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <TrendingUp size={16} style={{ color: 'var(--teal-glow)' }} />
              Priority Remediation Actions
            </span>
            <span className="badge badge-teal">ROI Impact Ranking</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {readiness.recommendations.map((rec, idx) => (
              <div
                key={idx}
                style={{
                  padding: '10px 12px',
                  backgroundColor: 'var(--bg-surface-elevated)',
                  borderRadius: '4px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                    <span className={`badge ${rec.priority === 'HIGH' ? 'badge-red' : 'badge-amber'}`} style={{ fontSize: '9.5px' }}>
                      {rec.priority}
                    </span>
                    <span style={{ fontWeight: 600, color: '#FFF', fontSize: '12px' }}>{rec.source}</span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    {rec.action}
                  </div>
                </div>

                <div className="badge badge-teal" style={{ whiteSpace: 'nowrap', fontSize: '11px' }}>
                  {rec.impact}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

    </div>
  );
};
