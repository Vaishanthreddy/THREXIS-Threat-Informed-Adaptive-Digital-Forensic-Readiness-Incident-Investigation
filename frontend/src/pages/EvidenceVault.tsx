import React, { useState, useEffect } from 'react';
import {
  Vault,
  ShieldCheck,
  ShieldAlert,
  FileCheck2,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Layers,
  ArrowRight
} from 'lucide-react';
import { EvidenceVaultItem, InvestigationCase, SecurityEvent } from '../types';
import { api } from '../services/api';

interface EvidenceVaultProps {
  vaultItems: EvidenceVaultItem[];
  activeCase: InvestigationCase | null;
  events: SecurityEvent[];
  onRefresh: () => void;
}

export const EvidenceVault: React.FC<EvidenceVaultProps> = ({
  vaultItems,
  activeCase,
  events,
  onRefresh
}) => {
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [acquiring, setAcquiring] = useState<boolean>(false);
  const [acquireSuccessMsg, setAcquireSuccessMsg] = useState<string | null>(null);

  const handleVerify = async (evidenceId: string) => {
    setVerifyingId(evidenceId);
    try {
      const res = await api.verifyIntegrity(evidenceId);
      setVerificationResult(res);
      onRefresh();
    } catch (err: any) {
      console.error(err);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleQuickAcquire = async () => {
    if (!activeCase) return;
    setAcquiring(true);
    try {
      // Pick all failure events
      const relevantEventIds = events
        .filter(e => e.event_type === 'ssh_auth_failure' || e.event_type === 'sudo_event')
        .map(e => e.event_id);

      const targetIds = relevantEventIds.length > 0 ? relevantEventIds : events.map(e => e.event_id);

      const newItem = await api.acquireEvidence(
        activeCase.case_id,
        'ssh_auth',
        'SSH Authentication Telemetry',
        targetIds,
        '/var/log/auth.log'
      );

      setAcquireSuccessMsg(`Acquired ${newItem.record_count} events into Vault as ${newItem.evidence_id}. Cryptographic SHA-256 calculated.`);
      onRefresh();
      setTimeout(() => setAcquireSuccessMsg(null), 5000);
    } catch (err: any) {
      console.error(err);
    } finally {
      setAcquiring(false);
    }
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      
      {/* Top Card: Forensic Integrity Workflow & Quick Acquire */}
      <div className="card" style={{ borderLeft: '4px solid var(--teal-core)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--teal-glow)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Forensic Preservation Standard
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#FFF', marginTop: '4px' }}>
              Cryptographic Evidence Vault & Chain of Custody
            </h2>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '750px', lineHeight: 1.5 }}>
              All acquired digital evidence artifacts are saved as bit-stream copies with immediate SHA-256 hash generation,
              stored in read-only vaults with signed JSON custody manifests to guarantee evidentiary admissibility.
            </div>
          </div>

          {activeCase && (
            <button
              className="btn btn-primary"
              onClick={handleQuickAcquire}
              disabled={acquiring}
              style={{ fontSize: '12px', padding: '8px 14px' }}
            >
              <Vault size={14} />
              {acquiring ? 'Preserving Evidence...' : 'Preserve Evidence for Active Case'}
            </button>
          )}
        </div>

        {/* Workflow Diagram */}
        <div style={{
          marginTop: '16px',
          padding: '12px 16px',
          backgroundColor: 'var(--bg-core)',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '11px',
          flexWrap: 'wrap',
          gap: '8px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
            <span className="mono badge badge-neutral">1</span> Evidence Identified
          </div>
          <span style={{ color: 'var(--text-muted)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
            <span className="mono badge badge-neutral">2</span> Telemetry Acquired
          </div>
          <span style={{ color: 'var(--text-muted)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--teal-glow)' }}>
            <span className="mono badge badge-teal">3</span> SHA-256 Calculated
          </div>
          <span style={{ color: 'var(--text-muted)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
            <span className="mono badge badge-neutral">4</span> Manifest Sealed
          </div>
          <span style={{ color: 'var(--text-muted)' }}>→</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)' }}>
            <span className="mono badge badge-neutral">5</span> Integrity Verified
          </div>
        </div>

        {acquireSuccessMsg && (
          <div style={{ marginTop: '12px', padding: '8px 12px', backgroundColor: 'var(--teal-dim)', border: '1px solid var(--teal-dim-border)', borderRadius: '4px', fontSize: '11.5px', color: 'var(--teal-glow)' }}>
            {acquireSuccessMsg}
          </div>
        )}
      </div>

      {/* Vault Items Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Vault size={16} style={{ color: 'var(--teal-glow)' }} />
            Preserved Forensic Artifacts in Vault ({vaultItems.length} Registered Items)
          </span>
          <span className="badge badge-neutral">Immutable Filesystem Vault</span>
        </div>

        {vaultItems.length > 0 ? (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Evidence ID</th>
                  <th>Linked Case</th>
                  <th>Source Title</th>
                  <th>Original Path</th>
                  <th>Records</th>
                  <th>Size</th>
                  <th>Cryptographic SHA-256 Hash</th>
                  <th>Integrity Status</th>
                  <th>Last Verified</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {vaultItems.map((item) => {
                  const isVerified = item.integrity_status === 'VERIFIED';
                  return (
                    <tr key={item.evidence_id}>
                      <td className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600 }}>
                        {item.evidence_id}
                      </td>
                      <td className="mono badge badge-neutral" style={{ margin: '8px 0' }}>
                        {item.case_id}
                      </td>
                      <td style={{ color: '#FFF', fontWeight: 500 }}>{item.source_title}</td>
                      <td className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        {item.original_source_path}
                      </td>
                      <td className="mono">{item.record_count} lines</td>
                      <td className="mono">{item.file_size_bytes} B</td>
                      <td className="mono" style={{ fontSize: '11px', color: '#CBD5E1', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis' }} title={item.sha256_hash}>
                        {item.sha256_hash}
                      </td>
                      <td>
                        <span className={`badge ${isVerified ? 'badge-teal' : 'badge-red'}`}>
                          {isVerified ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
                          {item.integrity_status}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: '11px' }}>
                        {new Date(item.last_verified_at).toLocaleTimeString()}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: '10.5px', padding: '3px 8px' }}
                          disabled={verifyingId === item.evidence_id}
                          onClick={() => handleVerify(item.evidence_id)}
                        >
                          <ShieldCheck size={12} />
                          {verifyingId === item.evidence_id ? 'Verifying...' : 'Verify Integrity'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No forensic evidence preserved in the vault yet. Click "Preserve Evidence for Active Case" above to snapshot current telemetry with SHA-256 hashing.
          </div>
        )}
      </div>

      {/* Verification Result Modal */}
      {verificationResult && (
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
            padding: '22px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '10px' }}>
              <span style={{ fontSize: '14px', fontWeight: 600, color: '#FFF', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck size={18} style={{ color: verificationResult.verified ? 'var(--teal-glow)' : 'var(--red-oxide-bright)' }} />
                Integrity Verification: {verificationResult.evidence_id}
              </span>
              <button className="btn btn-secondary" onClick={() => setVerificationResult(null)}>Close</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div>
                <b>Verification Status: </b>
                <span className={`badge ${verificationResult.verified ? 'badge-teal' : 'badge-red'}`} style={{ fontSize: '11px', marginLeft: '6px' }}>
                  {verificationResult.status}
                </span>
              </div>

              <div>
                <b>Expected SHA-256 Hash (Custody Record):</b>
                <pre style={{ backgroundColor: 'var(--bg-core)', padding: '6px 10px', borderRadius: '4px', color: '#94A3B8', fontSize: '11px', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                  {verificationResult.expected_sha256}
                </pre>
              </div>

              <div>
                <b>Calculated SHA-256 Hash (Current Disk File):</b>
                <pre style={{ backgroundColor: 'var(--bg-core)', padding: '6px 10px', borderRadius: '4px', color: verificationResult.verified ? 'var(--teal-glow)' : 'var(--red-oxide-bright)', fontSize: '11px', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                  {verificationResult.calculated_sha256}
                </pre>
              </div>

              <div style={{ marginTop: '6px', padding: '10px 12px', backgroundColor: 'var(--bg-surface-elevated)', borderRadius: '4px', borderLeft: `3px solid ${verificationResult.verified ? 'var(--teal-core)' : 'var(--red-oxide)'}` }}>
                <div style={{ color: '#FFF', fontWeight: 500 }}>
                  {verificationResult.explanation}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
