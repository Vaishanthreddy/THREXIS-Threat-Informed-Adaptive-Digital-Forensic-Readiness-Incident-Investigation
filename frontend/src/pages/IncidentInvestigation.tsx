import React, { useState, useEffect } from 'react';
import {
  FileSearch,
  Download,
  FileText,
  Clock,
  ShieldAlert,
  Save,
  CheckCircle2,
  HelpCircle,
  ExternalLink,
  Layers,
  ArrowRight
} from 'lucide-react';
import { InvestigationCase, TimelineItem } from '../types';
import { api } from '../services/api';

interface IncidentInvestigationProps {
  activeCase: InvestigationCase | null;
  onRefresh: () => void;
  onNavigateToVault: () => void;
}

export const IncidentInvestigation: React.FC<IncidentInvestigationProps> = ({
  activeCase,
  onRefresh,
  onNavigateToVault
}) => {
  const [caseDetail, setCaseDetail] = useState<any>(null);
  const [notes, setNotes] = useState<string>('');
  const [savingNotes, setSavingNotes] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  useEffect(() => {
    if (activeCase) {
      api.getCaseDetail(activeCase.case_id).then((data) => {
        setCaseDetail(data);
        setNotes(data.case.analyst_notes || '');
      }).catch(console.error);
    }
  }, [activeCase]);

  const handleSaveNotes = async () => {
    if (!activeCase) return;
    setSavingNotes(true);
    try {
      await api.updateCaseNotes(activeCase.case_id, notes);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      onRefresh();
    } catch (err) {
      console.error(err);
    } finally {
      setSavingNotes(false);
    }
  };

  if (!activeCase) {
    return (
      <div className="page-container" style={{ textAlign: 'center', padding: '60px' }}>
        <FileSearch size={40} style={{ color: 'var(--text-muted)', margin: '0 auto 12px' }} />
        <div style={{ fontSize: '15px', color: '#FFF' }}>No Incident Cases Opened</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '6px' }}>
          When security detections occur, THREXIS automatically opens a threat-informed forensic investigation case.
        </div>
      </div>
    );
  }

  const timeline: TimelineItem[] = caseDetail?.timeline || [];

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      
      {/* Top Banner: Case Summary & Download Actions */}
      <div className="card" style={{ borderLeft: '4px solid var(--amber-oxide)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="mono badge badge-amber" style={{ fontSize: '12px' }}>{activeCase.case_id}</span>
              <span className={`badge ${activeCase.severity === 'CRITICAL' || activeCase.severity === 'HIGH' ? 'badge-red' : 'badge-neutral'}`}>
                {activeCase.severity} SEVERITY
              </span>
              <span className="badge badge-teal">{activeCase.status}</span>
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#FFF', marginTop: '6px' }}>
              {activeCase.title}
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px', maxWidth: '750px', lineHeight: 1.5 }}>
              {activeCase.summary}
            </p>
          </div>

          {/* Export Report Buttons */}
          <div style={{ display: 'flex', gap: '10px' }}>
            <a
              href={api.getReportDownloadUrl(activeCase.case_id, 'pdf')}
              download={`THREXIS_Investigation_Report_${activeCase.case_id}.pdf`}
              className="btn btn-primary"
              style={{ textDecoration: 'none', fontSize: '12px', padding: '7px 12px' }}
            >
              <Download size={13} />
              Export Court-Admissible PDF
            </a>
            <a
              href={api.getReportDownloadUrl(activeCase.case_id, 'json')}
              download={`THREXIS_Investigation_Report_${activeCase.case_id}.json`}
              className="btn btn-secondary"
              style={{ textDecoration: 'none', fontSize: '12px', padding: '7px 12px' }}
            >
              <FileText size={13} />
              Export Structured JSON
            </a>
          </div>
        </div>

        {/* Case Metadata Details */}
        <div style={{
          marginTop: '16px',
          padding: '10px 14px',
          backgroundColor: 'var(--bg-core)',
          borderRadius: '4px',
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: '11.5px',
          color: 'var(--text-secondary)'
        }}>
          <div><b>Mapped Technique:</b> <span className="mono" style={{ color: 'var(--teal-glow)' }}>{activeCase.primary_technique}</span></div>
          <div><b>First Observed:</b> <span className="mono">{new Date(activeCase.created_at).toLocaleString()}</span></div>
          <div><b>Readiness Score At Detection:</b> <span className="mono" style={{ color: '#FFF', fontWeight: 600 }}>{activeCase.readiness_score_at_time.toFixed(1)}%</span></div>
          <div><b>Supporting Events:</b> <span className="mono">{activeCase.supporting_event_ids?.length || 0} events</span></div>
        </div>
      </div>

      {/* Investigation Timeline */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Clock size={16} style={{ color: 'var(--teal-glow)' }} />
            Chronological Investigation Timeline ({timeline.length} Correlated Items)
          </span>
          <span className="badge badge-neutral">Event + Alert + Vault Synchronized</span>
        </div>

        <div style={{ position: 'relative', paddingLeft: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Vertical timeline line */}
          <div style={{
            position: 'absolute',
            left: '8px',
            top: '4px',
            bottom: '4px',
            width: '2px',
            backgroundColor: 'var(--border-medium)'
          }} />

          {timeline.map((item, idx) => {
            const isAlert = item.type === 'DETECTION_ALERT';
            const isVault = item.type === 'EVIDENCE_ACQUIRED';
            const dotColor = isAlert ? 'var(--red-oxide-bright)' : (isVault ? 'var(--teal-glow)' : '#64748B');

            return (
              <div key={idx} style={{ position: 'relative', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {/* Timeline node dot */}
                <div style={{
                  position: 'absolute',
                  left: '-20px',
                  top: '4px',
                  width: '10px',
                  height: '10px',
                  borderRadius: '50%',
                  backgroundColor: dotColor,
                  border: '2px solid var(--bg-surface)'
                }} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                  <span className={`badge ${isAlert ? 'badge-red' : (isVault ? 'badge-teal' : 'badge-neutral')}`} style={{ fontSize: '9.5px' }}>
                    {item.type}
                  </span>
                  <span style={{ fontSize: '12.5px', fontWeight: 600, color: '#FFF' }}>
                    {item.title}
                  </span>
                </div>

                <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', paddingLeft: '2px' }}>
                  {item.description}
                </div>

                {item.sha256 && (
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    SHA-256 Provenance: {item.sha256}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Findings & Unresolved Questions */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <CheckCircle2 size={16} style={{ color: 'var(--teal-glow)' }} />
              Forensic Findings
            </span>
            <span className="badge badge-teal">Verified Facts</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {activeCase.findings?.map((f, i) => (
              <div key={i} style={{ display: 'flex', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span style={{ color: 'var(--teal-glow)', fontWeight: 700 }}>•</span>
                <span>{f}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <HelpCircle size={16} style={{ color: 'var(--amber-oxide)' }} />
              Unresolved Investigative Questions
            </span>
            <span className="badge badge-amber">Hypotheses</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {activeCase.unresolved_questions?.map((q, i) => (
              <div key={i} style={{ display: 'flex', gap: '8px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span style={{ color: 'var(--amber-oxide)', fontWeight: 700 }}>?</span>
                <span>{q}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Analyst Notes Editor */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <FileText size={16} style={{ color: 'var(--teal-glow)' }} />
            Analyst Working Notes & Investigative Assessment
          </span>
          <button
            className="btn btn-primary"
            onClick={handleSaveNotes}
            disabled={savingNotes}
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            <Save size={12} />
            {savingNotes ? 'Saving...' : 'Save Notes'}
          </button>
        </div>

        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={5}
          placeholder="Document investigator observations, hypothesis testing, witness statements, or lateral movement verification..."
          style={{
            width: '100%',
            backgroundColor: 'var(--bg-core)',
            border: '1px solid var(--border-medium)',
            borderRadius: '4px',
            color: '#F1F5F9',
            padding: '12px',
            fontSize: '12px',
            fontFamily: 'var(--font-sans)',
            lineHeight: 1.5,
            resize: 'vertical'
          }}
        />

        {saveSuccess && (
          <div style={{ marginTop: '8px', fontSize: '11.5px', color: 'var(--teal-glow)' }}>
            Analyst notes successfully committed to case manifest.
          </div>
        )}
      </div>

    </div>
  );
};
