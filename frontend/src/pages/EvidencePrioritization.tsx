import React, { useState, useEffect } from 'react';
import {
  ListOrdered,
  Layers,
  Sliders,
  DollarSign,
  TrendingUp,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  HelpCircle,
  BarChart2,
  RefreshCw
} from 'lucide-react';
import { PrioritizationResult, StrategyComparisonItem } from '../types';
import { api } from '../services/api';

export const EvidencePrioritization: React.FC = () => {
  const [strategy, setStrategy] = useState<string>('adaptive');
  const [budget, setBudget] = useState<number>(60);
  const [threatContext, setThreatContext] = useState<string>('T1110');
  const [result, setResult] = useState<PrioritizationResult | null>(null);
  const [comparison, setComparison] = useState<StrategyComparisonItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  const runPrioritization = async () => {
    setLoading(true);
    try {
      const data = await api.runPrioritization(strategy, budget, threatContext);
      setResult(data);
      const compData = await api.compareStrategies(budget, threatContext);
      setComparison(compData.strategies_comparison);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runPrioritization();
  }, [strategy, budget, threatContext]);

  const STRATEGY_DESCRIPTIONS: Record<string, string> = {
    'adaptive': 'Dynamic utility ranking based on observed MITRE ATT&CK technique affinity, availability factor, and acquisition cost.',
    'static': 'Fixed baseline priority order regardless of observed security events or active threats.',
    'random': 'Stochastic baseline evidence selection within collection budget limit.',
    'threat_agnostic': 'Ranks evidence solely by availability-to-cost ratio, completely ignoring active attack behavior.',
    'frozen_context': 'Uses initial baseline threat model but refuses to adapt when telemetry indicates threat context shifts.'
  };

  return (
    <div className="page-container" style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      
      {/* Top Controls Card: Budget & Strategy Configuration */}
      <div className="card" style={{ borderLeft: '4px solid var(--teal-core)' }}>
        <div className="card-header">
          <span className="card-title">
            <Sliders size={16} style={{ color: 'var(--teal-glow)' }} />
            Adaptive Prioritization Parameters & Threat Context
          </span>
          <span className="badge badge-teal">Core Research Optimization</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '14px' }}>
          {/* Strategy selector */}
          <div>
            <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Selection Strategy
            </label>
            <select
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-surface-elevated)',
                border: '1px solid var(--border-medium)',
                borderRadius: '4px',
                color: '#FFF',
                padding: '7px 10px',
                fontSize: '12px',
                fontFamily: 'var(--font-sans)',
                cursor: 'pointer'
              }}
              value={strategy}
              onChange={(e) => setStrategy(e.target.value)}
            >
              <option value="adaptive">1. Adaptive Threat-Informed (Recommended)</option>
              <option value="static">2. Static Selection (Fixed Baseline)</option>
              <option value="random">3. Random Selection (Stochastic Baseline)</option>
              <option value="threat_agnostic">4. Threat-Agnostic (Cost-Availability Only)</option>
              <option value="frozen_context">5. Frozen-Context (Stale Model)</option>
            </select>
          </div>

          {/* Budget Limit Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                Collection Budget Constraint
              </label>
              <span className="mono" style={{ color: 'var(--teal-glow)', fontWeight: 600 }}>
                {budget.toFixed(1)} Units
              </span>
            </div>
            <input
              type="range"
              min="15"
              max="120"
              step="5"
              value={budget}
              onChange={(e) => setBudget(parseFloat(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--teal-bright)', cursor: 'pointer' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
              <span>15 (Constrained)</span>
              <span>60 (Moderate)</span>
              <span>120 (Permissive)</span>
            </div>
          </div>

          {/* Threat Context */}
          <div>
            <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
              Observed Threat Context
            </label>
            <select
              style={{
                width: '100%',
                backgroundColor: 'var(--bg-surface-elevated)',
                border: '1px solid var(--border-medium)',
                borderRadius: '4px',
                color: '#FFF',
                padding: '7px 10px',
                fontSize: '12px',
                fontFamily: 'var(--font-sans)',
                cursor: 'pointer'
              }}
              value={threatContext}
              onChange={(e) => setThreatContext(e.target.value)}
            >
              <option value="T1110">T1110: SSH Brute Force / Password Guessing</option>
              <option value="T1548.003">T1548.003: Privilege Escalation / Sudo Abuse</option>
              <option value="T1059.004">T1059.004: Unix Shell & Scripting Execution</option>
              <option value="BASELINE">BASELINE: Normal Security Operations</option>
            </select>
          </div>
        </div>

        <div style={{ padding: '8px 12px', backgroundColor: 'var(--bg-core)', borderRadius: '4px', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
          <b style={{ color: 'var(--teal-glow)' }}>Strategy Logic: </b>
          {STRATEGY_DESCRIPTIONS[strategy]}
        </div>
      </div>

      {/* KPI Cards: Budget Utilization, Recall, Precision */}
      {result && (
        <div className="grid-4">
          <div className="card" style={{ padding: '14px' }}>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Budget Allocated / Used</div>
            <div className="mono" style={{ fontSize: '20px', fontWeight: 700, color: '#FFF', marginTop: '4px' }}>
              {result.budget_used.toFixed(1)} / {result.budget_limit.toFixed(1)}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--teal-glow)', marginTop: '2px' }}>
              {result.budget_utilization_pct}% utilization ({result.remaining_budget.toFixed(1)} rem)
            </div>
          </div>

          <div className="card" style={{ padding: '14px' }}>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Relevant Evidence Recall</div>
            <div className="mono" style={{ fontSize: '20px', fontWeight: 700, color: result.metrics.recall >= 0.8 ? 'var(--teal-glow)' : 'var(--amber-oxide)', marginTop: '4px' }}>
              {(result.metrics.recall * 100).toFixed(0)}%
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              {result.metrics.true_positives} of {result.metrics.total_relevant} critical sources captured
            </div>
          </div>

          <div className="card" style={{ padding: '14px' }}>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Selection Precision</div>
            <div className="mono" style={{ fontSize: '20px', fontWeight: 700, color: '#FFF', marginTop: '4px' }}>
              {(result.metrics.precision * 100).toFixed(0)}%
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Fraction of acquired items matching threat
            </div>
          </div>

          <div className="card" style={{ padding: '14px' }}>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Cost per Relevant Source</div>
            <div className="mono" style={{ fontSize: '20px', fontWeight: 700, color: '#FFF', marginTop: '4px' }}>
              {result.metrics.cost_per_relevant_item.toFixed(1)} units
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Acquisition resource efficiency
            </div>
          </div>
        </div>
      )}

      {/* Ranked Candidate Sources Table */}
      {result && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <ListOrdered size={16} style={{ color: 'var(--teal-glow)' }} />
              Ranked Evidence Candidate Items ({result.selected_sources.length} Selected within Budget)
            </span>
            <span className="badge badge-neutral">Knapsack Budget Constraint</span>
          </div>

          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rank</th>
                  <th>Evidence Source</th>
                  <th>Category</th>
                  <th>Priority Score</th>
                  <th>Threat Affinity</th>
                  <th>Acquisition Cost</th>
                  <th>Availability Factor</th>
                  <th>Status Decision</th>
                  <th>Remaining Budget</th>
                  <th>Selection Rationale</th>
                </tr>
              </thead>
              <tbody>
                {result.ranked_items.map((item, idx) => (
                  <tr key={item.source_key} style={{ opacity: item.selected ? 1 : 0.65 }}>
                    <td className="mono" style={{ fontWeight: 600, color: item.selected ? 'var(--teal-glow)' : 'var(--text-muted)' }}>
                      #{idx + 1}
                    </td>
                    <td style={{ fontWeight: 600, color: item.selected ? '#FFF' : 'var(--text-secondary)' }}>
                      {item.source_name}
                    </td>
                    <td><span className="badge badge-neutral">{item.category}</span></td>
                    <td className="mono" style={{ fontWeight: 700, color: item.selected ? 'var(--teal-glow)' : '#FFF' }}>
                      {item.priority_score.toFixed(3)}
                    </td>
                    <td className="mono">
                      {item.threat_affinity !== undefined ? item.threat_affinity.toFixed(2) : 'N/A'}
                    </td>
                    <td className="mono">{item.cost.toFixed(1)} u</td>
                    <td className="mono">{item.availability_factor.toFixed(2)}</td>
                    <td>
                      {item.selected ? (
                        <span className="badge badge-teal">
                          <CheckCircle2 size={11} /> SELECTED
                        </span>
                      ) : (
                        <span className="badge badge-red" title={item.rejection_reason}>
                          <XCircle size={11} /> EXCLUDED
                        </span>
                      )}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-muted)' }}>
                      {item.remaining_after !== undefined ? `${item.remaining_after} u` : 'N/A'}
                    </td>
                    <td style={{ fontSize: '11px', color: 'var(--text-secondary)', maxWidth: '280px' }}>
                      {item.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5-Strategy Comparative Benchmark Matrix */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <BarChart2 size={16} style={{ color: 'var(--teal-glow)' }} />
            Comparative Benchmark: All 5 Prioritization Strategies (Budget = {budget.toFixed(0)} Units)
          </span>
          <span className="badge badge-teal">Academic Baseline Comparison</span>
        </div>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Strategy</th>
                <th>Sources Acquired</th>
                <th>Budget Used</th>
                <th>Utilization</th>
                <th>Relevant Recall</th>
                <th>Precision</th>
                <th>Cost / Relevant Source</th>
                <th>Academic Behavior</th>
              </tr>
            </thead>
            <tbody>
              {comparison.map((comp) => {
                const isSelected = comp.strategy === strategy;
                return (
                  <tr key={comp.strategy} style={{ backgroundColor: isSelected ? 'var(--teal-dim)' : 'transparent' }}>
                    <td style={{ fontWeight: 600, color: isSelected ? 'var(--teal-glow)' : '#FFF' }}>
                      {comp.strategy.toUpperCase().replace('_', ' ')}
                      {isSelected && <span className="badge badge-teal" style={{ marginLeft: '6px', fontSize: '9px' }}>ACTIVE</span>}
                    </td>
                    <td className="mono">{comp.selected_count} sources</td>
                    <td className="mono">{comp.budget_used.toFixed(1)} u</td>
                    <td className="mono">{comp.utilization_pct.toFixed(1)}%</td>
                    <td className="mono" style={{ fontWeight: 700, color: comp.recall >= 0.8 ? 'var(--teal-glow)' : (comp.recall >= 0.5 ? '#EAB308' : 'var(--red-oxide-bright)') }}>
                      {(comp.recall * 100).toFixed(0)}%
                    </td>
                    <td className="mono">{(comp.precision * 100).toFixed(0)}%</td>
                    <td className="mono">{comp.cost_per_relevant.toFixed(1)} u</td>
                    <td style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {comp.strategy === 'adaptive' && 'Optimal: Adapts to threat telemetry to select critical sources first.'}
                      {comp.strategy === 'static' && 'Fixed baseline: Misses high-value evidence when attacks diverge from default order.'}
                      {comp.strategy === 'random' && 'Stochastic: Exhibits high variance and unpredictable evidence gaps.'}
                      {comp.strategy === 'threat_agnostic' && 'Cost-biased: Collects cheap irrelevant logs while missing critical authentication telemetry.'}
                      {comp.strategy === 'frozen_context' && 'Stale context: Fails to detect pivots due to outdated threat priors.'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
