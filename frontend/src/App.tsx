import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { CommandCenter } from './pages/CommandCenter';
import { ForensicReadiness } from './pages/ForensicReadiness';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { EvidencePrioritization } from './pages/EvidencePrioritization';
import { IncidentInvestigation } from './pages/IncidentInvestigation';
import { EvidenceVault } from './pages/EvidenceVault';
import { ResearchEvaluation } from './pages/ResearchEvaluation';
import { api } from './services/api';
import type {
  ReadinessAssessment,
  SecurityEvent,
  DetectionAlert,
  MitreTechnique,
  EvidenceVaultItem,
  CollectorStatus,
  InvestigationCase
} from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('command-center');
  const [readiness, setReadiness] = useState<ReadinessAssessment | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [vaultItems, setVaultItems] = useState<EvidenceVaultItem[]>([]);
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus | null>(null);
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const activeCase = cases.length > 0 ? cases[0] : null;

  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [rData, eData, aData, tData, vData, cStatus, caseList] = await Promise.all([
        api.getReadiness().catch(() => null),
        api.getRecentEvents(60).catch(() => []),
        api.getAlerts().catch(() => []),
        api.getMitreTechniques().catch(() => []),
        api.getVaultItems().catch(() => []),
        api.getCollectorStatus().catch(() => null),
        api.getCases().catch(() => [])
      ]);

      if (rData) setReadiness(rData);
      setEvents(eData);
      setAlerts(aData);
      setTechniques(tData);
      setVaultItems(vData);
      setCollectorStatus(cStatus);
      setCases(caseList);
    } catch (err) {
      console.error('Error fetching dashboard state:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadData();
    // Continuous background sync every 3 seconds for real-time live detection
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [loadData]);

  // WebSocket Live Connection for instantaneous real-time event alerts
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    let ws: WebSocket;

    try {
      ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (
            msg.type === 'TELEMETRY_BATCH' ||
            msg.type === 'NEW_ALERTS' ||
            msg.type === 'READINESS_UPDATED' ||
            msg.type === 'COLLECTOR_HEARTBEAT' ||
            msg.type === 'EVIDENCE_PRESERVED'
          ) {
            loadData();
          }
        } catch (e) {
          // ignore heartbeat ping
        }
      };

      ws.onerror = (err) => {
        console.warn('WebSocket connection notice:', err);
      };
    } catch (e) {
      console.warn('WebSocket init exception:', e);
    }

    return () => {
      if (ws) ws.close();
    };
  }, [loadData]);

  return (
    <div className="app-container">
      <Sidebar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        collectorStatus={collectorStatus}
        activeCase={activeCase}
        lastEventTime={events.length > 0 ? events[0].timestamp : null}
        totalEventsCount={events.length}
      />

      <div className="main-content">
        <Header
          currentTab={currentTab}
          onRefresh={loadData}
          isRefreshing={isRefreshing}
        />

        {currentTab === 'command-center' && (
          <CommandCenter
            readiness={readiness}
            events={events}
            alerts={alerts}
            collectorStatus={collectorStatus}
            activeCase={activeCase}
            onNavigate={setCurrentTab}
          />
        )}

        {currentTab === 'readiness' && (
          <ForensicReadiness
            readiness={readiness}
            onRefresh={loadData}
          />
        )}

        {currentTab === 'detection' && (
          <ThreatIntelligence
            alerts={alerts}
            techniques={techniques}
            onNavigateToInvestigation={() => setCurrentTab('investigation')}
          />
        )}

        {currentTab === 'prioritization' && (
          <EvidencePrioritization />
        )}

        {currentTab === 'investigation' && (
          <IncidentInvestigation
            activeCase={activeCase}
            onRefresh={loadData}
            onNavigateToVault={() => setCurrentTab('vault')}
          />
        )}

        {currentTab === 'vault' && (
          <EvidenceVault
            vaultItems={vaultItems}
            activeCase={activeCase}
            events={events}
            onRefresh={loadData}
          />
        )}

        {currentTab === 'evaluation' && (
          <ResearchEvaluation />
        )}
      </div>
    </div>
  );
};

export default App;
