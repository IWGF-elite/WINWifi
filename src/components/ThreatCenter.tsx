import React, { useEffect, useState } from 'react';
import { 
  Flame, 
  CheckCircle2, 
  Check, 
  X, 
  ArrowRight, 
  Clock, 
  FileText
} from 'lucide-react';
import { AccessPoint, AnalystClassification, IncidentRecord, SecurityChange, UIMode, ActiveTab } from '../types';
import { countOpenIncidents } from '../services/incidentMapper';
import { isSuspiciousAccessPoint } from '../services/threatMetrics';

interface ThreatCenterProps {
  accessPoints: AccessPoint[];
  incidents?: IncidentRecord[];
  securityChanges: SecurityChange[];
  uiMode: UIMode;
  onNavigate: (tab: ActiveTab, filterParam?: string) => void;
  onSelectAP: (ap: AccessPoint) => void;
  onRefreshThreats: () => void;
  onClassifyAP: (bssid: string, status: AnalystClassification) => void;
}

const EMPTY_ACCESS_POINTS: AccessPoint[] = [];

export const ThreatCenter: React.FC<ThreatCenterProps> = ({
  accessPoints = EMPTY_ACCESS_POINTS,
  incidents = [],
  securityChanges = [],
  uiMode,
  onNavigate,
  onSelectAP,
  onRefreshThreats,
  onClassifyAP
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'rogues' | 'changes'>('rogues');
  const [analysis, setAnalysis] = useState<{ at: number; count: number } | null>(null);

  useEffect(() => {
    setAnalysis({ at: Date.now(), count: accessPoints.length });
  }, [accessPoints]);

  // Filter rogue candidates
  const rogueAPs = accessPoints.filter(isSuspiciousAccessPoint);
  const openCases = countOpenIncidents(incidents);

  const handleAnalystOverride = (bssid: string, status: 'Trusted' | 'False Positive' | 'Confirmed Rogue') => {
    onClassifyAP(bssid, status);
    onRefreshThreats();
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400 shadow-inner">
              <Flame className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-slate-100">Wireless Threat & Anomaly Intelligence</h1>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300">
                  {rogueAPs.length} Suspicious APs Active
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Multi-factor defensive correlation analyzing SSID collisions, cryptographic downgrades, OUI anomalies, and historical drift.
              </p>
              <p className="mt-1 text-[10px] text-slate-500" aria-live="polite">
                {analysis ? `Last analyzed at ${new Date(analysis.at).toLocaleTimeString()}, ${analysis.count} APs checked` : 'No observations analyzed'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onNavigate('investigations')}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all flex items-center gap-1.5"
            >
              <FileText className="w-3.5 h-3.5" /> View Active Incident Cases ({openCases})
            </button>
          </div>
        </div>

        {/* Sub-tab Navigation */}
        <div className="flex items-center gap-2 mt-5 pt-3 border-t border-slate-800 text-xs font-medium">
          <button
            onClick={() => setActiveSubTab('rogues')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeSubTab === 'rogues'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="w-3.5 h-3.5" />
            <span>Rogue AP & Evil Twin Detections ({rogueAPs.length})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('changes')}
            className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ${
              activeSubTab === 'changes'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Security Change Intelligence ({securityChanges.length})</span>
          </button>
        </div>
      </div>

      {/* Sub-tab 1: Rogue APs */}
      {activeSubTab === 'rogues' && (
        <div className="space-y-4">
          {rogueAPs.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-10 text-center text-slate-400">
              <CheckCircle2 className="w-10 h-10 text-slate-500 mx-auto mb-3 opacity-80" />
              <h3 className="text-sm font-semibold text-slate-200">{accessPoints.length ? 'No suspicious access points in current observations' : 'No wireless observations to analyze'}</h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                {accessPoints.length
                  ? `Checked ${accessPoints.length} observed access point${accessPoints.length === 1 ? '' : 's'}. This result does not confirm authorization or safety.`
                  : 'Start a scan or import a capture to analyze observed access points.'}
              </p>
              {!accessPoints.length && <button onClick={() => onNavigate('networks')} className="mt-3 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white">Open Networks</button>}
            </div>
          ) : (
            rogueAPs.map(ap => (
              <div 
                key={ap.bssid}
                className="bg-slate-900 border border-rose-500/30 rounded-xl p-5 shadow-sm space-y-4"
              >
                <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center gap-2.5">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 uppercase">
                        {ap.classification === 'Rogue' ? 'CONFIRMED ROGUE' : 'SUSPECTED EVIL TWIN'}
                      </span>
                      <h2 className="text-base font-bold text-slate-100">"{ap.ssid}"</h2>
                      <span className="text-xs font-mono text-slate-400">({ap.bssid})</span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1 flex items-center gap-3">
                      <span>Hardware: <strong className="text-slate-200">{ap.vendor}</strong></span>
                      <span>•</span>
                      <span>Channel: <strong className="text-slate-200">Ch {ap.channel} ({ap.band})</strong></span>
                      <span>•</span>
                      <span>Signal: <strong className="text-slate-200">{ap.rssi} dBm</strong></span>
                    </div>
                  </div>

                  {/* Confidence Rating Gauge */}
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="text-xs text-slate-400 font-medium">Threat Confidence</div>
                      <div className="text-xl font-bold text-rose-400">
                        {typeof ap.rogueConfidence === 'number' ? `${ap.rogueConfidence}%` : 'Not scored'}
                      </div>
                    </div>

                    {/* Analyst Override Action Buttons */}
                    <div className="flex items-center gap-1.5 text-xs">
                      <button
                        onClick={() => handleAnalystOverride(ap.bssid, 'Trusted')}
                        title="Mark this network as an approved organizational AP"
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-emerald-500/20 text-slate-300 hover:text-emerald-300 border border-slate-700 transition-colors flex items-center gap-1"
                      >
                        <Check className="w-3.5 h-3.5" /> Approve
                      </button>
                      <button
                        onClick={() => handleAnalystOverride(ap.bssid, 'False Positive')}
                        title="Dismiss alert as benign beacon divergence"
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-amber-500/20 text-slate-300 hover:text-amber-300 border border-slate-700 transition-colors flex items-center gap-1"
                      >
                        <X className="w-3.5 h-3.5" /> False Positive
                      </button>
                      <button
                        onClick={() => handleAnalystOverride(ap.bssid, 'Confirmed Rogue')}
                        title="Escalate to confirmed rogue AP"
                        className="px-2.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-semibold shadow-sm transition-colors flex items-center gap-1"
                      >
                        <Flame className="w-3.5 h-3.5" /> Confirm Rogue
                      </button>
                    </div>
                  </div>
                </div>

                {/* Evidence Breakdown */}
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider text-[10px]">
                    Multi-Factor Forensic Evidence
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    {(ap.rogueEvidence && ap.rogueEvidence.length > 0 ? ap.rogueEvidence : [
                      'No multi-signal evidence was recorded for this transmitter. Review the beacon details before classifying it.'
                    ]).map((ev, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300 flex items-start gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 flex-shrink-0" />
                        <span>{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Footer Action */}
                <div className="flex items-center justify-between pt-2 text-xs">
                  <span className="text-slate-500">First observed: {ap.firstSeen} • Last seen: {ap.lastSeen}</span>
                  <button
                    onClick={() => onSelectAP(ap)}
                    className="text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1"
                  >
                    Deep 802.11 Frame Analysis <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Sub-tab 2: Security Changes */}
      {activeSubTab === 'changes' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Dynamic Security Change Audit Stream
            </h3>
            <span className="text-xs text-slate-500">Chronological state transitions</span>
          </div>

          <div className="divide-y divide-slate-800/60 text-xs">
            {securityChanges.length === 0 ? (
              <div className="py-8 text-center text-slate-500">
                No state shifts or parameter changes recorded during this session.
              </div>
            ) : (
              securityChanges.map(chg => (
                <div key={chg.id} className="p-4 hover:bg-slate-800/30 transition-colors flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                        chg.riskImpact === 'CRITICAL' 
                          ? 'bg-rose-500/20 text-rose-300' 
                          : chg.riskImpact === 'HIGH' 
                            ? 'bg-amber-500/20 text-amber-300' 
                            : 'bg-blue-500/20 text-blue-300'
                      }`}>
                        {chg.riskImpact}
                      </span>
                      <span className="font-semibold text-slate-100">{chg.title}</span>
                      <span className="text-slate-500 font-mono">• "{chg.ssid}" ({chg.bssid})</span>
                    </div>

                    <div className="text-slate-300 flex items-center gap-2 pt-1 font-mono text-[11px]">
                      <span className="text-slate-400 line-through">{chg.before}</span>
                      <ArrowRight className="w-3 h-3 text-blue-400" />
                      <span className="text-slate-100 font-semibold">{chg.after}</span>
                    </div>
                  </div>

                  <div className="text-right text-[11px] text-slate-500 font-mono flex-shrink-0">
                    {chg.timestamp}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
