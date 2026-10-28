import React, { useState } from 'react';
import { 
  User, 
  FileText, 
  Send, 
  Search
} from 'lucide-react';
import { AccessPoint, EvidenceItem, IncidentRecord, UIMode } from '../types';
import { ThreatEngine } from '../services/threatEngine';
import { countOpenIncidents } from '../services/incidentMapper';

interface IncidentCenterProps {
  incidents: IncidentRecord[];
  evidenceItems: EvidenceItem[];
  accessPoints: AccessPoint[];
  uiMode: UIMode;
  onRefreshIncidents: () => void;
  onAddEvidence: (incidentId: string, evidence: EvidenceItem) => void;
}

export const IncidentCenter: React.FC<IncidentCenterProps> = ({
  incidents = [],
  evidenceItems = [],
  accessPoints = [],
  uiMode,
  onRefreshIncidents,
  onAddEvidence
}) => {
  const threatEngine = ThreatEngine.getInstance();
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(incidents[0]?.id || '');
  const [noteText, setNoteText] = useState('');
  const [resolutionText, setResolutionText] = useState('');
  const [isResolving, setIsResolving] = useState(false);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [showEvidenceForm, setShowEvidenceForm] = useState(false);
  const [evidenceTitle, setEvidenceTitle] = useState('');
  const [evidenceDescription, setEvidenceDescription] = useState('');
  const [evidenceType, setEvidenceType] = useState<EvidenceItem['type']>('note');

  const selectedIncident = incidents.find(i => i.id === selectedIncidentId) || incidents[0];
  const openCaseCount = countOpenIncidents(incidents);
  const targetAccessPoint = selectedIncident?.bssidTarget
    ? accessPoints.find(ap => ap.bssid.toUpperCase() === selectedIncident.bssidTarget?.toUpperCase())
    : undefined;

  const handleAddEvidence = () => {
    if (!selectedIncident || !evidenceTitle.trim() || !evidenceDescription.trim()) return;
    onAddEvidence(selectedIncident.id, {
      id: `EVD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: evidenceType,
      title: evidenceTitle.trim(),
      source: selectedIncident.bssidTarget || selectedIncident.id,
      description: evidenceDescription.trim()
    });
    setEvidenceTitle('');
    setEvidenceDescription('');
    setShowEvidenceForm(false);
  };

  const handleAttachTargetSnapshot = () => {
    if (!selectedIncident || !targetAccessPoint) return;
    onAddEvidence(selectedIncident.id, {
      id: `EVD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: 'observation',
      title: `Observed AP snapshot: ${targetAccessPoint.ssid || targetAccessPoint.bssid}`,
      source: targetAccessPoint.dataSourceOrigin || 'Saved observation',
      description: `SSID ${targetAccessPoint.ssid || '[Hidden SSID]'}, BSSID ${targetAccessPoint.bssid}, channel ${targetAccessPoint.channel} (${targetAccessPoint.band}), ${targetAccessPoint.security}, ${targetAccessPoint.rssi} dBm.`,
      rawData: JSON.stringify(targetAccessPoint, null, 2)
    });
  };

  const handleAddNote = () => {
    if (!noteText.trim() || !selectedIncident) return;
    if (!selectedIncident.notes) selectedIncident.notes = [];
    selectedIncident.notes.push({
      timestamp: new Date().toLocaleTimeString(),
      author: 'Lead Auditor',
      text: noteText.trim()
    });
    selectedIncident.updatedAt = new Date().toISOString();
    setNoteText('');
    onRefreshIncidents();
  };

  const handleUpdateStatus = (newStatus: IncidentRecord['status']) => {
    if (!selectedIncident) return;
    threatEngine.updateIncidentStatus(selectedIncident.id, newStatus, resolutionText);
    setIsResolving(false);
    setResolutionText('');
    onRefreshIncidents();
  };

  const filteredIncidents = incidents.filter(i => {
    if (filterStatus !== 'all' && i.status !== filterStatus) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        i.id.toLowerCase().includes(q) ||
        i.title.toLowerCase().includes(q) ||
        (i.bssidTarget && i.bssidTarget.toLowerCase().includes(q)) ||
        (i.ssidTarget && i.ssidTarget.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const getStatusBadge = (status: IncidentRecord['status']) => {
    switch (status) {
      case 'Open':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">Open</span>;
      case 'Investigating':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">Investigating</span>;
      case 'Confirmed':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/30">Confirmed Threat</span>;
      case 'Resolved':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Resolved</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-700 text-slate-300">False Positive</span>;
    }
  };

  return (
    <div className="space-y-5 pb-8">
      {/* Top Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-purple-500/15 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-slate-100">Wireless Incident Investigation Center · {openCaseCount} open</h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Defensive incident management tracking triage, evidence trails, auditor notes, and verified remediations.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Incident Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Confirmed">Confirmed</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Incident Case List & Active Case Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Incident List (4 cols) */}
        <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col h-[640px]">
          <div className="p-3 border-b border-slate-800 bg-slate-800/40">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search case #, SSID, BSSID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="overflow-y-auto flex-1 divide-y divide-slate-800/60 text-xs">
            {filteredIncidents.length === 0 ? (
              <div className="p-6 text-center text-slate-500">No matching incident cases.</div>
            ) : (
              filteredIncidents.map(inc => {
                const isSelected = selectedIncident?.id === inc.id;

                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncidentId(inc.id)}
                    className={`p-3.5 cursor-pointer transition-colors ${
                      isSelected ? 'bg-blue-500/10 border-l-2 border-blue-500' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-slate-200">{inc.id}</span>
                      {getStatusBadge(inc.status)}
                    </div>
                    <div className="font-semibold text-slate-100 mt-1 line-clamp-1">{inc.title}</div>
                    <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                      <span>Conf: {inc.confidence}%</span>
                      <span>{new Date(inc.createdAt).toLocaleDateString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right: Selected Case Details (8 cols) */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col h-[640px] overflow-y-auto space-y-4">
          {selectedIncident ? (
            <>
              {/* Case Header */}
              <div className="border-b border-slate-800 pb-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {selectedIncident.id}
                    </span>
                    <span className="text-xs text-slate-500">•</span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                      selectedIncident.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'
                    }`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="text-xs text-slate-400">Confidence: <strong>{selectedIncident.confidence}%</strong></span>
                  </div>

                  {/* Status Dropdown */}
                  <div className="flex items-center gap-2">
                    <select
                      value={selectedIncident.status}
                      onChange={(e) => handleUpdateStatus(e.target.value as IncidentRecord['status'])}
                      className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-blue-500"
                    >
                      <option value="Open">Open</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Confirmed">Confirmed</option>
                      <option value="False Positive">False Positive</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                </div>

                <h2 className="text-base font-bold text-slate-100 mt-2">{selectedIncident.title}</h2>
                <p className="text-xs text-slate-400 mt-1">{selectedIncident.summary}</p>

                <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400 mt-3 pt-3 border-t border-slate-800/80">
                  <span>Assigned: <strong className="text-slate-200">{selectedIncident.assignedTo}</strong></span>
                  <span>Target BSSID: <strong className="text-slate-200 font-mono">{selectedIncident.bssidTarget || 'N/A'}</strong></span>
                  <span>SSID: <strong className="text-slate-200">{selectedIncident.ssidTarget || 'N/A'}</strong></span>
                </div>
              </div>

              {/* Linked evidence records */}
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider text-[10px]">Case Evidence Records</div>
                  <div className="flex gap-2">
                    <button disabled={!targetAccessPoint} onClick={handleAttachTargetSnapshot} title={targetAccessPoint ? 'Attach the currently loaded target AP observation' : 'Load an observation for this incident target first'} className="rounded border border-slate-700 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-800 disabled:opacity-40">Attach target snapshot</button>
                    <button onClick={() => setShowEvidenceForm(value => !value)} className="rounded bg-blue-600 px-2 py-1 text-[10px] font-semibold text-white hover:bg-blue-500">Add evidence</button>
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {(selectedIncident.evidenceIds || []).map(evId => {
                    const evidence = evidenceItems.find(item => item.id === evId);
                    return <div key={evId} className="rounded-lg border border-slate-700/60 bg-slate-800/60 p-2.5 text-xs">
                      <div className="flex items-center justify-between gap-2"><span className="flex items-center gap-2"><FileText className="h-3.5 w-3.5 text-blue-400" /><span className="font-mono text-slate-200">{evId}</span></span><span className="text-[10px] uppercase text-slate-400">{evidence?.type || 'unresolved'}</span></div>
                      <div className="mt-1 font-medium text-slate-200">{evidence?.title || 'Legacy evidence reference'}</div>
                      <p className="mt-1 text-slate-400">{evidence?.description || 'No stored evidence details are available for this reference.'}</p>
                      {evidence?.rawData && <details className="mt-2"><summary className="cursor-pointer text-blue-300">View captured observation</summary><pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap text-[10px] text-slate-300">{evidence.rawData}</pre></details>}
                    </div>;
                  })}
                  {selectedIncident.evidenceIds?.length === 0 && <p className="text-[11px] text-slate-500">No evidence has been attached to this case.</p>}
                </div>
                {showEvidenceForm && <form onSubmit={event => { event.preventDefault(); handleAddEvidence(); }} className="grid grid-cols-1 gap-2 rounded-lg border border-slate-700 bg-slate-900/70 p-3 sm:grid-cols-2">
                  <input required value={evidenceTitle} onChange={event => setEvidenceTitle(event.target.value)} placeholder="Evidence title" className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-100" />
                  <select value={evidenceType} onChange={event => setEvidenceType(event.target.value as EvidenceItem['type'])} className="rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-100"><option value="note">Analyst note</option><option value="observation">Observation</option><option value="pcap">PCAP reference</option><option value="packet">Packet reference</option><option value="handshake">Handshake reference</option><option value="timeline">Timeline record</option></select>
                  <textarea required value={evidenceDescription} onChange={event => setEvidenceDescription(event.target.value)} placeholder="Describe the evidence and how it was collected" className="min-h-16 rounded border border-slate-700 bg-slate-800 px-2 py-1.5 text-xs text-slate-100 sm:col-span-2" />
                  <div className="flex justify-end gap-2 sm:col-span-2"><button type="button" onClick={() => setShowEvidenceForm(false)} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300">Cancel</button><button type="submit" className="rounded bg-blue-600 px-3 py-1.5 text-xs font-semibold text-white">Save evidence</button></div>
                </form>}
              </div>

              {/* Auditor Notes & Timeline */}
              <div className="flex-1 space-y-3">
                <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider text-[10px]">
                  Investigation Audit Trail & Notes
                </div>

                <div className="space-y-2 max-h-[160px] overflow-y-auto pr-1">
                  {(selectedIncident.notes || []).map((note, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-slate-400">
                        <span className="font-semibold text-slate-300 flex items-center gap-1">
                          <User className="w-3 h-3 text-purple-400" /> {note.author}
                        </span>
                        <span>{note.timestamp}</span>
                      </div>
                      <p className="text-slate-300">{note.text}</p>
                    </div>
                  ))}
                </div>

                {/* Add Note Box */}
                <div className="flex items-center gap-2 pt-2">
                  <input
                    type="text"
                    placeholder="Append forensic observation or remediation note..."
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddNote()}
                    className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={handleAddNote}
                    className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1 transition-colors"
                  >
                    <Send className="w-3.5 h-3.5" /> Append Note
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full text-slate-500 text-xs">
              Select an incident case from the left panel to inspect.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
