import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  Tag, 
  Building, 
  CheckCircle2, 
  XCircle, 
  ShieldAlert, 
  Edit3, 
  Plus, 
  Check, 
  Shield, 
  Lock, 
  Radio, 
  AlertTriangle,
  Eye,
  SlidersHorizontal
} from 'lucide-react';
import { AccessPoint, AssetClassification, UIMode } from '../types';

interface AssetInventoryProps {
  accessPoints: AccessPoint[];
  uiMode: UIMode;
  initialFilter?: string;
  onSelectAP: (ap: AccessPoint) => void;
  onUpdateAP: (ap: AccessPoint) => void;
}

export const AssetInventory: React.FC<AssetInventoryProps> = ({
  accessPoints = [],
  uiMode,
  initialFilter = '',
  onSelectAP,
  onUpdateAP
}) => {
  const [searchTerm, setSearchTerm] = useState(initialFilter);
  const [classificationFilter, setClassificationFilter] = useState<string>('all');
  const [approvalFilter, setApprovalFilter] = useState<string>('all');
  const [selectedTag, setSelectedTag] = useState<string>('all');
  const [editingBssid, setEditingBssid] = useState<string | null>(null);

  // Form states for editing metadata
  const [editClassification, setEditClassification] = useState<AssetClassification>('Unknown');
  const [editApproval, setEditApproval] = useState<AccessPoint['approvedStatus']>('Pending Review');
  const [editOwnership, setEditOwnership] = useState('');
  const [editSite, setEditSite] = useState('');
  const [editBuilding, setEditBuilding] = useState('');
  const [editFloor, setEditFloor] = useState('');
  const [editTags, setEditTags] = useState('');
  const [editNotes, setEditNotes] = useState('');

  // Collect all unique tags
  const allTags = Array.from(new Set((accessPoints || []).flatMap(ap => ap.tags || [])));

  // Filtered APs
  const filtered = (accessPoints || []).filter(ap => {
    // Quick keyword matching for smart search
    const lowerSearch = searchTerm.toLowerCase().trim();
    if (lowerSearch) {
      if (lowerSearch === 'rogue' && !ap.isRogueCandidate && ap.classification !== 'Rogue') return false;
      if (lowerSearch === 'critical' && !(ap.issues || []).some(i => i.severity === 'CRITICAL')) return false;
      if (lowerSearch === 'unknown' && ap.classification !== 'Unknown') return false;
      if (lowerSearch === 'approved' && ap.approvedStatus !== 'Approved') return false;
      if (lowerSearch === 'wps' && !ap.wpsEnabled) return false;
      if (lowerSearch === 'tkip' && !(ap.security || '').includes('TKIP') && ap.cipher !== 'TKIP') return false;
      if (lowerSearch === 'wep' && !(ap.security || '').includes('WEP') && ap.cipher !== 'WEP') return false;

      const matchGeneral = 
        (ap.ssid || '').toLowerCase().includes(lowerSearch) ||
        (ap.bssid || '').toLowerCase().includes(lowerSearch) ||
        (ap.vendor || '').toLowerCase().includes(lowerSearch) ||
        (ap.security || '').toLowerCase().includes(lowerSearch) ||
        (ap.tags && ap.tags.some(t => (t || '').toLowerCase().includes(lowerSearch))) ||
        (ap.site && ap.site.toLowerCase().includes(lowerSearch)) ||
        (ap.ownership && ap.ownership.toLowerCase().includes(lowerSearch));
      if (!matchGeneral) return false;
    }

    if (classificationFilter !== 'all' && ap.classification !== classificationFilter) return false;
    if (approvalFilter !== 'all' && ap.approvedStatus !== approvalFilter) return false;
    if (selectedTag !== 'all' && (!ap.tags || !ap.tags.includes(selectedTag))) return false;

    return true;
  });

  const handleStartEdit = (ap: AccessPoint) => {
    setEditingBssid(ap.bssid);
    setEditClassification(ap.classification || 'Unknown');
    setEditApproval(ap.approvedStatus || 'Pending Review');
    setEditOwnership(ap.ownership || '');
    setEditSite(ap.site || 'HQ Campus');
    setEditBuilding(ap.building || 'Building A');
    setEditFloor(ap.floor || 'Floor 1');
    setEditTags((ap.tags || []).join(', '));
    setEditNotes(ap.notes || '');
  };

  const handleSaveEdit = (ap: AccessPoint) => {
    const updated: AccessPoint = {
      ...ap,
      classification: editClassification,
      approvedStatus: editApproval,
      ownership: editOwnership,
      site: editSite,
      building: editBuilding,
      floor: editFloor,
      notes: editNotes,
      tags: editTags.split(',').map(t => t.trim()).filter(Boolean)
    };
    onUpdateAP(updated);
    setEditingBssid(null);
  };

  const getClassificationBadge = (cls?: AssetClassification) => {
    switch (cls) {
      case 'Corporate':
      case 'Trusted':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Trusted Corporate</span>;
      case 'Guest':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">Guest Network</span>;
      case 'IoT':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/30">IoT Endpoint</span>;
      case 'Rogue':
      case 'Suspicious':
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">Rogue / Suspicious</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-700/60 text-slate-300 border border-slate-600">Unknown Asset</span>;
    }
  };

  const getApprovalBadge = (status?: AccessPoint['approvedStatus']) => {
    switch (status) {
      case 'Approved':
        return <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" /> Approved</span>;
      case 'Unapproved':
        return <span className="flex items-center gap-1 text-[11px] font-medium text-rose-400"><XCircle className="w-3.5 h-3.5" /> Unapproved</span>;
      case 'Investigating':
        return <span className="flex items-center gap-1 text-[11px] font-medium text-amber-400"><AlertTriangle className="w-3.5 h-3.5" /> Investigating</span>;
      default:
        return <span className="flex items-center gap-1 text-[11px] font-medium text-slate-400">Pending Review</span>;
    }
  };

  return (
    <div className="space-y-5 pb-8">
      {/* Header with Search & Filters */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input 
              type="text"
              placeholder='Search networks, BSSID, vendor, "wps", "tkip", "rogue", or "critical"...'
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-800/80 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Classification Filter */}
            <select
              value={classificationFilter}
              onChange={(e) => setClassificationFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Classifications</option>
              <option value="Corporate">Corporate</option>
              <option value="Guest">Guest</option>
              <option value="IoT">IoT</option>
              <option value="Unknown">Unknown</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Rogue">Rogue</option>
            </select>

            {/* Approval Filter */}
            <select
              value={approvalFilter}
              onChange={(e) => setApprovalFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 focus:outline-none focus:border-blue-500"
            >
              <option value="all">All Approvals</option>
              <option value="Approved">Approved</option>
              <option value="Pending Review">Pending Review</option>
              <option value="Unapproved">Unapproved</option>
              <option value="Investigating">Investigating</option>
            </select>

            {/* Tag Filter */}
            {allTags.length > 0 && (
              <select
                value={selectedTag}
                onChange={(e) => setSelectedTag(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 focus:outline-none focus:border-blue-500"
              >
                <option value="all">All Tags</option>
                {allTags.map(tag => (
                  <option key={tag} value={tag}>{tag}</option>
                ))}
              </select>
            )}

            <div className="text-slate-400 font-mono text-[11px] px-2 py-1 bg-slate-800 rounded">
              {filtered.length} of {accessPoints.length} Assets
            </div>
          </div>
        </div>
      </div>

      {/* Assets Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/80 text-slate-400 font-semibold uppercase tracking-wider text-[10px] border-b border-slate-700/80">
              <tr>
                <th className="py-3 px-4">Network Identity / SSID</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Approval Status</th>
                <th className="py-3 px-4">Location / Site</th>
                <th className="py-3 px-4">Security Suite</th>
                <th className="py-3 px-4">Tags</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No wireless assets matched your search filters.
                  </td>
                </tr>
              ) : (
                filtered.map(ap => {
                  const isEditing = editingBssid === ap.bssid;

                  return (
                    <tr key={ap.bssid} className="hover:bg-slate-800/40 transition-colors">
                      {/* Identity */}
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-100 flex items-center gap-2">
                          <span>{ap.ssid || '[Hidden SSID]'}</span>
                          {ap.isRogueCandidate && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-400 font-bold">
                              ROGUE
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 flex items-center gap-2 mt-0.5">
                          <span>{ap.bssid}</span>
                          <span className="text-slate-600">•</span>
                          <span>{ap.vendor}</span>
                        </div>
                      </td>

                      {/* Classification */}
                      <td className="py-3 px-4">
                        {getClassificationBadge(ap.classification)}
                      </td>

                      {/* Approval */}
                      <td className="py-3 px-4">
                        {getApprovalBadge(ap.approvedStatus)}
                      </td>

                      {/* Location */}
                      <td className="py-3 px-4">
                        <div className="text-slate-300 font-medium">{ap.site || 'HQ Campus'}</div>
                        <div className="text-[11px] text-slate-500">
                          {ap.building || 'Building A'}{ap.floor ? ` - ${ap.floor}` : ''}
                        </div>
                      </td>

                      {/* Security */}
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">{ap.security}</div>
                        <div className="text-[11px] text-slate-400">
                          Ch {ap.channel} ({ap.band}) • {ap.cipher}
                        </div>
                      </td>

                      {/* Tags */}
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {ap.tags && ap.tags.length > 0 ? (
                            ap.tags.map(t => (
                              <span key={t} className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-300">
                                {t}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-600 italic text-[11px]">No tags</span>
                          )}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => onSelectAP(ap)}
                            title="Inspect 802.11 Technical Details"
                            className="p-1.5 rounded hover:bg-slate-700/60 text-slate-400 hover:text-blue-300 transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleStartEdit(ap)}
                            title="Edit Asset Metadata"
                            className="p-1.5 rounded hover:bg-slate-700/60 text-slate-400 hover:text-slate-200 transition-colors"
                          >
                            <Edit3 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Metadata Modal / Drawer */}
      {editingBssid && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <SlidersHorizontal className="w-4 h-4 text-blue-400" />
                Edit Wireless Asset Metadata
              </h3>
              <button 
                onClick={() => setEditingBssid(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 font-medium block mb-1">Asset Classification</label>
                <select
                  value={editClassification}
                  onChange={(e) => setEditClassification(e.target.value as AssetClassification)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="Corporate">Corporate (Enterprise Authorized)</option>
                  <option value="Guest">Guest (Visitor Public Network)</option>
                  <option value="IoT">IoT (Smart Devices / Scanners)</option>
                  <option value="Unknown">Unknown (Unclassified Transmitter)</option>
                  <option value="Suspicious">Suspicious (Anomaly Detected)</option>
                  <option value="Rogue">Rogue (Confirmed Rogue AP)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Approval Status</label>
                <select
                  value={editApproval}
                  onChange={(e) => setEditApproval(e.target.value as AccessPoint['approvedStatus'])}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="Approved">Approved</option>
                  <option value="Pending Review">Pending Review</option>
                  <option value="Unapproved">Unapproved</option>
                  <option value="Investigating">Investigating</option>
                </select>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="text-slate-400 font-medium block mb-1">Site</label>
                  <input
                    type="text"
                    value={editSite}
                    onChange={(e) => setEditSite(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-slate-400 font-medium block mb-1">Building</label>
                  <input
                    type="text"
                    value={editBuilding}
                    onChange={(e) => setEditBuilding(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-slate-400 font-medium block mb-1">Floor / Room</label>
                  <input
                    type="text"
                    value={editFloor}
                    onChange={(e) => setEditFloor(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Tags (Comma-separated)</label>
                <input
                  type="text"
                  value={editTags}
                  onChange={(e) => setEditTags(e.target.value)}
                  placeholder="e.g. Production, Floor-3, Cisco-Catalyst"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 font-medium block mb-1">Auditor Notes</label>
                <textarea
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  rows={3}
                  placeholder="Record asset observations or compliance notes..."
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2 text-slate-200"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-800 text-xs font-medium">
              <button
                onClick={() => setEditingBssid(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const ap = accessPoints.find(a => a.bssid === editingBssid);
                  if (ap) handleSaveEdit(ap);
                }}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-colors flex items-center gap-1.5"
              >
                <Check className="w-3.5 h-3.5" /> Save Changes
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
