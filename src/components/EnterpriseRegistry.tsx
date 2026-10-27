import React, { useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Building,
  CheckCircle2,
  Download,
  Edit3,
  MapPin,
  Plus,
  Radio,
  Search,
  Trash2,
  Upload,
  UserCheck,
  X
} from 'lucide-react';
import { EnterpriseAssetRecord, UIMode } from '../types';
import {
  ASSET_APPROVAL_STATUSES,
  ASSET_CLASSIFICATIONS,
  ASSET_TYPES,
  formatUtcTimestamp,
  newAssetId,
  normalizeAsset
} from '../services/assetRegistry';

export interface AssetImportSummary {
  imported: number;
  rejected: number;
  warnings: string[];
  message: string;
}

interface EnterpriseRegistryProps {
  assets: EnterpriseAssetRecord[];
  bridgeConnected: boolean;
  uiMode: UIMode;
  onSaveAsset: (asset: EnterpriseAssetRecord) => Promise<void>;
  onDeleteAsset: (macAddress: string) => Promise<void>;
  onImportCsv: (csv: string) => Promise<AssetImportSummary>;
  onExportCsv: () => void;
  onShowNetworks: () => void;
  onManageScope: () => void;
}

const EMPTY_ASSET = (): EnterpriseAssetRecord => ({
  id: newAssetId(),
  macAddress: '',
  ssid: '',
  assetType: 'Access Point',
  classification: 'Unknown',
  approvalStatus: 'Pending Review',
  site: '',
  building: '',
  areaFloor: '',
  ownerDepartment: '',
  vendor: '',
  model: '',
  lastSeen: formatUtcTimestamp(new Date()),
  notes: ''
});

const approvalStyles: Record<string, string> = {
  Approved: 'text-emerald-400',
  Unapproved: 'text-rose-400',
  'Under Investigation': 'text-amber-400',
  Decommissioned: 'text-slate-400',
  'Pending Review': 'text-slate-400'
};

const classificationStyles: Record<string, string> = {
  Corporate: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  Guest: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  IoT: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  Suspicious: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  Rogue: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
  Unknown: 'bg-slate-700/60 text-slate-300 border-slate-600'
};

export const EnterpriseRegistry: React.FC<EnterpriseRegistryProps> = ({
  assets,
  bridgeConnected,
  uiMode,
  onSaveAsset,
  onDeleteAsset,
  onImportCsv,
  onExportCsv,
  onShowNetworks,
  onManageScope
}) => {
  const [search, setSearch] = useState('');
  const [classificationFilter, setClassificationFilter] = useState('all');
  const [approvalFilter, setApprovalFilter] = useState('all');
  const [draft, setDraft] = useState<EnterpriseAssetRecord | null>(null);
  const [editingIsNew, setEditingIsNew] = useState(false);
  const [formError, setFormError] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: 'ok' | 'warn' | 'error'; text: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return assets.filter(asset => {
      if (classificationFilter !== 'all' && asset.classification !== classificationFilter) return false;
      if (approvalFilter !== 'all' && asset.approvalStatus !== approvalFilter) return false;
      if (!term) return true;
      return [asset.ssid, asset.macAddress, asset.vendor, asset.model, asset.site, asset.building, asset.areaFloor, asset.ownerDepartment, asset.notes]
        .some(value => (value || '').toLowerCase().includes(term));
    });
  }, [assets, search, classificationFilter, approvalFilter]);

  const openNew = () => {
    setDraft(EMPTY_ASSET());
    setEditingIsNew(true);
    setFormError('');
  };

  const openEdit = (asset: EnterpriseAssetRecord) => {
    setDraft({ ...asset });
    setEditingIsNew(false);
    setFormError('');
  };

  const handleSave = async () => {
    if (!draft) return;
    const normalized = normalizeAsset(draft);
    if (!normalized.asset) {
      setFormError(normalized.error || 'The asset record is invalid.');
      return;
    }
    setBusy(true);
    setFormError('');
    try {
      await onSaveAsset(normalized.asset);
      setDraft(null);
      setNotice({ tone: 'ok', text: `Saved ${normalized.asset.macAddress} to the project registry.` });
    } catch (err: any) {
      setFormError(err?.message || 'The registry record could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const handleDelete = async (asset: EnterpriseAssetRecord) => {
    const confirmed = window.confirm(
      `Delete the registry record for ${asset.macAddress} (${asset.ssid || 'no SSID'})?\n\n` +
      'This removes its approval and classification from this project. Captured evidence and incidents are not deleted.'
    );
    if (!confirmed) return;
    setBusy(true);
    try {
      await onDeleteAsset(asset.macAddress);
      setNotice({ tone: 'ok', text: `Removed ${asset.macAddress} from the project registry.` });
    } catch (err: any) {
      setNotice({ tone: 'error', text: err?.message || 'The registry record could not be deleted.' });
    } finally {
      setBusy(false);
    }
  };

  const handleFile = async (file: File | null) => {
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      setNotice({ tone: 'error', text: 'CSV files larger than 2 MB are rejected.' });
      return;
    }
    setBusy(true);
    try {
      const text = await file.text();
      const summary = await onImportCsv(text);
      setNotice({
        tone: summary.rejected > 0 || summary.warnings.length > 0 ? 'warn' : 'ok',
        text: summary.message
      });
    } catch (err: any) {
      setNotice({ tone: 'error', text: err?.message || 'The CSV could not be imported.' });
    } finally {
      setBusy(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const field = (label: string, key: keyof EnterpriseAssetRecord, placeholder: string, type: 'text' | 'textarea' = 'text') => (
    <label className="space-y-1 block">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</span>
      {type === 'textarea' ? (
        <textarea
          value={String(draft?.[key] ?? '')}
          onChange={event => setDraft(current => current ? { ...current, [key]: event.target.value } : current)}
          placeholder={placeholder}
          rows={3}
          className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
        />
      ) : (
        <input
          type="text"
          value={String(draft?.[key] ?? '')}
          onChange={event => setDraft(current => current ? { ...current, [key]: event.target.value } : current)}
          placeholder={placeholder}
          className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
        />
      )}
    </label>
  );

  return (
    <div className="space-y-5 pb-8">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-1 bg-slate-800/70 rounded-lg p-1">
            <button
              onClick={onShowNetworks}
              className="px-3 py-1.5 rounded text-xs font-semibold text-slate-400 hover:text-slate-200 flex items-center gap-1.5"
            >
              <Radio className="w-3.5 h-3.5" /> Network Inventory
            </button>
            <button className="px-3 py-1.5 rounded bg-slate-700 text-white text-xs font-semibold flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5" /> Enterprise Registry ({assets.length})
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={event => void handleFile(event.target.files?.[0] ?? null)}
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={busy}
              className="px-2.5 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" /> Import CSV
            </button>
            <button
              onClick={onExportCsv}
              disabled={assets.length === 0}
              className="px-2.5 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50 flex items-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>
            <button
              onClick={openNew}
              className="px-2.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" /> Add asset
            </button>
          </div>
        </div>

        <div className="flex flex-col md:flex-row md:items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search MAC, SSID, site, owner, vendor, or notes..."
              className="w-full pl-10 pr-4 py-2 bg-slate-800/80 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <select
            value={classificationFilter}
            onChange={event => setClassificationFilter(event.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 text-xs focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Classifications</option>
            {ASSET_CLASSIFICATIONS.map(value => <option key={value} value={value}>{value}</option>)}
          </select>
          <select
            value={approvalFilter}
            onChange={event => setApprovalFilter(event.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-300 rounded-lg px-2.5 py-2 text-xs focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Approvals</option>
            {ASSET_APPROVAL_STATUSES.map(value => <option key={value} value={value}>{value}</option>)}
          </select>
          <span className="text-[11px] font-mono text-slate-400 px-2 py-1 bg-slate-800 rounded">
            {filtered.length} of {assets.length}
          </span>
        </div>

        <div className="text-[11px] text-slate-500 flex flex-wrap items-center gap-2">
          <span className={`px-2 py-0.5 rounded border ${bridgeConnected ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-amber-500/30 bg-amber-500/10 text-amber-300'}`}>
            {bridgeConnected ? 'SYNCED TO PROJECT SQLITE' : 'OFFLINE LOCAL CACHE'}
          </span>
          <span>
            {bridgeConnected
              ? 'Approval and classification changes are written to the native project database and apply to matching BSSIDs.'
              : 'The Windows bridge is offline. Changes are cached locally for this project and can be saved once it reconnects.'}
          </span>
          <button onClick={onManageScope} className="text-blue-400 hover:text-blue-300 underline underline-offset-2">
            Open project settings
          </button>
        </div>

        {notice && (
          <div className={`text-xs rounded-lg border px-3 py-2 ${
            notice.tone === 'ok'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
              : notice.tone === 'warn'
                ? 'border-amber-500/30 bg-amber-500/10 text-amber-200'
                : 'border-rose-500/30 bg-rose-500/10 text-rose-200'
          }`}>
            <div className="flex items-start justify-between gap-3">
              <span className="whitespace-pre-line">{notice.text}</span>
              <button onClick={() => setNotice(null)} className="text-current opacity-70 hover:opacity-100"><X className="w-3.5 h-3.5" /></button>
            </div>
          </div>
        )}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-800/80 text-slate-400 font-semibold uppercase tracking-wider text-[10px] border-b border-slate-700/80">
              <tr>
                <th className="py-3 px-4">Asset Identity</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Approval</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Owner / Department</th>
                <th className="py-3 px-4">Vendor / Model</th>
                <th className="py-3 px-4">Last Seen</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-200">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-10 px-6 text-center text-slate-500">
                    <div className="font-semibold text-slate-300 mb-1">
                      {assets.length === 0 ? 'No enterprise assets registered in this project.' : 'No registry assets match the current filters.'}
                    </div>
                    <div className="text-[11px] mb-3">
                      {assets.length === 0
                        ? 'Add a MAC address manually or import a CSV with a macAddress column. Records are keyed by MAC, so re-importing updates instead of duplicating.'
                        : 'Adjust the search or filters to see other records.'}
                    </div>
                    {assets.length === 0 && (
                      <button onClick={openNew} className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold">
                        Add the first asset
                      </button>
                    )}
                  </td>
                </tr>
              ) : filtered.map(asset => (
                <tr key={asset.macAddress} className="hover:bg-slate-800/40 transition-colors align-top">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-100">{asset.ssid || '[No SSID recorded]'}</div>
                    <div className="text-[11px] font-mono text-slate-400">{asset.macAddress}</div>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{asset.assetType}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${classificationStyles[asset.classification] || classificationStyles.Unknown}`}>
                      {asset.classification}
                    </span>
                  </td>
                  <td className={`py-3 px-4 font-medium ${approvalStyles[asset.approvalStatus] || 'text-slate-400'}`}>
                    {asset.approvalStatus === 'Approved' && <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" />}
                    {asset.approvalStatus === 'Under Investigation' && <AlertTriangle className="w-3.5 h-3.5 inline mr-1" />}
                    {asset.approvalStatus}
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    <div className="flex items-start gap-1"><MapPin className="w-3.5 h-3.5 mt-0.5 text-slate-500" />{asset.site || 'Not set'}</div>
                    <div className="text-[11px] text-slate-500 flex items-start gap-1">
                      <Building className="w-3 h-3 mt-0.5" />
                      {asset.building || 'Not set'}{asset.areaFloor ? ` · ${asset.areaFloor}` : ''}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-slate-300">{asset.ownerDepartment || <span className="text-slate-600 italic">Not assigned</span>}</td>
                  <td className="py-3 px-4 text-slate-300">
                    <div>{asset.vendor || 'Unknown vendor'}</div>
                    <div className="text-[11px] text-slate-500">{asset.model || 'Model not recorded'}</div>
                  </td>
                  <td className="py-3 px-4 text-[11px] font-mono text-slate-400">{asset.lastSeen}</td>
                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => openEdit(asset)}
                        title="Edit registry record"
                        className="p-1.5 rounded hover:bg-slate-700/60 text-slate-400 hover:text-slate-200"
                      >
                        <Edit3 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => void handleDelete(asset)}
                        title="Delete registry record"
                        className="p-1.5 rounded hover:bg-rose-900/40 text-slate-400 hover:text-rose-300"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {draft && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl my-8 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">{editingIsNew ? 'Register enterprise asset' : 'Edit registry record'}</h3>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  MAC addresses are canonicalized and used as the project-scoped identity. Blank fields stay blank; nothing is inferred.
                </p>
              </div>
              <button onClick={() => setDraft(null)} className="text-slate-400 hover:text-slate-200"><X className="w-5 h-5" /></button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {field('MAC / BSSID *', 'macAddress', 'AA:BB:CC:DD:EE:FF')}
                {field('SSID', 'ssid', 'Network name')}
                <label className="space-y-1 block">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Asset type</span>
                  <select
                    value={draft.assetType}
                    onChange={event => setDraft({ ...draft, assetType: event.target.value as EnterpriseAssetRecord['assetType'] })}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    {ASSET_TYPES.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
                <label className="space-y-1 block">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Classification</span>
                  <select
                    value={draft.classification}
                    onChange={event => setDraft({ ...draft, classification: event.target.value as EnterpriseAssetRecord['classification'] })}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    {ASSET_CLASSIFICATIONS.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
                <label className="space-y-1 block">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Approval status</span>
                  <select
                    value={draft.approvalStatus}
                    onChange={event => setDraft({ ...draft, approvalStatus: event.target.value as EnterpriseAssetRecord['approvalStatus'] })}
                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    {ASSET_APPROVAL_STATUSES.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
                {field('Site', 'site', 'Optional site name')}
                {field('Building', 'building', 'Optional building')}
                {field('Area / Floor', 'areaFloor', 'Optional floor or area')}
                {field('Owner / Department', 'ownerDepartment', 'Optional responsible team')}
                {field('Vendor', 'vendor', 'Optional hardware vendor')}
                {field('Model', 'model', 'Optional model or role')}
                {field('Last seen (UTC)', 'lastSeen', 'YYYY-MM-DD HH:MM:SS')}
              </div>
              {field('Notes', 'notes', 'Optional analyst notes. Multi-line text is supported.', 'textarea')}

              {formError && (
                <div className="text-xs text-rose-300 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{formError}</div>
              )}

              <div className="flex items-center justify-between border-t border-slate-800 pt-3">
                <span className="text-[11px] text-slate-500">
                  {uiMode === 'beginner' ? 'Approval affects how WinWiFi scores matching BSSIDs.' : 'Registry values override analyst overrides for matching BSSIDs.'}
                </span>
                <div className="flex items-center gap-2">
                  <button onClick={() => setDraft(null)} className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800">
                    Cancel
                  </button>
                  <button
                    onClick={() => void handleSave()}
                    disabled={busy}
                    className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold"
                  >
                    {busy ? 'Saving...' : 'Save record'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
