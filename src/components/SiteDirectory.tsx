import React, { useState } from 'react';
import { Building2, MapPin, Layers, Plus, Pencil, Trash2, Check, X } from 'lucide-react';
import { EnterpriseAssetRecord, SiteRecord } from '../types';
import {
  addSite,
  renameSite,
  deleteSite,
  addBuilding,
  renameBuilding,
  deleteBuilding,
  addFloor,
  renameFloor,
  deleteFloor,
  sanitizeSiteName,
  countAssetsAtSite,
  countAssetsInBuilding,
  countAssetsOnFloor,
  renameSiteInAssets,
  renameBuildingInAssets,
  renameFloorInAssets
} from '../services/siteDirectory';
import type { SiteMutationResult } from '../services/siteDirectory';

interface SiteDirectoryProps {
  sites: SiteRecord[];
  assets: EnterpriseAssetRecord[];
  onChange: (sites: SiteRecord[], changedAssets: EnterpriseAssetRecord[]) => void;
}

type EditTarget = {
  kind: 'site' | 'building' | 'floor';
  siteId: string;
  buildingId?: string;
  floorId?: string;
  targetId: string;
  value: string;
};

type DeleteTarget = EditTarget & { label: string };

const inputClass = 'min-w-0 flex-1 rounded border border-slate-600 bg-slate-900 px-2 py-1 text-xs text-slate-100 focus:border-blue-500 focus:outline-none';
const iconButtonClass = 'rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-30';

const changedBetween = (before: EnterpriseAssetRecord[], after: EnterpriseAssetRecord[]): EnterpriseAssetRecord[] =>
  after.filter((asset, index) => asset !== before[index]);

export const SiteDirectory: React.FC<SiteDirectoryProps> = ({ sites, assets, onChange }) => {
  const [siteDraft, setSiteDraft] = useState('');
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [editing, setEditing] = useState<EditTarget | null>(null);
  const [pendingDelete, setPendingDelete] = useState<DeleteTarget | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const buildingCount = sites.reduce((sum, site) => sum + site.buildings.length, 0);
  const floorCount = sites.reduce((sum, site) =>
    sum + site.buildings.reduce((inner, building) => inner + building.floors.length, 0), 0);

  const report = (result: SiteMutationResult, changed: EnterpriseAssetRecord[], message: string): boolean => {
    if (result.error) {
      setError(result.error);
      setNotice('');
      return false;
    }
    setError('');
    setNotice(message);
    onChange(result.directory, changed);
    return true;
  };

  const setDraft = (key: string, value: string) =>
    setDrafts(previous => ({ ...previous, [key]: value }));

  const handleAddSite = () => {
    const result = addSite(sites, siteDraft);
    if (report(result, [], `Added site "${sanitizeSiteName(siteDraft)}".`)) setSiteDraft('');
  };

  const handleAddBuilding = (siteId: string, siteName: string) => {
    const key = `bldg:${siteId}`;
    const name = drafts[key] || '';
    const result = addBuilding(sites, siteId, name);
    if (report(result, [], `Added building "${sanitizeSiteName(name)}" to ${siteName}.`)) setDraft(key, '');
  };

  const handleAddFloor = (siteId: string, buildingId: string, label: string) => {
    const key = `floor:${buildingId}`;
    const name = drafts[key] || '';
    const result = addFloor(sites, siteId, buildingId, name);
    if (report(result, [], `Added floor "${sanitizeSiteName(name)}" to ${label}.`)) setDraft(key, '');
  };

  const startEdit = (target: EditTarget) => {
    setEditing(target);
    setError('');
    setNotice('');
  };

  const commitRename = () => {
    if (!editing) return;
    const clean = sanitizeSiteName(editing.value);
    const site = sites.find(candidate => candidate.id === editing.siteId);
    if (!site) {
      setError('That site no longer exists.');
      return;
    }

    if (editing.kind === 'site') {
      const result = renameSite(sites, site.id, editing.value);
      const updated = renameSiteInAssets(assets, site.name, clean);
      if (report(result, changedBetween(assets, updated), `Renamed site "${site.name}" to "${clean}". Matching registry records were updated.`)) {
        setEditing(null);
      }
      return;
    }

    const building = site.buildings.find(candidate => candidate.id === editing.buildingId);
    if (!building) {
      setError('That building no longer exists.');
      return;
    }

    if (editing.kind === 'building') {
      const result = renameBuilding(sites, site.id, building.id, editing.value);
      const updated = renameBuildingInAssets(assets, site.name, building.name, clean);
      if (report(result, changedBetween(assets, updated), `Renamed building "${building.name}" to "${clean}". Matching registry records were updated.`)) {
        setEditing(null);
      }
      return;
    }

    const floor = building.floors.find(candidate => candidate.id === editing.floorId);
    if (!floor) {
      setError('That floor no longer exists.');
      return;
    }
    const result = renameFloor(sites, site.id, building.id, floor.id, editing.value);
    const updated = renameFloorInAssets(assets, site.name, building.name, floor.name, clean);
    if (report(result, changedBetween(assets, updated), `Renamed floor "${floor.name}" to "${clean}". Matching registry records were updated.`)) {
      setEditing(null);
    }
  };

  const confirmDelete = () => {
    if (!pendingDelete) return;
    let result: SiteMutationResult;
    if (pendingDelete.kind === 'site') {
      result = deleteSite(sites, pendingDelete.siteId);
    } else if (pendingDelete.kind === 'building') {
      result = deleteBuilding(sites, pendingDelete.siteId, pendingDelete.buildingId!);
    } else {
      result = deleteFloor(sites, pendingDelete.siteId, pendingDelete.buildingId!, pendingDelete.floorId!);
    }
    if (report(result, [], `Removed ${pendingDelete.kind} "${pendingDelete.label}" from the directory.`)) {
      setPendingDelete(null);
    }
  };

  const renderName = (targetId: string, name: string, className: string) => {
    if (editing?.targetId !== targetId) return <span className={className}>{name}</span>;
    return (
      <input
        autoFocus
        value={editing.value}
        onChange={event => setEditing({ ...editing, value: event.target.value })}
        onKeyDown={event => {
          if (event.key === 'Enter') commitRename();
          if (event.key === 'Escape') setEditing(null);
        }}
        className={inputClass}
        aria-label={`Rename ${editing.kind}`}
      />
    );
  };

  const renderActions = (target: EditTarget, count: number, label: string) => {
    if (editing?.targetId === target.targetId) {
      return (
        <div className="flex items-center gap-1">
          <button type="button" onClick={commitRename} className={iconButtonClass} title="Save name">
            <Check className="h-3.5 w-3.5" />
          </button>
          <button type="button" onClick={() => setEditing(null)} className={iconButtonClass} title="Cancel rename">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      );
    }
    return (
      <div className="flex items-center gap-1">
        <button type="button" onClick={() => startEdit(target)} className={iconButtonClass} title={`Rename ${target.kind}`}>
          <Pencil className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          disabled={count > 0}
          onClick={() => setPendingDelete({ ...target, label })}
          className={iconButtonClass}
          title={count > 0 ? `Reassign ${count} registry asset${count === 1 ? '' : 's'} before deleting` : `Delete ${target.kind}`}
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
    );
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-4 h-4 text-blue-400" />
            Site &amp; Floor Directory
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Group this project's networks by location. Renaming an entry updates matching registry records; deleting requires reassigning them first.
          </p>
        </div>
        <div className="text-[11px] font-mono text-slate-400 whitespace-nowrap">
          {sites.length} site{sites.length === 1 ? '' : 's'} · {buildingCount} building{buildingCount === 1 ? '' : 's'} · {floorCount} floor{floorCount === 1 ? '' : 's'}
        </div>
      </div>

      <form
        onSubmit={event => { event.preventDefault(); handleAddSite(); }}
        className="flex flex-wrap items-center gap-2 text-xs"
      >
        <input
          value={siteDraft}
          onChange={event => setSiteDraft(event.target.value)}
          placeholder="New site name"
          aria-label="New site name"
          className={inputClass}
        />
        <button
          type="submit"
          className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 font-semibold text-white hover:bg-blue-500"
        >
          <Plus className="h-3.5 w-3.5" /> Add site
        </button>
      </form>

      {error && <p role="alert" className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</p>}
      {notice && !error && <p className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">{notice}</p>}

      {sites.length === 0 ? (
        <p className="rounded-lg border border-dashed border-slate-700 bg-slate-800/30 px-3 py-6 text-center text-xs text-slate-400">
          No sites defined for this project. Add a site, then attach buildings and floors. Registry records stay unassigned until you choose them.
        </p>
      ) : (
        <div className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
          {sites.map(site => {
            const siteAssets = countAssetsAtSite(assets, site.name);
            return (
              <div key={site.id} className="rounded-lg border border-slate-800 bg-slate-800/30">
                <div className="flex items-center justify-between gap-2 px-3 py-2.5">
                  <div className="flex min-w-0 flex-1 items-center gap-2">
                    <MapPin className="h-3.5 w-3.5 shrink-0 text-blue-400" />
                    {renderName(site.id, site.name, 'truncate text-xs font-semibold text-slate-100')}
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] ${siteAssets ? 'bg-blue-500/15 text-blue-300' : 'bg-slate-700/60 text-slate-400'}`}>
                      {siteAssets} asset{siteAssets === 1 ? '' : 's'}
                    </span>
                  </div>
                  {renderActions({ kind: 'site', siteId: site.id, targetId: site.id, value: site.name }, siteAssets, site.name)}
                </div>

                <div className="space-y-2 px-3 pb-3">
                  {site.buildings.map(building => {
                    const buildingAssets = countAssetsInBuilding(assets, site.name, building.name);
                    return (
                      <div key={building.id} className="rounded border border-slate-700/60 bg-slate-900/40 p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex min-w-0 flex-1 items-center gap-2">
                            <Building2 className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                            {renderName(building.id, building.name, 'truncate text-xs font-medium text-slate-200')}
                            <span className="shrink-0 text-[10px] text-slate-500">{buildingAssets} asset{buildingAssets === 1 ? '' : 's'}</span>
                          </div>
                          {renderActions(
                            { kind: 'building', siteId: site.id, buildingId: building.id, targetId: building.id, value: building.name },
                            buildingAssets,
                            `${site.name} / ${building.name}`
                          )}
                        </div>

                        <div className="mt-2 space-y-1 pl-5">
                          {building.floors.map(floor => {
                            const floorAssets = countAssetsOnFloor(assets, site.name, building.name, floor.name);
                            return (
                              <div key={floor.id} className="flex items-center justify-between gap-2">
                                <div className="flex min-w-0 flex-1 items-center gap-2">
                                  <Layers className="h-3 w-3 shrink-0 text-slate-500" />
                                  {renderName(floor.id, floor.name, 'truncate text-[11px] text-slate-300')}
                                  <span className="shrink-0 text-[10px] text-slate-600">{floorAssets} asset{floorAssets === 1 ? '' : 's'}</span>
                                </div>
                                {renderActions(
                                  { kind: 'floor', siteId: site.id, buildingId: building.id, floorId: floor.id, targetId: floor.id, value: floor.name },
                                  floorAssets,
                                  `${site.name} / ${building.name} / ${floor.name}`
                                )}
                              </div>
                            );
                          })}

                          <form
                            onSubmit={event => { event.preventDefault(); handleAddFloor(site.id, building.id, `${site.name} / ${building.name}`); }}
                            className="flex items-center gap-2 pt-1"
                          >
                            <input
                              value={drafts[`floor:${building.id}`] || ''}
                              onChange={event => setDraft(`floor:${building.id}`, event.target.value)}
                              placeholder="Add floor or area"
                              aria-label={`Add floor to ${building.name}`}
                              className={inputClass}
                            />
                            <button type="submit" className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100" title="Add floor">
                              <Plus className="h-3.5 w-3.5" />
                            </button>
                          </form>
                        </div>
                      </div>
                    );
                  })}

                  <form
                    onSubmit={event => { event.preventDefault(); handleAddBuilding(site.id, site.name); }}
                    className="flex items-center gap-2"
                  >
                    <input
                      value={drafts[`bldg:${site.id}`] || ''}
                      onChange={event => setDraft(`bldg:${site.id}`, event.target.value)}
                      placeholder="Add building"
                      aria-label={`Add building to ${site.name}`}
                      className={inputClass}
                    />
                    <button type="submit" className="rounded p-1 text-slate-400 hover:bg-slate-700 hover:text-slate-100" title="Add building">
                      <Plus className="h-3.5 w-3.5" />
                    </button>
                  </form>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {pendingDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-5 text-slate-100 shadow-2xl">
            <h3 className="text-sm font-bold">Delete {pendingDelete.kind} “{pendingDelete.label}”?</h3>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">
              This removes the directory entry only. Registry records, captured evidence, and incidents are not deleted.
            </p>
            <div className="mt-5 flex justify-end gap-2">
              <button onClick={() => setPendingDelete(null)} className="rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800">Cancel</button>
              <button onClick={confirmDelete} className="rounded bg-rose-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-rose-500">Delete {pendingDelete.kind}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
