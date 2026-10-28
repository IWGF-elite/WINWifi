import React, { useState } from 'react';
import { Archive, Download, RefreshCw, ShieldCheck } from 'lucide-react';
import { NativeBridgeClient } from '../services/bridgeClient';
import { NATIVE_TABLES } from '../services/nativeDatabaseView';
import { downloadBlob } from '../services/download';

interface SnapshotEntry { storageKey: string; payloadJson: string; recordCount: number; bytes: number; }
interface NativeCount { table: string; rows: number; }
interface Preview { entries: SnapshotEntry[]; totalRecords: number; totalBytes: number; native: NativeCount[]; }

const PREFIX = 'winwifi_sqlite_';
const countRecords = (value: unknown): number => Array.isArray(value) ? value.length
  : value && typeof value === 'object' && Array.isArray((value as { records?: unknown }).records) ? ((value as { records: unknown[] }).records.length)
  : value && typeof value === 'object' ? Object.keys(value).length
  : value === null || value === undefined ? 0 : 1;
const formatBytes = (bytes: number) => bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`;

export const StorageMigrationPreview: React.FC = () => {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmImport, setConfirmImport] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const buildPreview = async () => {
    setBusy(true); setError(''); setMessage(''); setConfirmImport(false);
    try {
      const entries: SnapshotEntry[] = [];
      for (let index = 0; index < localStorage.length; index++) {
        const storageKey = localStorage.key(index);
        if (!storageKey?.startsWith(PREFIX)) continue;
        const payloadJson = localStorage.getItem(storageKey);
        if (payloadJson === null) continue;
        let recordCount = 0;
        try { recordCount = countRecords(JSON.parse(payloadJson)); } catch { recordCount = 0; }
        entries.push({ storageKey, payloadJson, recordCount, bytes: new Blob([payloadJson]).size });
      }
      entries.sort((a, b) => a.storageKey.localeCompare(b.storageKey));
      const client = NativeBridgeClient.getInstance();
      const native = await Promise.all(NATIVE_TABLES.map(async table => {
        if (table.key === 'scan_observations') {
          const result = await client.getObservations();
          return { table: table.label, rows: result.totalObservationsCount };
        }
        return { table: table.label, rows: (await table.load(client)).length };
      }));
      setPreview({ entries, totalRecords: entries.reduce((sum, entry) => sum + entry.recordCount, 0), totalBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0), native });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally { setBusy(false); }
  };

  const backup = () => {
    if (!preview) return;
    const payload = { createdAt: new Date().toISOString(), source: 'WebView2 local storage', records: preview.entries.map(({ bytes: _bytes, ...entry }) => entry) };
    downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), `winwifi-browser-storage-backup-${new Date().toISOString().slice(0, 10)}.json`);
    setMessage('A JSON backup was downloaded. Browser storage was not changed.');
  };

  const importSnapshot = async () => {
    if (!preview) return;
    const currentKeys = Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index) || '')
      .filter(key => key.startsWith(PREFIX)).sort();
    const previewKeys = preview.entries.map(entry => entry.storageKey).sort();
    const changed = currentKeys.length !== previewKeys.length
      || currentKeys.some((key, index) => key !== previewKeys[index])
      || preview.entries.some(entry => localStorage.getItem(entry.storageKey) !== entry.payloadJson);
    if (changed) { setError('Browser records changed after preview. Refresh the preview and compare counts again.'); setConfirmImport(false); return; }
    setBusy(true); setError(''); setMessage('');
    try {
      const result = await NativeBridgeClient.getInstance().importBrowserStorageSnapshot({
        importId: crypto.randomUUID(),
        entries: preview.entries.map(({ storageKey, payloadJson, recordCount }) => ({ storageKey, payloadJson, recordCount }))
      });
      setMessage(`SQLite archived ${result.importedKeys} browser-storage keys (${result.importedRecords} records). Browser storage remains unchanged. Import ID: ${result.importId}`);
      setConfirmImport(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally { setBusy(false); }
  };

  return <section className="mb-4 rounded-xl border border-amber-700/40 bg-slate-950/60 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h3 className="flex items-center gap-2 text-sm font-semibold text-slate-100"><Archive className="h-4 w-4 text-amber-300" />Browser data preview and backup</h3><p className="mt-1 text-[11px] text-slate-400">Preview counts first. Import creates a transactional archive copy in native SQLite; it does not delete or modify browser records.</p></div>
      <button type="button" onClick={() => void buildPreview()} disabled={busy} className="flex items-center gap-1 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-50"><RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} />Preview counts</button>
    </div>
    {preview && <>
      <div className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
        <div className="rounded bg-slate-900 p-3"><div className="text-slate-500">Browser source</div><div className="mt-1 font-semibold text-slate-100">{preview.entries.length} keys · {preview.totalRecords} records</div><div className="text-[10px] text-slate-500">{formatBytes(preview.totalBytes)} · read-only preview</div></div>
        <div className="rounded bg-slate-900 p-3 sm:col-span-2"><div className="text-slate-500">Existing native SQLite row counts</div><div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-slate-200">{preview.native.map(row => <span key={row.table}>{row.table}: {row.rows}</span>)}</div></div>
      </div>
      <div className="mt-2 max-h-40 overflow-auto rounded border border-slate-800"><table className="min-w-full text-left text-[10px]"><thead className="sticky top-0 bg-slate-900 text-slate-500"><tr><th className="px-2 py-1.5">Storage key</th><th className="px-2 py-1.5">Browser records</th><th className="px-2 py-1.5">Size</th></tr></thead><tbody>{preview.entries.map(entry => <tr key={entry.storageKey} className="border-t border-slate-800 text-slate-300"><td className="px-2 py-1 font-mono">{entry.storageKey}</td><td className="px-2 py-1">{entry.recordCount}</td><td className="px-2 py-1">{formatBytes(entry.bytes)}</td></tr>)}</tbody></table>{!preview.entries.length && <p className="p-3 text-slate-500">No browser records were found under the application storage prefix.</p>}</div>
      <div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={backup} disabled={!preview.entries.length} className="flex items-center gap-1 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-200 disabled:opacity-40"><Download className="h-3.5 w-3.5" />Download backup</button><button type="button" onClick={() => setConfirmImport(true)} disabled={!preview.entries.length || preview.totalBytes > 20 * 1024 * 1024 || busy} className="rounded bg-amber-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-40">Prepare SQLite import</button>{preview.totalBytes > 20 * 1024 * 1024 && <span className="self-center text-[10px] text-amber-300">Over the 20 MB import limit; download the backup to preserve it.</span>}</div>
      {confirmImport && <div className="mt-3 rounded border border-amber-600/50 bg-amber-950/30 p-3 text-xs"><p className="font-semibold text-amber-200">Confirm archive import</p><p className="mt-1 text-slate-300">Add {preview.entries.length} keys and {preview.totalRecords} records ({formatBytes(preview.totalBytes)}) to native SQLite in one transaction. Existing SQLite data and all browser data will remain unchanged.</p><div className="mt-2 flex gap-2"><button type="button" onClick={() => setConfirmImport(false)} className="rounded border border-slate-700 px-3 py-1.5 text-slate-200">Back</button><button type="button" onClick={() => void importSnapshot()} disabled={busy} className="flex items-center gap-1 rounded bg-amber-600 px-3 py-1.5 font-semibold text-white disabled:opacity-40"><ShieldCheck className="h-3.5 w-3.5" />Import a copy</button></div></div>}
    </>}
    {message && <p role="status" className="mt-2 text-[11px] text-emerald-300">{message}</p>}{error && <p role="alert" className="mt-2 text-[11px] text-rose-300">{error}</p>}
  </section>;
};
