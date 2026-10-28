import { ClientDevice } from '../types';

const MAC_PATTERN = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

const number = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0);

const words = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(entry => text(entry)).filter(Boolean) : [];

/** The BSSID a station was seen on, or empty when no association was observed. */
const observedBssid = (value: unknown): string => {
  const candidate = text(value);
  return MAC_PATTERN.test(candidate) ? candidate.toUpperCase() : '';
};

/**
 * Native `StationClientRecord` and the browser capture parser name the same
 * evidence differently, and a Windows scan cannot prove an association at all.
 * A placeholder BSSID is therefore dropped rather than rendered as an address.
 */
export const mapStationClient = (raw: any): ClientDevice | null => {
  const macAddress = text(raw?.macAddress).toUpperCase();
  if (!MAC_PATTERN.test(macAddress)) return null;
  const apBssid = observedBssid(raw?.apBssid ?? raw?.associatedApBssid);
  return {
    macAddress,
    vendor: text(raw?.vendor) || 'Unknown',
    apBssid,
    connectedSsid: text(raw?.connectedSsid ?? raw?.associatedApSsid) || undefined,
    rssi: number(raw?.rssi),
    packetsSent: number(raw?.packetsSent ?? raw?.packetsCount),
    dataRateMbps: number(raw?.dataRateMbps),
    lastSeen: text(raw?.lastSeen ?? raw?.lastActivity),
    firstSeen: text(raw?.firstSeen) || undefined,
    probes: words(raw?.probes ?? raw?.probeRequests),
    ipAssigned: text(raw?.ipAssigned) || undefined,
    isAssociated: Boolean(apBssid && (raw?.isAssociated ?? true)),
    eapolPacketsObserved: number(raw?.eapolPacketsObserved) || undefined
  };
};

export const mapStationClients = (rows: unknown): ClientDevice[] => {
  if (!Array.isArray(rows)) return [];
  const mapped = new Map<string, ClientDevice>();
  rows.forEach(row => {
    const client = mapStationClient(row);
    if (client) mapped.set(`${client.macAddress}|${client.apBssid}`, client);
  });
  return Array.from(mapped.values());
};
