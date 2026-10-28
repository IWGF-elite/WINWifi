import { BridgeConnectionState } from '../types';

export type BridgeErrorKind = 'offline' | 'token' | 'timeout' | 'unknown';

/**
 * Classify a bridge connection failure from the raw error text produced by
 * NativeBridgeClient, so the UI can distinguish "the daemon is not running"
 * from "the daemon is running but rejected this session's token".
 */
export function classifyBridgeError(rawMessage: string): BridgeErrorKind {
  const raw = rawMessage || '';
  if (
    raw.includes('401') ||
    /unauthori[sz]ed/i.test(raw) ||
    /rejected this dashboard session/i.test(raw) ||
    (/token/i.test(raw) && /reject/i.test(raw))
  ) {
    return 'token';
  }
  if (raw.includes('Failed to fetch') || raw.includes('NetworkError') || raw.includes('ECONNREFUSED')) {
    return 'offline';
  }
  if (raw.includes('timeout') || raw.includes('timed out')) {
    return 'timeout';
  }
  return 'unknown';
}

export interface BridgeStatusView {
  /** Short label for the header pill. */
  label: string;
  /** Visual severity for badges and panels. */
  tone: 'ok' | 'busy' | 'warn' | 'bad';
  /** Panel heading when the bridge is not connected. */
  title: string;
  /** Actionable explanation shown in the offline panel. */
  description: string;
}

export function bridgeStatusView(state: BridgeConnectionState, errorKind: BridgeErrorKind | null): BridgeStatusView {
  switch (state) {
    case 'CONNECTED':
      return {
        label: 'Connected',
        tone: 'ok',
        title: 'Native bridge connected',
        description: 'Live Windows WLAN telemetry is flowing from the local bridge.'
      };
    case 'CONNECTING':
      return {
        label: 'Connecting',
        tone: 'busy',
        title: 'Connecting to the native bridge',
        description: 'Attempting to reach the local WinWiFi bridge. Retrying automatically every few seconds.'
      };
    case 'DISCONNECTED':
      return {
        label: 'Offline',
        tone: 'warn',
        title: 'Native bridge offline',
        description: BRIDGE_OFFLINE_DESCRIPTION
      };
    case 'ERROR':
      if (errorKind === 'token') {
        return {
          label: 'Token mismatch',
          tone: 'bad',
          title: 'Bridge token mismatch',
          description:
            'The local bridge is running but rejected this dashboard session. Open the dashboard from WinWiFi, ' +
            'or relaunch the dev server with VITE_WINWIFI_BRIDGE_TOKEN from %LOCALAPPDATA%\\WinWiFi\\bridge.token, ' +
            'or open the URL printed by the bridge daemon (it includes ?token=).'
        };
      }
      if (errorKind === 'timeout') {
        return {
          label: 'Unresponsive',
          tone: 'bad',
          title: 'Native bridge is not responding',
          description: 'The bridge accepted the connection but did not answer in time. Retrying automatically every few seconds.'
        };
      }
      return {
        label: 'Offline',
        tone: 'bad',
        title: 'Native bridge offline',
        description: BRIDGE_OFFLINE_DESCRIPTION
      };
  }
}

export const BRIDGE_OFFLINE_DESCRIPTION =
  'Native bridge offline. Start WinWiFi.Desktop or run the CLI with --bridge --port 38989 ' +
  '(dotnet run --project WinWiFi.CLI -- --bridge --port 38989), or use start-dev.ps1 to launch both together. ' +
  'The dashboard retries automatically every few seconds.';

export const BRIDGE_RETRY_NOTE = 'Retrying automatically every few seconds. Press Retry to check immediately.';
