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

export function bridgeStatusView(
  state: BridgeConnectionState,
  errorKind: BridgeErrorKind | null,
  embedded: boolean = isEmbeddedDashboard()
): BridgeStatusView {
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
        description: embedded
          ? 'Waiting for WinWiFi to finish starting its live data connection. This happens by itself.'
          : 'Attempting to reach the local WinWiFi bridge. Retrying automatically every few seconds.'
      };
    case 'DISCONNECTED':
      return {
        label: 'Offline',
        tone: 'warn',
        title: embedded ? 'Live data paused' : 'Native bridge offline',
        description: embedded ? SHELL_OFFLINE_DESCRIPTION : BRIDGE_OFFLINE_DESCRIPTION
      };
    case 'ERROR':
      if (errorKind === 'token') {
        return {
          label: embedded ? 'Not authorised' : 'Token mismatch',
          tone: 'bad',
          title: embedded ? 'This window is not authorised for live data' : 'Bridge token mismatch',
          description: embedded
            ? SHELL_TOKEN_DESCRIPTION
            : TOKEN_DESCRIPTION
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
        title: embedded ? 'Live data unavailable' : 'Native bridge offline',
        description: embedded ? SHELL_OFFLINE_DESCRIPTION : BRIDGE_OFFLINE_DESCRIPTION
      };
  }
}

export const BRIDGE_OFFLINE_DESCRIPTION =
  'Native bridge offline. Start WinWiFi.Desktop or run the CLI with --bridge --port 38989 ' +
  '(dotnet run --project WinWiFi.CLI -- --bridge --port 38989), or use start-dev.ps1 to launch both together. ' +
  'The dashboard retries automatically every few seconds.';

const TOKEN_DESCRIPTION =
  'The local bridge is running but rejected this dashboard session. Open the dashboard from WinWiFi, ' +
  'or relaunch the dev server with VITE_WINWIFI_BRIDGE_TOKEN from %LOCALAPPDATA%\\WinWiFi\\bridge.token, ' +
  'or open the URL printed by the bridge daemon (it includes ?token=).';

// The desktop shell owns its own data connection, so the user has nothing to
// start, no address to type, and no credential to place anywhere.
export const SHELL_OFFLINE_DESCRIPTION =
  'WinWiFi lost its live Wi-Fi data connection. Retry to reconnect, or close this window and start WinWiFi again ' +
  'from its desktop icon. Your adapter and scans are untouched.';

export const SHELL_TOKEN_DESCRIPTION =
  'This dashboard window is no longer authorised for WinWiFi\'s live data connection. Close this window and start ' +
  'WinWiFi again from its desktop icon — a new window is authorised automatically.';

export const BRIDGE_RETRY_NOTE = 'Retrying automatically every few seconds. Press Retry to check immediately.';

export const DEV_SERVER_PORTS = ['5173', '3000'];

function isLoopbackHost(hostname: string): boolean {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1' || hostname === '[::1]';
}

/**
 * True when this page is served by the WinWiFi shell's own bridge (the WebView2
 * window, or a browser tab opened directly on the daemon port). In that mode the
 * user has nothing to configure, so developer instructions must not be shown.
 */
export function isEmbeddedDashboard(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const { hostname, port } = window.location;
    return isLoopbackHost(hostname) && port !== '' && !DEV_SERVER_PORTS.includes(port);
  } catch {
    return false;
  }
}

/**
 * Resolve the bridge base URL for the page. When the bridge itself serves this
 * page (embedded desktop WebView2, or a browser tab opened on the daemon port),
 * the serving origin is the bridge, so a dynamically chosen port works with
 * zero configuration. A `port` query parameter (start-dev.ps1) also overrides.
 * Dev-server pages keep the saved/default URL.
 */
export function resolveBridgeBaseUrl(hostname: string, port: string, search: string, fallbackUrl: string): string {
  if (!isLoopbackHost(hostname)) return fallbackUrl;
  const portParam = new URLSearchParams(search || '').get('port');
  if (portParam && /^\d{1,5}$/.test(portParam)) return `http://127.0.0.1:${portParam}`;
  if (port && !DEV_SERVER_PORTS.includes(port)) return `http://${hostname}:${port}`;
  return fallbackUrl;
}
