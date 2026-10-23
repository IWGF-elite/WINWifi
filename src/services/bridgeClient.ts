import { 
  AccessPoint, 
  WifiAdapter, 
  BridgeConfig, 
  BridgeConnectionState, 
  BridgeHealthStatus, 
  BridgeScanStatus, 
  BridgeDiagnostics,
  DataOrigin
} from '../types';

export type BridgeEventCallback<T> = (data: T) => void;

const DEFAULT_CONFIG: BridgeConfig = {
  baseUrl: 'http://127.0.0.1:38989',
  allowRemote: false,
  pollIntervalMs: 2500,
  timeoutMs: 5000,
  autoReconnect: true
};

export class NativeBridgeClient {
  private static instance: NativeBridgeClient;

  private config: BridgeConfig = { ...DEFAULT_CONFIG };
  private state: BridgeConnectionState = 'DISCONNECTED';
  private lastError: string | null = null;
  private eventSource: EventSource | null = null;
  private pollTimer: any = null;
  private reconnectTimer: any = null;
  private sseRetryTimer: any = null;
  private reconnectAttempts = 0;
  private maxReconnectDelayMs = 15000;

  // Event Listeners
  private stateListeners: Set<BridgeEventCallback<BridgeConnectionState>> = new Set();
  private networkListeners: Set<BridgeEventCallback<AccessPoint[]>> = new Set();
  private incidentListeners: Set<BridgeEventCallback<any[]>> = new Set();
  private clientListeners: Set<BridgeEventCallback<any[]>> = new Set();
  private diagnosticListeners: Set<BridgeEventCallback<BridgeDiagnostics>> = new Set();
  private errorListeners: Set<BridgeEventCallback<string>> = new Set();

  private constructor() {
    this.loadConfig();
  }

  public static getInstance(): NativeBridgeClient {
    if (!NativeBridgeClient.instance) {
      NativeBridgeClient.instance = new NativeBridgeClient();
    }
    return NativeBridgeClient.instance;
  }

  // ================= Configuration & Localhost Safety =================

  public getConfig(): BridgeConfig {
    return { ...this.config };
  }

  public setConfig(partial: Partial<BridgeConfig>): void {
    const updated = { ...this.config, ...partial };

    // Validate Localhost Safety constraint
    if (!updated.allowRemote && !this.isLocalhost(updated.baseUrl)) {
      throw new Error(
        `Safety Violation: '${updated.baseUrl}' is a non-localhost address. ` +
        `Remote bridges must be explicitly allowed by setting allowRemote to true.`
      );
    }

    this.config = updated;
    this.saveConfig();

    // If currently connected or connecting, restart connection with new settings
    if (this.state === 'CONNECTED' || this.state === 'CONNECTING') {
      this.disconnect();
      this.connect();
    }
  }

  private isLocalhost(urlStr: string): boolean {
    try {
      const parsed = new URL(urlStr);
      const host = parsed.hostname.toLowerCase();
      return (
        host === 'localhost' ||
        host === '127.0.0.1' ||
        host === '::1' ||
        host === '[::1]'
      );
    } catch {
      return false;
    }
  }

  private loadConfig(): void {
    try {
      const saved = localStorage.getItem('winwifi_bridge_config');
      if (saved) {
        const parsed = JSON.parse(saved);
        this.config = { ...DEFAULT_CONFIG, ...parsed };
      }
    } catch {
      this.config = { ...DEFAULT_CONFIG };
    }
  }

  private saveConfig(): void {
    try {
      localStorage.setItem('winwifi_bridge_config', JSON.stringify(this.config));
    } catch (e) {
      console.warn('[BridgeClient] Failed to persist config to localStorage', e);
    }
  }

  // ================= State & Observers =================

  public getState(): BridgeConnectionState {
    return this.state;
  }

  public getLastError(): string | null {
    return this.lastError;
  }

  public onStateChange(cb: BridgeEventCallback<BridgeConnectionState>): () => void {
    this.stateListeners.add(cb);
    return () => this.stateListeners.delete(cb);
  }

  public onNetworks(cb: BridgeEventCallback<AccessPoint[]>): () => void {
    this.networkListeners.add(cb);
    return () => this.networkListeners.delete(cb);
  }

  public onIncidents(cb: BridgeEventCallback<any[]>): () => void {
    this.incidentListeners.add(cb);
    return () => this.incidentListeners.delete(cb);
  }

  public onClients(cb: BridgeEventCallback<any[]>): () => void {
    this.clientListeners.add(cb);
    return () => this.clientListeners.delete(cb);
  }

  public onDiagnostics(cb: BridgeEventCallback<BridgeDiagnostics>): () => void {
    this.diagnosticListeners.add(cb);
    return () => this.diagnosticListeners.delete(cb);
  }

  public onError(cb: BridgeEventCallback<string>): () => void {
    this.errorListeners.add(cb);
    return () => this.errorListeners.delete(cb);
  }

  private setState(newState: BridgeConnectionState, errorMsg?: string): void {
    this.state = newState;
    if (errorMsg !== undefined) {
      this.lastError = errorMsg;
      if (errorMsg) {
        this.errorListeners.forEach(cb => cb(errorMsg));
      }
    }
    this.stateListeners.forEach(cb => cb(this.state));
  }

  // ================= Network Request Helper with Timeout =================

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.config.baseUrl.replace(/\/$/, '')}${endpoint}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        mode: 'cors',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...(options.headers || {})
        },
        signal: controller.signal
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errorText = await response.text().catch(() => response.statusText);
        let detail = errorText || response.statusText;
        try {
          const payload = JSON.parse(errorText);
          detail = payload?.error?.message || payload?.message || payload?.error || detail;
          if (typeof detail !== 'string') detail = errorText;
        } catch { /* Keep non-JSON response text for diagnostics. */ }
        throw new Error(`HTTP ${response.status}: ${detail}`);
      }

      return await response.json() as T;
    } catch (err: any) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        throw new Error(`Bridge timeout: Request to ${endpoint} exceeded ${this.config.timeoutMs}ms.`);
      }
      throw err;
    }
  }

  // ================= REST API Endpoints =================

  /**
   * Health / Status endpoint: checks if the native daemon is listening
   */
  public async checkHealth(): Promise<BridgeHealthStatus> {
    return await this.request<BridgeHealthStatus>('/api/status');
  }

  /**
   * Enumerate physical / virtual Wi-Fi interfaces detected on Windows host
   */
  public async getAdapters(): Promise<WifiAdapter[]> {
    return await this.request<WifiAdapter[]>('/api/adapters');
  }

  /**
   * Retrieve the complete, unbounded list of all discovered BSS access points
   * ZERO truncation (no Take(6), Take(10), Take(20)).
   */
  public async getNetworks(): Promise<AccessPoint[]> {
    const raw = await this.request<any[]>('/api/networks');
    return this.tagOrigin(raw, 'LIVE_WINDOWS');
  }

  public async getIncidents(): Promise<any[]> {
    return await this.request<any[]>('/api/incidents');
  }

  public async getClients(): Promise<any[]> {
    return await this.request<any[]>('/api/clients');
  }

  /** Submit a local capture to the native dissector. The bytes never leave localhost. */
  public async importPcap(file: File): Promise<any> {
    const url = `${this.config.baseUrl.replace(/\/$/, '')}/api/import/pcap`;
    const response = await fetch(url, {
      method: 'POST',
      mode: 'cors',
      headers: { 'Content-Type': 'application/vnd.tcpdump.pcap' },
      body: await file.arrayBuffer()
    });
    if (!response.ok) throw new Error(`PCAP import failed: ${await response.text()}`);
    return await response.json();
  }

  /**
   * Trigger continuous scanning in background service
   */
  public async startScan(adapterId?: string): Promise<{ isScanning: boolean; message: string }> {
    const query = adapterId ? `?adapterId=${encodeURIComponent(adapterId)}` : '';
    return await this.request<{ isScanning: boolean; message: string }>(`/api/scan/start${query}`, {
      method: 'POST'
    });
  }

  /**
   * Stop / pause continuous scanning in background service
   */
  public async stopScan(): Promise<{ isScanning: boolean; message: string }> {
    return await this.request<{ isScanning: boolean; message: string }>('/api/scan/stop', {
      method: 'POST'
    });
  }

  /**
   * Trigger immediate hardware scan cycle and refresh network list
   */
  public async refreshScan(adapterId?: string): Promise<{ count: number; accessPoints: AccessPoint[] }> {
    const query = adapterId ? `?adapterId=${encodeURIComponent(adapterId)}` : '';
    const result = await this.request<{ count: number; accessPoints: any[] }>(`/api/scan/refresh${query}`, {
      method: 'POST'
    });
    const tagged = this.tagOrigin(result.accessPoints || [], 'LIVE_WINDOWS');
    return {
      count: result.count ?? tagged.length,
      accessPoints: tagged
    };
  }

  /**
   * Continuous scan telemetry status
   */
  public async getScanStatus(): Promise<BridgeScanStatus> {
    return await this.request<BridgeScanStatus>('/api/scan/status');
  }

  /**
   * Detailed native diagnostics (P/Invoke state, netsh fallback, scan durations)
   */
  public async getDiagnostics(): Promise<BridgeDiagnostics> {
    return await this.request<BridgeDiagnostics>('/api/diagnostics');
  }

  /**
   * Historical discrete scan observations from SQLite database
   */
  public async getObservations(): Promise<{ totalObservationsCount: number; records: any[] }> {
    return await this.request<{ totalObservationsCount: number; records: any[] }>('/api/observations');
  }

  // ================= Connection Management & Reconnect =================

  public async connect(): Promise<boolean> {
    if (this.state === 'CONNECTING') return false;

    this.setState('CONNECTING');
    this.stopPolling();
    if (this.sseRetryTimer) clearTimeout(this.sseRetryTimer);
    this.sseRetryTimer = null;
    this.closeEventSource();

    try {
      const health = await this.checkHealth();
      this.reconnectAttempts = 0;
      this.setState('CONNECTED');
      this.lastError = null;

      // Start SSE stream for real-time observation updates
      this.initEventSource();

      // Initial network fetch
      const networks = await this.getNetworks();
      this.networkListeners.forEach(cb => cb(networks));
      const incidents = await this.getIncidents();
      this.incidentListeners.forEach(cb => cb(Array.isArray(incidents) ? incidents : []));
      const clients = await this.getClients();
      this.clientListeners.forEach(cb => cb(Array.isArray(clients) ? clients : []));

      return true;
    } catch (err: any) {
      const msg = this.formatBridgeError(err);
      this.setState('ERROR', msg);

      if (this.config.autoReconnect) {
        this.scheduleReconnect();
      }
      return false;
    }
  }

  public disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopPolling();
    if (this.sseRetryTimer) {
      clearTimeout(this.sseRetryTimer);
      this.sseRetryTimer = null;
    }
    this.closeEventSource();
    this.setState('DISCONNECTED');
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelayMs);
    console.log(`[BridgeClient] Reconnecting to ${this.config.baseUrl} in ${Math.round(delay)}ms (attempt ${this.reconnectAttempts})...`);

    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  // ================= Server-Sent Events (SSE) Stream =================

  private initEventSource(): void {
    this.closeEventSource();

    const sseUrl = `${this.config.baseUrl.replace(/\/$/, '')}/api/events`;
    try {
      this.eventSource = new EventSource(sseUrl);

      this.eventSource.addEventListener('scan_result', (event: MessageEvent) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.accessPoints && Array.isArray(payload.accessPoints)) {
            const tagged = this.tagOrigin(payload.accessPoints, 'LIVE_WINDOWS');
            this.networkListeners.forEach(cb => cb(tagged));
          }
          if (Array.isArray(payload.incidents)) this.incidentListeners.forEach(cb => cb(payload.incidents));
          if (Array.isArray(payload.clients)) this.clientListeners.forEach(cb => cb(payload.clients));
        } catch (e) {
          console.error('[BridgeClient] Failed to parse SSE scan_result payload', e);
        }
      });

      this.eventSource.addEventListener('diagnostics', (event: MessageEvent) => {
        try {
          const diag = JSON.parse(event.data);
          this.diagnosticListeners.forEach(cb => cb(diag));
        } catch (e) {
          console.error('[BridgeClient] Failed to parse SSE diagnostics payload', e);
        }
      });

      this.eventSource.addEventListener('state_change', (event: MessageEvent) => {
        try {
          const stateData = JSON.parse(event.data);
          console.log('[BridgeClient] Native scanner state changed:', stateData.state);
        } catch (e) {
          console.error('[BridgeClient] Failed to parse SSE state_change payload', e);
        }
      });

      this.eventSource.onopen = () => {
        console.log('[BridgeClient] SSE stream connection established.');
        if (this.sseRetryTimer) clearTimeout(this.sseRetryTimer);
        this.sseRetryTimer = null;
        this.stopPolling();
      };

      this.eventSource.onerror = (e) => {
        console.warn('[BridgeClient] SSE stream error. Falling back to HTTP polling.', e);
        this.closeEventSource();
        this.startPolling();
        if (this.sseRetryTimer) clearTimeout(this.sseRetryTimer);
        this.sseRetryTimer = setTimeout(() => {
          this.sseRetryTimer = null;
          if (this.state === 'CONNECTED') this.initEventSource();
        }, 10_000);
      };
    } catch (e) {
      console.warn('[BridgeClient] Failed to initialize EventSource. Falling back to HTTP polling.', e);
      this.startPolling();
    }
  }

  private closeEventSource(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  // ================= Fallback HTTP Polling =================

  private startPolling(): void {
    if (this.pollTimer) return;

    this.pollTimer = setInterval(async () => {
      if (this.state !== 'CONNECTED') return;

      try {
        const aps = await this.getNetworks();
        this.networkListeners.forEach(cb => cb(aps));
      } catch (err: any) {
        console.warn('[BridgeClient] Polling error:', err.message);
      }
    }, this.config.pollIntervalMs);
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  // ================= Origin Tagging & Error Formatting =================

  private tagOrigin(aps: any[], origin: DataOrigin): AccessPoint[] {
    return aps.map(ap => ({
      ...ap,
      bssid: ap.bssid || ap.Bssid || '',
      ssid: ap.ssid ?? ap.Ssid ?? '',
      channel: ap.channel ?? ap.Channel ?? 1,
      band: ap.band || ap.Band || '2.4 GHz',
      frequencyMHz: ap.frequencyMHz ?? ap.FrequencyMHz ?? 2412,
      rssi: ap.rssi ?? ap.Rssi ?? -70,
      signalQuality: ap.signalQuality ?? ap.SignalQuality ?? 50,
      security: ap.security || ap.Security || 'Open',
      cipher: ap.cipher || ap.Cipher || 'None',
      standard: ap.standard || ap.phyType || ap.PhyType || '802.11ax (Wi-Fi 6)',
      phyType: ap.phyType || ap.PhyType || '802.11ax',
      channelWidth: ap.channelWidth ?? ap.ChannelWidth ?? 20,
      channelWidthMhz: ap.channelWidthMhz ?? ap.ChannelWidthMhz ?? ap.channelWidth ?? ap.ChannelWidth ?? 20,
      vendor: ap.vendor || ap.Vendor || 'Unknown',
      beaconCount: ap.beaconCount ?? ap.BeaconCount ?? 1,
      dataPacketCount: ap.dataPacketCount ?? ap.DataPacketCount ?? 0,
      securityScore: ap.securityScore ?? ap.SecurityScore ?? 100,
      isRogue: ap.isRogue ?? ap.IsRogue ?? false,
      firstSeen: ap.firstSeen || ap.FirstSeen || '',
      lastSeen: ap.lastSeen || ap.LastSeen || '',
      dataSourceOrigin: origin,
      // Ensure clients and issues are arrays (supports issues, securityIssues, or PascalCase variants)
      clients: ap.clients || ap.Clients || [],
      issues: ap.issues || ap.securityIssues || ap.SecurityIssues || []
    }));
  }

  private formatBridgeError(err: any): string {
    const raw = err.message || String(err);
    if (raw.includes('Failed to fetch') || raw.includes('NetworkError') || raw.includes('ECONNREFUSED')) {
      return (
        `Unable to reach WinWiFi Native Bridge at ${this.config.baseUrl}. ` +
        `Ensure WinWiFi.Desktop or WinWiFi.CLI daemon is running on your Windows host with '--bridge --port 38989'.`
      );
    }
    if (raw.includes('timeout')) {
      return `Connection to ${this.config.baseUrl} timed out. The native scanner process may be busy or unresponsive.`;
    }
    return raw;
  }
}
