export const isWebView2Host = (): boolean => {
  if (typeof window === 'undefined') return false;
  return Boolean((window as unknown as { chrome?: { webview?: unknown } }).chrome?.webview);
};

export interface SystemCapabilities {
  environment: 'Browser Sandboxed DOM (Web Container)' | 'Windows Desktop Native Host';
  nativeWlanApiAccess: boolean;
  nativeWlanApiReason: string;
  ndisMonitorMode: boolean;
  ndisMonitorModeReason: string;
  pcapDissectorActive: boolean;
  netshCliImportActive: boolean;
  relationalSqliteStorage: boolean;
  cryptographicValidator: boolean;
}

export class WifiEngine {
  private static instance: WifiEngine;

  public static getInstance(): WifiEngine {
    if (!WifiEngine.instance) {
      WifiEngine.instance = new WifiEngine();
    }
    return WifiEngine.instance;
  }

  // Capability detection for runtime sandbox architecture
  public getSystemCapabilities(): SystemCapabilities {
    const host = isWebView2Host();
    return {
      environment: host ? 'Windows Desktop Native Host' : 'Browser Sandboxed DOM (Web Container)',
      nativeWlanApiAccess: false,
      nativeWlanApiReason: host
        ? 'The WebView2 dashboard has no direct P/Invoke access to wlanapi.dll; native WLAN calls go through the local .NET bridge.'
        : 'Web browsers enforce strict sandbox boundaries prohibiting direct P/Invoke calls to Windows wlanapi.dll or NDIS 6.x kernel drivers without an external native helper daemon.',
      ndisMonitorMode: false,
      ndisMonitorModeReason: 'Raw 802.11 monitor mode and packet injection require kernel-level NDIS filter drivers (e.g., Npcap with raw WiFi or custom Airpcap drivers), which are not available to the dashboard process.',
      pcapDissectorActive: true,
      netshCliImportActive: true,
      relationalSqliteStorage: true,
      cryptographicValidator: true
    };
  }
}
