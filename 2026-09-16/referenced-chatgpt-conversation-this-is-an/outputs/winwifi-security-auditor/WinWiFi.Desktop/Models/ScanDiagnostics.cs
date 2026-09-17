using System;
using System.Collections.Generic;

namespace WinWiFi.Models
{
    public enum ScanTelemetryState
    {
        Idle,
        Scanning,
        Paused,
        Error,
        AdapterUnavailable,
        DriverUnsupported,
        NoNetworksFound
    }

    public class ScanDiagnostics
    {
        public ScanTelemetryState State { get; set; } = ScanTelemetryState.Idle;
        public string ActiveAdapterId { get; set; } = string.Empty;
        public string ActiveAdapterName { get; set; } = string.Empty;
        public int TotalAdaptersDetected { get; set; }
        public int LastScanDurationMs { get; set; }
        public int LastDiscoveredBssCount { get; set; }
        public int TotalUniqueBssidsTracked { get; set; }
        public long TotalScanCycles { get; set; }
        public string LastError { get; set; } = string.Empty;
        public DateTime LastScanTimestamp { get; set; } = DateTime.UtcNow;
        public bool NativeWlanAvailable { get; set; }
        public bool NetshFallbackUsed { get; set; }
        public List<string> StatusMessages { get; set; } = new();

        public override string ToString()
        {
            return $"[{State}] Adapter: {ActiveAdapterName} ({ActiveAdapterId}) | Cycles: {TotalScanCycles} | Last BSS Count: {LastDiscoveredBssCount} | Duration: {LastScanDurationMs}ms";
        }
    }

    public class ScanBatchResult
    {
        public List<AccessPoint> AccessPoints { get; set; } = new();
        public ScanTelemetryState State { get; set; } = ScanTelemetryState.Idle;
        public string AdapterId { get; set; } = string.Empty;
        public string AdapterDescription { get; set; } = string.Empty;
        public int DurationMs { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string? ErrorMessage { get; set; }
        public int TotalBssCount => AccessPoints.Count;
    }

    public class ScanObservationRecord
    {
        public long Id { get; set; }
        public string ProjectId { get; set; } = string.Empty;
        public string AdapterId { get; set; } = string.Empty;
        public int ScanCycle { get; set; }
        public string Bssid { get; set; } = string.Empty;
        public string Ssid { get; set; } = string.Empty;
        public int Channel { get; set; }
        public string Band { get; set; } = "Unknown";
        public int FrequencyMHz { get; set; }
        public int Rssi { get; set; }
        public uint SignalQuality { get; set; }
        public string Security { get; set; } = "Unknown";
        public string Cipher { get; set; } = "Unknown";
        public string PhyType { get; set; } = "Unknown";
        public int ChannelWidth { get; set; } = 20;
        public string ObservedAt { get; set; } = DateTime.UtcNow.ToString("o");
    }
}
