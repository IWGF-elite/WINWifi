using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public interface INativeWifiService : IDisposable
    {
        Task<List<WifiAdapter>> GetAdaptersAsync();
        Task<List<AccessPoint>> ScanNetworksAsync(string adapterId, CancellationToken cancellationToken = default);
        Task<ScanBatchResult> ScanNetworksExAsync(string adapterId, CancellationToken cancellationToken = default);
        Task<Dictionary<string, ScanBatchResult>> ScanAllAdaptersAsync(CancellationToken cancellationToken = default);
        Task TriggerHardwareScanAsync(string adapterId, CancellationToken cancellationToken = default);
        bool IsNativeWifiAvailable();
        ScanDiagnostics GetDiagnostics();
        ScanTelemetryState CurrentState { get; }
        event Action<ScanDiagnostics>? DiagnosticsUpdated;
        event Action<ScanBatchResult>? ScanCompleted;
    }
}
