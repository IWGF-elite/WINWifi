using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using WinWiFi.Data;
using WinWiFi.Models;

namespace WinWiFi.Services;

/// <summary>Requests a normal Windows WLAN scan and then reads the BSS list at a bounded cadence. It does not use monitor mode, capture frames, hop channels, or inject packets.</summary>
public sealed class WifiBackgroundScanner : BackgroundService
{
    // WlanScan is asynchronous. A three-second cadence gives Windows a bounded
    // chance to refresh the BSS cache while promptly expiring APs that vanish.
    public const int MinimumIntervalSeconds = 3;
    private readonly INativeWifiService _wifiService;
    private readonly SecurityAnalyzer _securityAnalyzer;
    private readonly SqliteStorageService? _storageService;
    private readonly Action<ScanDiagnostics> _diagHandler;
    private string? _activeAdapterId;
    private string? _activeProjectId;
    private bool _isScanning;
    private int _scanCycle;
    private ScanTelemetryState _state = ScanTelemetryState.Idle;

    public WifiBackgroundScanner(INativeWifiService wifiService, SecurityAnalyzer securityAnalyzer, SqliteStorageService? storageService = null)
    {
        _wifiService = wifiService ?? throw new ArgumentNullException(nameof(wifiService));
        _securityAnalyzer = securityAnalyzer ?? throw new ArgumentNullException(nameof(securityAnalyzer));
        _storageService = storageService;
        _diagHandler = diagnostics => DiagnosticsUpdated?.Invoke(diagnostics);
        _wifiService.DiagnosticsUpdated += _diagHandler;
    }

    public ScanTelemetryState CurrentState => _state;
    public string? ActiveAdapterId => _activeAdapterId;
    public string? ActiveProjectId => _activeProjectId;
    public bool IsScanning => _isScanning;
    public string? LastError { get; private set; }
    public TimeSpan Interval { get; private set; } = TimeSpan.FromSeconds(MinimumIntervalSeconds);
    public event Action<List<AccessPoint>>? NetworksDiscovered;
    public event Action<ScanCycleStats>? ScanCycleCompleted;
    public event Action<int>? ChannelHopped;
    public event Action<ScanTelemetryState>? StateChanged;
    public event Action<ScanDiagnostics>? DiagnosticsUpdated;

    public void SetActiveAdapter(string adapterId)
    {
        if (string.IsNullOrWhiteSpace(adapterId)) throw new ArgumentException("An adapter identifier is required.", nameof(adapterId));
        _activeAdapterId = adapterId;
    }

    /// <summary>Selects the audit project that owns persisted scan telemetry. Null pauses persistence.</summary>
    public void SetProjectId(string? projectId)
    {
        _activeProjectId = string.IsNullOrWhiteSpace(projectId) ? null : projectId.Trim();
    }

    public void SetInterval(TimeSpan interval)
    {
        if (interval < TimeSpan.FromSeconds(MinimumIntervalSeconds)) throw new ArgumentOutOfRangeException(nameof(interval), $"The minimum telemetry interval is {MinimumIntervalSeconds} seconds.");
        Interval = interval;
    }

    public void SetScanningState(bool scanning)
    {
        _isScanning = scanning;
        SetState(scanning ? ScanTelemetryState.Idle : ScanTelemetryState.Paused);
    }

    // Compatibility notification for existing diagnostics; this service never changes radio channels.
    public void ReportChannelHop(int channel)
    {
        if (channel > 0) ChannelHopped?.Invoke(channel);
    }

    public override void Dispose()
    {
        _wifiService.DiagnosticsUpdated -= _diagHandler;
        base.Dispose();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        SetState(ScanTelemetryState.Paused);
        while (!stoppingToken.IsCancellationRequested)
        {
            if (!_isScanning)
            {
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                continue;
            }
            if (string.IsNullOrWhiteSpace(_activeAdapterId))
            {
                SetState(ScanTelemetryState.AdapterUnavailable);
                await Task.Delay(Interval, stoppingToken);
                continue;
            }
            var timer = Stopwatch.StartNew();
            try
            {
                _scanCycle++;
                SetState(ScanTelemetryState.Scanning);
                LastError = null;
                // WlanGetNetworkBssList only returns Windows' last cache. Ask the
                // OS to update that cache first so nearby networks are not hidden
                // until another application happens to scan.
                await _wifiService.TriggerHardwareScanAsync(_activeAdapterId, stoppingToken);
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
                var batch = await _wifiService.ScanNetworksExAsync(_activeAdapterId, stoppingToken);
                timer.Stop();
                var networks = batch.AccessPoints;
                // Emit every completed real scan, including an empty BSS list.
                // The bridge uses this to age out APs that have disappeared.
                _securityAnalyzer.DetectRogueAccessPoints(networks);
                NetworksDiscovered?.Invoke(networks);
                if (!_isScanning)
                {
                    // A pause requested during an in-flight WLAN scan takes
                    // effect when that read completes. Do not publish Idle or
                    // NoNetworksFound as if continuous scanning were still on.
                    SetState(ScanTelemetryState.Paused);
                }
                else if (networks.Count == 0)
                {
                    SetState(ScanTelemetryState.NoNetworksFound);
                }
                else
                {
                    var dominantChannel = networks.GroupBy(network => network.Channel).OrderByDescending(group => group.Count()).FirstOrDefault()?.Key ?? 0;
                    if (dominantChannel > 0) ChannelHopped?.Invoke(dominantChannel);
                    SetState(ScanTelemetryState.Idle);
                }
                if (_storageService is not null && !string.IsNullOrWhiteSpace(_activeProjectId))
                {
                    await _storageService.SaveAccessPointsAsync(_activeProjectId!, networks, stoppingToken);
                    await _storageService.SaveScanObservationsBatchAsync(_activeProjectId!, _activeAdapterId!, _scanCycle, networks, stoppingToken);
                }
                ScanCycleCompleted?.Invoke(new ScanCycleStats { CycleNumber = _scanCycle, NetworksDiscoveredCount = networks.Count, Timestamp = DateTime.UtcNow, DurationMs = (int)timer.ElapsedMilliseconds, State = _state });
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                LastError = exception.Message;
                Debug.WriteLine($"[WifiBackgroundScanner] telemetry cycle error: {exception.Message}");
                SetState(ScanTelemetryState.Error);
            }
            timer.Stop();
            // Keep the start of each hardware scan close to the configured cadence
            // rather than adding a full interval after the scan dwell completes.
            var remaining = Interval - timer.Elapsed;
            if (remaining > TimeSpan.Zero)
                await Task.Delay(remaining, stoppingToken);
        }
        SetState(_isScanning ? ScanTelemetryState.Idle : ScanTelemetryState.Paused);
    }

    private void SetState(ScanTelemetryState state)
    {
        if (_state == state) return;
        _state = state;
        StateChanged?.Invoke(state);
    }
}

public sealed class ScanCycleStats
{
    public int CycleNumber { get; set; }
    public int NetworksDiscoveredCount { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string ModeDescription { get; set; } = "Bounded Windows WLAN discovery";
    public int DurationMs { get; set; }
    public ScanTelemetryState State { get; set; } = ScanTelemetryState.Idle;
}
