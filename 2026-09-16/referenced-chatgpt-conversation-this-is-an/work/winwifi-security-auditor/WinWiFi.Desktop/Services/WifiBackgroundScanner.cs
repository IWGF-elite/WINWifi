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

/// <summary>Requests a normal Windows WLAN discovery scan at a bounded cadence, then reads the BSS results. It does not use monitor mode, capture frames, hop channels, or inject packets.</summary>
public sealed class WifiBackgroundScanner : BackgroundService
{
    public const int MinimumIntervalSeconds = 30;
    private readonly INativeWifiService _wifiService;
    private readonly SecurityAnalyzer _securityAnalyzer;
    private readonly SqliteStorageService? _storageService;
    private readonly Action<ScanDiagnostics> _diagHandler;
    private string? _activeAdapterId;
    private string _projectId = "proj-default";
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
    public string ActiveProjectId => _projectId;
    public bool IsScanning => _isScanning;
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

    public void SetActiveProject(string projectId)
    {
        if (string.IsNullOrWhiteSpace(projectId)) throw new ArgumentException("A project identifier is required.", nameof(projectId));
        _projectId = projectId;
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
            try
            {
                _scanCycle++;
                SetState(ScanTelemetryState.Scanning);
                var timer = Stopwatch.StartNew();
                var batch = await _wifiService.ScanNetworksExAsync(_activeAdapterId, stoppingToken);
                timer.Stop();
                var networks = batch.AccessPoints;
                if (networks.Count == 0)
                {
                    SetState(ScanTelemetryState.NoNetworksFound);
                }
                else
                {
                    _securityAnalyzer.DetectRogueAccessPoints(networks);
                    if (_storageService is not null)
                    {
                        await _storageService.SaveAccessPointsAsync(_projectId, networks, stoppingToken);
                        await _storageService.SaveScanObservationsBatchAsync(_projectId, _activeAdapterId, _scanCycle, networks, stoppingToken);
                    }
                    var dominantChannel = networks.GroupBy(network => network.Channel).OrderByDescending(group => group.Count()).FirstOrDefault()?.Key ?? 0;
                    if (dominantChannel > 0) ChannelHopped?.Invoke(dominantChannel);
                    NetworksDiscovered?.Invoke(networks);
                    SetState(ScanTelemetryState.Idle);
                }
                ScanCycleCompleted?.Invoke(new ScanCycleStats { CycleNumber = _scanCycle, NetworksDiscoveredCount = networks.Count, Timestamp = DateTime.UtcNow, DurationMs = (int)timer.ElapsedMilliseconds, State = _state });
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                Debug.WriteLine($"[WifiBackgroundScanner] telemetry cycle error: {exception.Message}");
                SetState(ScanTelemetryState.Error);
            }
            await Task.Delay(Interval, stoppingToken);
        }
        SetState(ScanTelemetryState.Idle);
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
    public string ModeDescription { get; set; } = "Bounded Windows WLAN BSS-cache observation";
    public int DurationMs { get; set; }
    public ScanTelemetryState State { get; set; } = ScanTelemetryState.Idle;
}
