using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Data;
using WinWiFi.Models;
using WinWiFi.Tests;

namespace WinWiFi.Services
{
    public class HttpBridgeServer : IAsyncDisposable
    {
        private readonly int _port;
        private readonly HttpListener _listener;
        private readonly INativeWifiService _wifiService;
        private readonly SecurityAnalyzer _securityAnalyzer;
        private readonly PcapDissector _pcapDissector;
        private readonly ReportGenerator _reportGenerator;
        private readonly SqliteStorageService _storage;
        private readonly bool _ownsStorage;
        private readonly WifiBackgroundScanner _scanner;
        private readonly string? _dashboardRoot;

        private CancellationTokenSource? _cts;
        private readonly object _localScanSync = new();
        private CancellationTokenSource? _localNetworkScanCts;
        private Task? _listenerTask;
        private readonly ConcurrentDictionary<string, StreamWriter> _sseClients = new();
        // Scanner events (networks, diagnostics, state) fire concurrently on
        // different threads. Serializing writes per payload prevents two events
        // from interleaving chunks on the same StreamWriter, which corrupted
        // SSE frames with "Bad control character" JSON parse errors.
        private readonly object _sseWriteLock = new();
        private readonly HashSet<string> _allowedBrowserOrigins;
        private readonly string _authToken;
        private const string AuthTokenHeader = "X-WinWiFi-Token";

        /// <summary>Per-process credential the dashboard must present on every /api request.</summary>
        public string AuthToken => _authToken;

        internal static string GenerateAuthToken()
        {
            Span<byte> bytes = stackalloc byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }

        internal static bool IsValidAuthToken(string? provided, string expected)
        {
            if (string.IsNullOrEmpty(provided) || string.IsNullOrEmpty(expected)) return false;
            byte[] actual = Encoding.UTF8.GetBytes(provided);
            byte[] required = Encoding.UTF8.GetBytes(expected);
            return CryptographicOperations.FixedTimeEquals(actual, required);
        }

        internal static string BridgeTokenFilePath() => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinWiFi",
            "bridge.token");

        private void PersistAuthToken()
        {
            try
            {
                byte[] bytes = Encoding.ASCII.GetBytes(_authToken);
                if (bytes.Length != _authToken.Length) throw new InvalidOperationException("Bridge token must be ASCII.");
                string path = BridgeTokenFilePath();
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, bytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HttpBridgeServer] Unable to write bridge token file: {ex.Message}");
            }
        }

        internal static HashSet<string> ParseAllowedBrowserOrigins(string? configuredOrigins)
        {
            var defaults = new[] { "http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:38989", "http://127.0.0.1:38989" };
            var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var candidates = string.IsNullOrWhiteSpace(configuredOrigins) ? defaults : configuredOrigins.Split(';');
            foreach (var candidate in candidates)
            {
                var value = candidate.Trim().TrimEnd('/');
                if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) continue;
                if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) continue;
                if (!uri.IsLoopback || uri.UserInfo.Length > 0 || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) continue;
                origins.Add(uri.GetLeftPart(UriPartial.Authority));
            }
            return origins;
        }

        internal static bool IsAllowedBrowserOrigin(string? origin, IEnumerable<string> allowedOrigins) =>
            !string.IsNullOrWhiteSpace(origin) && allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase);

        internal static bool RequestsPrivateNetworkAccess(string? requestHeader) =>
            string.Equals(requestHeader, "true", StringComparison.OrdinalIgnoreCase);

        internal static bool IsValidProjectId(string? projectId) =>
            !string.IsNullOrWhiteSpace(projectId) && ProjectIdPattern.IsMatch(projectId.Trim());

        private static string? NormalizeProjectId(string? projectId) =>
            IsValidProjectId(projectId) ? projectId!.Trim() : null;

        private string? ResolveProjectId(HttpListenerRequest request)
        {
            string? fromHeader = NormalizeProjectId(request.Headers["X-WinWiFi-Project"]);
            string? fromQuery = NormalizeProjectId(request.QueryString["projectId"]);
            return fromHeader ?? fromQuery ?? _activeProjectId;
        }

        private string? ResolveProjectName(HttpListenerRequest request)
        {
            string? name = request.Headers["X-WinWiFi-Project-Name"] ?? request.QueryString["projectName"];
            return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        }

        private void ApplyProjectContext(HttpListenerRequest request)
        {
            string? candidate = NormalizeProjectId(request.Headers["X-WinWiFi-Project"])
                ?? NormalizeProjectId(request.QueryString["projectId"]);
            if (candidate is null) return;

            string? name = ResolveProjectName(request);
            _activeProjectId = candidate;
            if (name is not null) _activeProjectName = name;
            _scanner.SetProjectId(candidate);
            _ = _storage.EnsureProjectAsync(candidate, _activeProjectName);
        }

        private List<AccessPoint> _latestAccessPoints = new();
        private List<ThreatFinding> _latestIncidents = new();
        private List<SecurityChange> _latestDrifts = new();
        private List<StationClientRecord> _latestClients = new();
        private Dictionary<string, AccessPoint> _previousScanByBssid = new(StringComparer.OrdinalIgnoreCase);
        private string? _activeAdapterId;
        private string? _activeProjectId;
        private string? _activeProjectName;
        private int _scanCycleCount = 0;
        private string? _lastScanCompletedAtUtc;
        private DateTime _lastRefreshUtc = DateTime.MinValue;
        private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(10);
        private const int MissingScanLimit = 3;
        private static readonly Regex ProjectIdPattern = new("^[A-Za-z0-9._-]{1,64}$", RegexOptions.Compiled);

        public HttpBridgeServer(
            int port = 38989,
            INativeWifiService? wifiService = null,
            SecurityAnalyzer? securityAnalyzer = null,
            PcapDissector? pcapDissector = null,
            ReportGenerator? reportGenerator = null,
            SqliteStorageService? storage = null,
            WifiBackgroundScanner? scanner = null,
            IEnumerable<string>? allowedBrowserOrigins = null,
            string? dashboardRoot = null)
        {
            _port = port;
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
            _listener.Prefixes.Add($"http://localhost:{_port}/");
            _allowedBrowserOrigins = allowedBrowserOrigins is null
                ? ParseAllowedBrowserOrigins(Environment.GetEnvironmentVariable("WINWIFI_ALLOWED_ORIGINS"))
                : new HashSet<string>(allowedBrowserOrigins.Where(origin => ParseAllowedBrowserOrigins(origin).Contains(origin.TrimEnd('/'))), StringComparer.OrdinalIgnoreCase);
            _allowedBrowserOrigins.Add($"http://127.0.0.1:{_port}");
            _allowedBrowserOrigins.Add($"http://localhost:{_port}");
            _dashboardRoot = ResolveDashboardRoot(dashboardRoot);
            _authToken = GenerateAuthToken();

            _securityAnalyzer = securityAnalyzer ?? new SecurityAnalyzer();
            _wifiService = wifiService ?? new NativeWifiService(_securityAnalyzer);
            _pcapDissector = pcapDissector ?? new PcapDissector();
            _reportGenerator = reportGenerator ?? new ReportGenerator();
            _ownsStorage = storage is null;
            _storage = storage ?? new SqliteStorageService();
            _scanner = scanner ?? new WifiBackgroundScanner(_wifiService, _securityAnalyzer);

            // Hook scanner events
            _scanner.NetworksDiscovered += OnNetworksDiscovered;
            _scanner.ScanCycleCompleted += OnScanCycleCompleted;
            _scanner.StateChanged += OnScannerStateChanged;
            _scanner.DiagnosticsUpdated += OnScannerDiagnosticsUpdated;
        }

        private void OnScannerStateChanged(ScanTelemetryState state)
        {
            BroadcastSseEvent("state_change", new
            {
                state = state.ToString(),
                timestamp = DateTime.UtcNow,
                isScanning = _scanner.IsScanning,
                lastError = _scanner.LastError,
                activeAdapterId = _activeAdapterId,
                scanCyclesCompleted = _scanCycleCount,
                lastDiscoveredCount = _latestAccessPoints.Count,
                lastScanCompletedAt = _lastScanCompletedAtUtc
            });
        }

        private void OnScannerDiagnosticsUpdated(ScanDiagnostics diag)
        {
            BroadcastSseEvent("diagnostics", diag);
        }

        private void OnNetworksDiscovered(List<AccessPoint> aps)
        {
            ProcessScanResults(aps);
        }

        private void ProcessScanResults(List<AccessPoint> aps)
        {
            _latestAccessPoints = ReconcileLiveAccessPoints(aps);
            var threats = AnalyzeCurrentScan(_latestAccessPoints.Where(ap => ap.IsActiveInCurrentScan).ToList());
            _latestIncidents = threats.Findings;
            _latestDrifts = threats.DetectedDrifts;

            BroadcastScanResult();
        }

        // The background cycle and a manual refresh publish one identical live
        // snapshot, so the payload is defined once instead of twice.
        private void BroadcastScanResult()
        {
            BroadcastSseEvent("scan_result", new
            {
                cycle = _scanCycleCount,
                timestamp = DateTime.UtcNow,
                accessPointsCount = _latestAccessPoints.Count,
                accessPoints = _latestAccessPoints,
                incidents = _latestIncidents,
                drifts = _latestDrifts
            });
        }

        // A BSSID must be present in every fresh WLAN scan. Retain a missed BSSID
        // for only two cycles so the grid can show its age, then remove it on the
        // third miss instead of leaving a powered-off AP visible indefinitely.
        private List<AccessPoint> ReconcileLiveAccessPoints(List<AccessPoint> observed)
        {
            var now = DateTime.UtcNow;
            var prior = _latestAccessPoints.ToDictionary(ap => ap.Bssid, StringComparer.OrdinalIgnoreCase);
            var next = new List<AccessPoint>(observed.Count + prior.Count);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var ap in observed.Where(ap => !string.IsNullOrWhiteSpace(ap.Bssid)))
            {
                seen.Add(ap.Bssid);
                if (prior.TryGetValue(ap.Bssid, out var previous))
                {
                    ap.FirstSeen = string.IsNullOrWhiteSpace(previous.FirstSeen) ? ap.FirstSeen : previous.FirstSeen;
                    ap.RssiHistory = previous.RssiHistory;
                    ap.SignalQualityHistory = previous.SignalQualityHistory;
                }
                ap.LastSeenTime = now;
                ap.LastSeen = now.ToString("yyyy-MM-dd HH:mm:ss");
                ap.IsActiveInCurrentScan = true;
                ap.DisappearedScanCycles = 0;
                next.Add(ap);
            }

            foreach (var previous in _latestAccessPoints.Where(ap => !string.IsNullOrWhiteSpace(ap.Bssid) && !seen.Contains(ap.Bssid)))
            {
                previous.IsActiveInCurrentScan = false;
                previous.DisappearedScanCycles++;
                if (previous.DisappearedScanCycles < MissingScanLimit)
                    next.Add(previous);
            }
            return next;
        }

        private ThreatAnalysisResult AnalyzeCurrentScan(List<AccessPoint> aps)
        {
            var baseline = _previousScanByBssid.Count == 0 ? null : _previousScanByBssid;
            var analysis = _securityAnalyzer.AnalyzeThreatsAndDrift(aps, baseline);
            _previousScanByBssid = aps
                .Where(ap => !string.IsNullOrWhiteSpace(ap.Bssid))
                .ToDictionary(ap => ap.Bssid, ap => ap, StringComparer.OrdinalIgnoreCase);
            return analysis;
        }

        private void OnScanCycleCompleted(ScanCycleStats stats)
        {
            _scanCycleCount = stats.CycleNumber;
            _lastScanCompletedAtUtc = stats.Timestamp.ToUniversalTime().ToString("O");
            BroadcastSseEvent("cycle_completed", new
            {
                state = stats.State.ToString(),
                timestamp = stats.Timestamp,
                isScanning = _scanner.IsScanning,
                lastError = _scanner.LastError,
                activeAdapterId = _activeAdapterId,
                scanCyclesCompleted = _scanCycleCount,
                lastDiscoveredCount = stats.NetworksDiscoveredCount,
                lastScanCompletedAt = _lastScanCompletedAtUtc
            });
        }

        public async Task StartAsync()
        {
            if (_listener.IsListening) return;

            _cts = new CancellationTokenSource();
            // Bind before anything slow: a port conflict must fail fast so the
            // caller can fall back to another port, and the dashboard must be
            // able to answer /api/health while the first WLAN scan warms up.
            _listener.Start();
            PersistAuthToken();
            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
            Console.WriteLine($"[HttpBridgeServer] Listening on http://127.0.0.1:{_port}/ (token file: {BridgeTokenFilePath()})");

            try
            {
                var adapters = await _wifiService.GetAdaptersAsync();
                if (adapters.Count > 0)
                {
                    _activeAdapterId = adapters[0].Id;
                    _scanner.SetActiveAdapter(_activeAdapterId);
                    _scanner.SetScanningState(true);

                    // Populate the dashboard before WebView2 asks for /api/networks.
                    // Otherwise a fresh launch can briefly display an empty state
                    // while the Windows WLAN service is still filling its cache.
                    await _wifiService.TriggerHardwareScanAsync(_activeAdapterId, _cts.Token);
                    await Task.Delay(TimeSpan.FromSeconds(2), _cts.Token);
                    var initialAps = await _wifiService.ScanNetworksAsync(_activeAdapterId, _cts.Token);
                    if (initialAps.Count > 0)
                    {
                        ProcessScanResults(initialAps);
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[HttpBridgeServer] Adapter discovery failed: {ex.Message}");
            }

            // Continue bounded Windows WLAN discovery after the startup scan.
            _ = _scanner.StartAsync(_cts.Token);

            // Cold-start warm-up: the Windows WLAN cache can take several seconds
            // to stabilize after the first scan request (observed 1 vs 37 visible
            // BSSIDs on real hardware). Scan again shortly after startup and merge
            // the results so early counts are not artificially low.
            _ = WarmupSecondScanAsync();
        }

        private async Task WarmupSecondScanAsync()
        {
            if (_cts is null || string.IsNullOrEmpty(_activeAdapterId)) return;
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(4), _cts.Token);
                await _wifiService.TriggerHardwareScanAsync(_activeAdapterId, _cts.Token);
                await Task.Delay(TimeSpan.FromSeconds(3), _cts.Token);
                var aps = await _wifiService.ScanNetworksAsync(_activeAdapterId, _cts.Token);
                if (aps.Count > 0)
                {
                    _scanCycleCount++;
                    ProcessScanResults(aps);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[HttpBridgeServer] Warm-up scan failed: {ex.Message}");
            }
        }

        public async Task StopAsync()
        {
            _scanner.NetworksDiscovered -= OnNetworksDiscovered;
            _scanner.ScanCycleCompleted -= OnScanCycleCompleted;
            _scanner.StateChanged -= OnScannerStateChanged;
            _scanner.DiagnosticsUpdated -= OnScannerDiagnosticsUpdated;

            _cts?.Cancel();
            try
            {
                _listener.Stop();
            }
            catch { }

            foreach (var client in _sseClients.Values)
            {
                try { client.Dispose(); } catch { }
            }
            _sseClients.Clear();

            if (_listenerTask != null)
            {
                // ConfigureAwait(false): the desktop shell awaits this from its UI
                // thread during shutdown, and a captured context would deadlock.
                try { await _listenerTask.ConfigureAwait(false); } catch { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
            _listener.Close();
            if (_ownsStorage) _storage.Dispose();
        }

        private async Task ListenLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _listener.IsListening)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    _ = ProcessRequestAsync(context);
                }
                catch (HttpListenerException) when (token.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (token.IsCancellationRequested) break;
                    Console.WriteLine($"[HttpBridgeServer] Listener loop error: {ex.Message}");
                }
            }
        }

        private async Task ProcessRequestAsync(HttpListenerContext context)
        {
            var request = context.Request;
            var response = context.Response;

            // Localhost-only security enforcement
            if (!request.IsLocal)
            {
                response.StatusCode = (int)HttpStatusCode.Forbidden;
                await WriteJsonErrorAsync(response, HttpStatusCode.Forbidden, "loopback_required", "WinWiFi HTTP Bridge only accepts loopback (localhost) connections.");
                return;
            }

            // Permit the known local dashboard origins, but do not expose audit data to arbitrary websites.
            string? origin = request.Headers["Origin"];
            if (!string.IsNullOrEmpty(origin))
            {
                if (!IsAllowedBrowserOrigin(origin, _allowedBrowserOrigins))
                {
                    response.StatusCode = (int)HttpStatusCode.Forbidden;
                    await WriteJsonErrorAsync(response, HttpStatusCode.Forbidden, "origin_not_allowed", "This browser origin is not allowed to access the local WinWiFi bridge.");
                    return;
                }

                response.AddHeader("Access-Control-Allow-Origin", origin);
                response.AddHeader("Vary", "Origin");
                response.AddHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
                response.AddHeader("Access-Control-Allow-Headers", $"Content-Type, Authorization, Accept, {AuthTokenHeader}, X-WinWiFi-Project, X-WinWiFi-Project-Name");
                response.AddHeader("Access-Control-Max-Age", "86400");
                if (RequestsPrivateNetworkAccess(request.Headers["Access-Control-Request-Private-Network"]))
                    response.AddHeader("Access-Control-Allow-Private-Network", "true");
            }

            if (request.HttpMethod.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.NoContent;
                response.Close();
                return;
            }

            string path = request.Url?.AbsolutePath.TrimEnd('/') ?? "";
            bool isApiRequest = path.Equals("/api", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase);
            if (isApiRequest)
            {
                // EventSource cannot attach headers, so the SSE stream may carry
                // the token as a query parameter. Everything else uses the header.
                string? providedToken = request.Headers[AuthTokenHeader];
                if (string.IsNullOrEmpty(providedToken) && path.Equals("/api/events", StringComparison.OrdinalIgnoreCase))
                    providedToken = request.QueryString["token"];

                if (!IsValidAuthToken(providedToken, _authToken))
                {
                    await WriteJsonErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized",
                        "A valid per-launch bridge token is required. Launch the dashboard from WinWiFi or read the token from %LOCALAPPDATA%\\WinWiFi\\bridge.token.");
                    return;
                }
            }

            ApplyProjectContext(request);

            try
            {
                switch (path)
                {
                    case "/api":
                    case "/api/status":
                    case "/api/health":
                        await HandleStatusAsync(response);
                        break;

                    case "/api/adapters":
                        await HandleAdaptersAsync(response);
                        break;

                    case "/api/local-network":
                        await WriteJsonAsync(response, LocalNetworkService.GetNetworkInfo(
                            request.QueryString["adapterId"] ?? _activeAdapterId));
                        break;

                    case "/api/local-network/activity":
                        await WriteJsonAsync(response, await LocalNetworkActivityService.GetAsync(_cts?.Token ?? CancellationToken.None));
                        break;

                    case "/api/network-doctor/check":
                        await HandleNetworkDoctorCheckAsync(request, response);
                        break;

                    case "/api/local-network/scan":
                        await HandleLocalNetworkScanAsync(request, response);
                        break;

                    case "/api/local-network/scan/cancel":
                        await HandleCancelLocalNetworkScanAsync(request, response);
                        break;

                    case "/api/local-network/devices":
                        await HandleLocalNetworkDevicesAsync(request, response);
                        break;

                    case "/api/local-network/devices/known":
                        await HandleLocalDeviceKnownAsync(request, response);
                        break;

                    case "/api/diagnostics":
                        await HandleDiagnosticsAsync(response);
                        break;

                    case "/api/observations":
                        await HandleObservationsAsync(request, response);
                        break;

                    case "/api/network-time-machine":
                        await HandleNetworkTimeMachineBoundsAsync(request, response);
                        break;

                    case "/api/network-time-machine/state":
                        await HandleNetworkTimeMachineStateAsync(request, response);
                        break;

                    case "/api/walk-mode":
                        await HandleWalkModeAsync(request, response);
                        break;

                    case "/api/projects":
                        await HandleProjectsAsync(request, response);
                        break;

                    case "/api/projects/select":
                        await HandleProjectSelectAsync(request, response);
                        break;

                    case "/api/storage/browser-snapshot/import":
                        await HandleBrowserStorageSnapshotImportAsync(request, response);
                        break;

                    case "/api/access-points":
                        await HandleProjectAccessPointsAsync(request, response);
                        break;

                    case "/api/assets":
                        await HandleEnterpriseAssetsAsync(request, response);
                        break;

                    case "/api/assets/import":
                        await HandleEnterpriseAssetsImportAsync(request, response);
                        break;

                    case "/api/assets/export":
                        await HandleEnterpriseAssetsExportAsync(request, response);
                        break;

                    case "/api/networks":
                    case "/api/aps":
                        await HandleNetworksAsync(response);
                        break;

                    case "/api/scan/start":
                        await HandleScanStartAsync(request, response);
                        break;

                    case "/api/scan/stop":
                        await HandleScanStopAsync(response);
                        break;

                    case "/api/scan/status":
                        await HandleScanStatusAsync(response);
                        break;

                    case "/api/scan/refresh":
                        await HandleTriggerScanAsync(request, response);
                        break;

                    case "/api/scan":
                        if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleTriggerScanAsync(request, response);
                        }
                        else
                        {
                            await HandleNetworksAsync(response);
                        }
                        break;

                    case "/api/incidents":
                        await HandleIncidentsAsync(response);
                        break;

                    case "/api/drifts":
                        await HandleDriftsAsync(response);
                        break;

                    case "/api/clients":
                        await HandleClientsAsync(request, response);
                        break;

                    case "/api/connection/status":
                        await HandleConnectionStatusAsync(request, response);
                        break;

                    case "/api/connection/connect":
                        await HandleConnectAsync(request, response);
                        break;

                    case "/api/events":
                        await HandleSseAsync(context);
                        return; // do not close response for SSE

                    case "/api/import/netsh":
                        await HandleImportNetshAsync(request, response);
                        break;

                    case "/api/import/pcap":
                        await HandleImportPcapAsync(request, response);
                        break;

                    case "/api/export/report":
                        await HandleExportReportAsync(response);
                        break;

                    case "/api/export/json":
                        await HandleExportJsonAsync(response);
                        break;

                    case "/api/export/csv":
                        await HandleExportCsvAsync(response);
                        break;

                    default:
                        if (path.StartsWith("/api/assets/", StringComparison.OrdinalIgnoreCase))
                        {
                            await HandleEnterpriseAssetByMacAsync(request, response, path);
                        }
                        else if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                        {
                            await WriteJsonErrorAsync(response, HttpStatusCode.NotFound, "endpoint_not_found", $"Endpoint '{path}' not found.");
                        }
                        else
                        {
                            await HandleDashboardFileAsync(request, response, path);
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                await WriteJsonErrorAsync(response, HttpStatusCode.InternalServerError, "bridge_error", ex.Message);
            }
            finally
            {
                if (path != "/api/events")
                {
                    try { response.Close(); } catch { }
                }
            }
        }

        private async Task HandleStatusAsync(HttpListenerResponse response)
        {
            bool isNativeWlan = _wifiService.IsNativeWifiAvailable();
            var monitor = NpcapMonitorCapability.ProbeAdapter(_wifiService.GetDiagnostics().ActiveAdapterName ?? string.Empty);
            var status = new
            {
                status = "online",
                version = "3.0.3",
                authRequired = true,
                engine = "WinWiFi Native 802.11 Core (.NET 8)",
                platform = Environment.OSVersion.ToString(),
                isWindows = OperatingSystem.IsWindows(),
                isNativeWlanAvailable = isNativeWlan,
                isScanning = _scanner.IsScanning,
                lastScanError = _scanner.LastError,
                activeAdapterId = _activeAdapterId,
                activeAdapterName = _wifiService.GetDiagnostics().ActiveAdapterName,
                activeProjectId = _activeProjectId,
                activeProjectName = _activeProjectName,
                minimumRefreshIntervalSeconds = (int)MinimumRefreshInterval.TotalSeconds,
                backgroundScanIntervalSeconds = (int)_scanner.Interval.TotalSeconds,
                telemetryMode = monitor.MonitorModeSupported ? "Windows WLAN discovery with Npcap passive monitor mode available; packet injection is disabled" : "Windows WLAN discovery; passive monitor capture unavailable on the active adapter; packet injection is disabled",
                capabilities = new
                {
                    nativeWlanAvailable = isNativeWlan,
                    nativeWlanReason = isNativeWlan ? "The C# bridge is using wlanapi.dll for live scans and connection status." : "Windows WLAN API could not be opened.",
                    sqliteAvailable = true,
                    sqliteReason = "The C# bridge persists scan observations and audit data through Microsoft.Data.Sqlite.",
                    eapolParserAvailable = true,
                    eapolParserReason = "The native PCAP dissector is available for imported PCAP/PCAPNG evidence.",
                    npcapInstalled = monitor.NpcapInstalled,
                    monitorModeSupported = monitor.MonitorModeSupported,
                    monitorModeReason = monitor.Reason,
                    captureDevice = monitor.DeviceName
                },
                scanCyclesCompleted = _scanCycleCount,
                accessPointsCount = _latestAccessPoints.Count,
                incidentsCount = _latestIncidents.Count,
                lastScanCompletedAt = _lastScanCompletedAtUtc,
                timestampUtc = DateTime.UtcNow
            };
            await WriteJsonAsync(response, status);
        }

        private static string? ResolveDashboardRoot(string? configuredRoot)
        {
            var candidates = configuredRoot is null
                ? new[] { Path.Combine(AppContext.BaseDirectory, "dashboard"), Path.Combine(AppContext.BaseDirectory, "dist"), Path.Combine(Directory.GetCurrentDirectory(), "dist") }
                : new[] { configuredRoot };
            return candidates.Select(Path.GetFullPath).FirstOrDefault(Directory.Exists);
        }

        private async Task HandleDashboardFileAsync(HttpListenerRequest request, HttpListenerResponse response, string requestPath)
        {
            if (!request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase) && !request.HttpMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "The dashboard accepts GET and HEAD requests.");
                return;
            }

            if (_dashboardRoot is null)
            {
                response.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
                response.ContentType = "text/html; charset=utf-8";
                var missing = Encoding.UTF8.GetBytes("<!doctype html><title>WinWiFi dashboard missing</title><h1>Dashboard files are missing</h1><p>Build the React dashboard or use the Windows release package, which includes the dashboard folder.</p>");
                response.ContentLength64 = missing.Length;
                if (!request.HttpMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase)) await response.OutputStream.WriteAsync(missing);
                return;
            }

            string relativePath;
            try { relativePath = Uri.UnescapeDataString(requestPath).TrimStart('/').Replace('/', Path.DirectorySeparatorChar); }
            catch (UriFormatException) { relativePath = string.Empty; }
            string rootPrefix = _dashboardRoot.EndsWith(Path.DirectorySeparatorChar) ? _dashboardRoot : _dashboardRoot + Path.DirectorySeparatorChar;
            string candidate = Path.GetFullPath(Path.Combine(_dashboardRoot, string.IsNullOrEmpty(relativePath) ? "index.html" : relativePath));
            if (!candidate.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.Forbidden, "invalid_path", "The requested dashboard path is invalid.");
                return;
            }

            if (!File.Exists(candidate)) candidate = Path.Combine(_dashboardRoot, "index.html"); // React client-side route fallback
            if (!File.Exists(candidate))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.NotFound, "dashboard_not_found", "The dashboard entry point is missing from the installed files.");
                return;
            }

            byte[] content = await File.ReadAllBytesAsync(candidate);
            response.ContentType = GetDashboardContentType(Path.GetExtension(candidate));
            response.ContentLength64 = content.Length;
            response.Headers["Cache-Control"] = Path.GetFileName(candidate).Equals("index.html", StringComparison.OrdinalIgnoreCase) ? "no-cache" : "public, max-age=31536000, immutable";
            if (!request.HttpMethod.Equals("HEAD", StringComparison.OrdinalIgnoreCase)) await response.OutputStream.WriteAsync(content);
        }

        private static string GetDashboardContentType(string extension) => extension.ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=utf-8",
            ".js" => "text/javascript; charset=utf-8",
            ".css" => "text/css; charset=utf-8",
            ".json" => "application/json; charset=utf-8",
            ".svg" => "image/svg+xml",
            ".png" => "image/png",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".ico" => "image/x-icon",
            ".woff" => "font/woff",
            ".woff2" => "font/woff2",
            _ => "application/octet-stream"
        };

        private sealed class LanDeviceKnownRequest
        {
            public string IpAddress { get; set; } = string.Empty;
            public string NetworkId { get; set; } = string.Empty;
            public bool IsKnown { get; set; }
        }

        private sealed class LocalNetworkScanRequest
        {
            public bool FullPortScan { get; set; }
            public int ProbesPerSecond { get; set; } = 100;
        }

        private sealed class BrowserStorageSnapshotImportRequest
        {
            public string ImportId { get; set; } = string.Empty;
            public List<BrowserStorageSnapshotEntry> Entries { get; set; } = new();
        }

        private async Task HandleBrowserStorageSnapshotImportAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to import a browser storage snapshot.");
                return;
            }

            byte[]? body = await ReadBodyAsync(request, response, 20 * 1024 * 1024, "Browser storage snapshot exceeds the 20 MB limit.");
            if (body is null) return;
            BrowserStorageSnapshotImportRequest? snapshot;
            try { snapshot = JsonSerializer.Deserialize<BrowserStorageSnapshotImportRequest>(body, JsonOptions); }
            catch (JsonException)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_snapshot", "Browser storage snapshot JSON is invalid.");
                return;
            }

            if (snapshot?.Entries is null || snapshot.Entries.Count == 0)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "empty_snapshot", "No browser storage records were provided.");
                return;
            }

            try
            {
                var result = await _storage.ImportBrowserStorageSnapshotAsync(snapshot.ImportId, snapshot.Entries, _cts?.Token ?? CancellationToken.None);
                await WriteJsonAsync(response, result);
            }
            catch (ArgumentException ex)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_snapshot", ex.Message);
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                await WriteJsonErrorAsync(response, HttpStatusCode.InternalServerError, "snapshot_import_failed", ex.Message);
            }
        }

        private async Task HandleLocalNetworkScanAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to scan the selected local network.");
                return;
            }

            string adapterId = request.QueryString["adapterId"] ?? _activeAdapterId ?? string.Empty;
            LocalNetworkScanRequest scanOptions;
            try { scanOptions = await JsonSerializer.DeserializeAsync<LocalNetworkScanRequest>(request.InputStream, JsonOptions) ?? new(); }
            catch { scanOptions = new(); }
            CancellationTokenSource? scanCts = null;
            bool scanInProgress;
            lock (_localScanSync)
            {
                scanInProgress = _localNetworkScanCts is not null;
                if (!scanInProgress)
                {
                    scanCts = CancellationTokenSource.CreateLinkedTokenSource(_cts?.Token ?? CancellationToken.None);
                    _localNetworkScanCts = scanCts;
                }
            }
            if (scanInProgress)
            {
                response.StatusCode = (int)HttpStatusCode.Conflict;
                await WriteJsonErrorAsync(response, HttpStatusCode.Conflict, "scan_in_progress", "A local network scan is already running.");
                return;
            }
            if (scanCts is null) throw new InvalidOperationException("Local scan cancellation source was not initialized.");
            string projectId = ResolveProjectId(request) ?? _activeProjectId ?? "proj-001";
            LocalNetworkInfo snapshot;
            try
            {
                snapshot = await LocalNetworkService.ScanAsync(adapterId, scanCts.Token,
                    scanOptions.FullPortScan, scanOptions.ProbesPerSecond);
            }
            catch (OperationCanceledException) when (scanCts.IsCancellationRequested)
            {
                snapshot = LocalNetworkService.GetNetworkInfo(adapterId);
                snapshot.Cancelled = true;
                snapshot.Reason = "Scan cancelled by the operator.";
                snapshot.PortScanMode = scanOptions.FullPortScan ? "Full TCP range (cancelled)" : "Common ports (cancelled)";
                await WriteJsonAsync(response, snapshot);
                return;
            }
            finally
            {
                lock (_localScanSync)
                {
                    if (ReferenceEquals(_localNetworkScanCts, scanCts)) _localNetworkScanCts = null;
                }
                scanCts.Dispose();
            }
            if (snapshot.Status != "Available" || string.IsNullOrWhiteSpace(snapshot.NetworkId))
            {
                await WriteJsonAsync(response, snapshot);
                return;
            }

            var previous = (await _storage.GetLanDevicesAsync(projectId, snapshot.NetworkId))
                .Where(d => LocalNetworkService.IsDiscoverableHost(d.IpAddress, snapshot.LocalIp, snapshot.PrefixLength))
                .ToList();
            var byIp = previous.ToDictionary(d => d.IpAddress, StringComparer.OrdinalIgnoreCase);
            foreach (var device in snapshot.Devices)
            {
                if (byIp.TryGetValue(device.IpAddress, out var old))
                {
                    device.IsNew = false;
                    device.IsKnown = old.IsKnown;
                    device.FirstSeen = old.FirstSeen;
                }
            }

            var currentIps = snapshot.Devices.Select(d => d.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var old in previous.Where(d => !currentIps.Contains(d.IpAddress)))
            {
                old.IsOnline = false;
                old.IsNew = false;
                if (!old.Evidence.Contains("Not observed in the latest scan"))
                    old.Evidence.Add("Not observed in the latest scan");
                snapshot.Devices.Add(old);
            }

            await _storage.SaveLanDevicesAsync(projectId, snapshot.NetworkId, snapshot.Devices);
            await WriteJsonAsync(response, snapshot);
        }

        private async Task HandleCancelLocalNetworkScanAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to cancel the active scan.");
                return;
            }
            bool requested;
            lock (_localScanSync)
            {
                requested = _localNetworkScanCts is not null;
                _localNetworkScanCts?.Cancel();
            }
            await WriteJsonAsync(response, new { status = requested ? "cancelling" : "idle", cancelRequested = requested });
        }

        private async Task HandleLocalNetworkDevicesAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string adapterId = request.QueryString["adapterId"] ?? _activeAdapterId ?? string.Empty;
            string projectId = ResolveProjectId(request) ?? _activeProjectId ?? "proj-001";
            var snapshot = LocalNetworkService.GetNetworkInfo(adapterId);
            if (snapshot.Status == "Available")
                snapshot.Devices = (await _storage.GetLanDevicesAsync(projectId, snapshot.NetworkId))
                    .Where(d => LocalNetworkService.IsDiscoverableHost(d.IpAddress, snapshot.LocalIp, snapshot.PrefixLength))
                    .ToList();
            await WriteJsonAsync(response, snapshot);
        }

        private async Task HandleLocalDeviceKnownAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to update a device review status.");
                return;
            }
            var body = await JsonSerializer.DeserializeAsync<LanDeviceKnownRequest>(request.InputStream, JsonOptions) ?? new();
            if (!IPAddress.TryParse(body.IpAddress, out _) || string.IsNullOrWhiteSpace(body.NetworkId))
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_device", "A valid device IP and network are required.");
                return;
            }
            string projectId = ResolveProjectId(request) ?? _activeProjectId ?? "proj-001";
            await _storage.SetLanDeviceKnownAsync(projectId, body.NetworkId, body.IpAddress, body.IsKnown);
            await WriteJsonAsync(response, new { status = "updated", body.IpAddress, body.IsKnown });
        }

        private async Task HandleAdaptersAsync(HttpListenerResponse response)
        {
            var adapters = await _wifiService.GetAdaptersAsync();
            await WriteJsonAsync(response, adapters);
        }

        private async Task HandleDiagnosticsAsync(HttpListenerResponse response)
        {
            var diag = _wifiService.GetDiagnostics();
            await WriteJsonAsync(response, diag);
        }

        private async Task HandleObservationsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to read scan observations.");
                return;
            }

            string? bssid = request.QueryString["bssid"];
            var observations = await _storage.GetScanObservationsAsync(projectId, bssid, 200);
            int total = await _storage.GetTotalObservationsCountAsync(projectId);
            await WriteJsonAsync(response, new { projectId, totalObservationsCount = total, records = observations });
        }

        private async Task HandleNetworkTimeMachineBoundsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (_storage is null)
            {
                await WriteJsonAsync(response, new NetworkTimelineBounds { Message = "Local timeline storage is unavailable in this runtime." });
                return;
            }
            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "Select a project to view its network history.");
                return;
            }
            await WriteJsonAsync(response, await _storage.GetNetworkTimelineBoundsAsync(projectId, _cts?.Token ?? CancellationToken.None));
        }

        private async Task HandleNetworkTimeMachineStateAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (_storage is null)
            {
                await WriteJsonAsync(response, new NetworkTimelineState { Message = "Local timeline storage is unavailable in this runtime." });
                return;
            }
            string? projectId = ResolveProjectId(request);
            string? at = request.QueryString["at"];
            if (projectId is null || !DateTimeOffset.TryParse(at, out _))
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_timeline_request", "A project and valid time are required.");
                return;
            }
            await WriteJsonAsync(response, await _storage.GetNetworkTimeMachineStateAsync(projectId, at!, _cts?.Token ?? CancellationToken.None));
        }

        private async Task HandleWalkModeAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (_storage is null)
            {
                response.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
                await WriteJsonErrorAsync(response, HttpStatusCode.ServiceUnavailable, "storage_unavailable", "Signal measurements cannot be saved because local storage is unavailable.");
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "Select a project before recording a signal measurement.");
                return;
            }

            if (request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(response, await _storage.GetWalkSignalReadingsAsync(projectId, 1000, _cts?.Token ?? CancellationToken.None));
                return;
            }
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use GET to view saved measurements or POST to record the selected access point.");
                return;
            }

            WalkSignalReadingRequest body;
            try { body = await JsonSerializer.DeserializeAsync<WalkSignalReadingRequest>(request.InputStream, JsonOptions) ?? new(); }
            catch (JsonException)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_measurement", "The signal measurement request could not be read.");
                return;
            }

            string bssid = body.Bssid.Trim();
            AccessPoint? observed = _latestAccessPoints.FirstOrDefault(ap => ap.Bssid.Equals(bssid, StringComparison.OrdinalIgnoreCase) && ap.IsActiveInCurrentScan);
            if (observed is null)
            {
                response.StatusCode = (int)HttpStatusCode.Conflict;
                await WriteJsonErrorAsync(response, HttpStatusCode.Conflict, "access_point_not_observed", "That access point is not present in the current live scan. Refresh the scan before recording a location.");
                return;
            }
            try
            {
                var reading = await _storage.SaveWalkSignalReadingAsync(projectId, new WalkSignalReadingRequest
                {
                    Bssid = observed.Bssid,
                    Ssid = observed.Ssid,
                    LocationName = body.LocationName,
                    RssiDbm = observed.Rssi,
                    SignalQuality = observed.SignalQuality
                }, _cts?.Token ?? CancellationToken.None);
                await WriteJsonAsync(response, reading);
            }
            catch (ArgumentException ex)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_measurement", ex.Message);
            }
        }

        private async Task HandleProjectAccessPointsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to read the saved project inventory.");
                return;
            }

            var aps = await _storage.GetAccessPointsAsync(projectId);
            await WriteJsonAsync(response, aps);
        }

        private async Task HandleEnterpriseAssetsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to read or update the enterprise asset registry.");
                return;
            }

            if (request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(response, await _storage.GetEnterpriseAssetsAsync(projectId));
                return;
            }

            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use GET or POST for /api/assets.");
                return;
            }

            byte[]? body = await ReadBodyAsync(request, response, 256 * 1024, "Asset payload exceeds the 256 KB limit.");
            if (body is null) return;

            EnterpriseAssetRecord? incoming;
            try
            {
                incoming = JsonSerializer.Deserialize<EnterpriseAssetRecord>(body, JsonOptions);
            }
            catch (JsonException)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_json", "The asset record is not valid JSON.");
                return;
            }

            var normalized = AssetRegistryCsv.NormalizeAsset(incoming, out string? error);
            if (normalized is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_asset", error ?? "The asset record is invalid.");
                return;
            }

            await _storage.SaveEnterpriseAssetsAsync(projectId, new[] { normalized });
            var saved = (await _storage.GetEnterpriseAssetsAsync(projectId))
                .FirstOrDefault(asset => asset.MacAddress.Equals(normalized.MacAddress, StringComparison.OrdinalIgnoreCase));
            await WriteJsonAsync(response, new { asset = saved ?? normalized });
        }

        private async Task HandleEnterpriseAssetByMacAsync(HttpListenerRequest request, HttpListenerResponse response, string path)
        {
            if (!request.HttpMethod.Equals("DELETE", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Only DELETE is supported on /api/assets/{mac}.");
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to delete an enterprise asset.");
                return;
            }

            string rawMac = Uri.UnescapeDataString(path.Substring("/api/assets/".Length));
            if (rawMac.Contains('/'))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.NotFound, "endpoint_not_found", "Asset endpoints use the form /api/assets/{mac}.");
                return;
            }

            string? mac = AssetRegistryCsv.NormalizeMac(rawMac);
            if (mac is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_mac", "A valid unicast 48-bit MAC address is required.");
                return;
            }

            var existing = await _storage.GetEnterpriseAssetsAsync(projectId);
            if (!existing.Any(asset => asset.MacAddress.Equals(mac, StringComparison.OrdinalIgnoreCase)))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.NotFound, "asset_not_found", $"No registry asset with MAC {mac} exists in this project.");
                return;
            }

            await _storage.DeleteEnterpriseAssetAsync(projectId, mac);
            await WriteJsonAsync(response, new { deleted = mac });
        }

        private async Task HandleEnterpriseAssetsImportAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST for /api/assets/import.");
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to import assets.");
                return;
            }

            byte[]? body = await ReadBodyAsync(request, response, 2 * 1024 * 1024, "Asset CSV exceeds the 2 MB import limit.");
            if (body is null) return;

            string csv = Encoding.UTF8.GetString(body);
            var parsed = AssetRegistryCsv.Parse(csv);
            if (parsed.FatalError is not null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonAsync(response, new
                {
                    error = new { code = "invalid_asset_csv", message = parsed.FatalError },
                    rejected = parsed.Rejected,
                    warnings = parsed.Warnings
                });
                return;
            }

            if (parsed.Rows.Count == 0)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonAsync(response, new
                {
                    error = new { code = "no_valid_assets", message = "No valid asset rows were found in the CSV." },
                    rejected = parsed.Rejected,
                    warnings = parsed.Warnings
                });
                return;
            }

            var existingByMac = (await _storage.GetEnterpriseAssetsAsync(projectId))
                .GroupBy(asset => asset.MacAddress, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

            var toSave = new List<EnterpriseAssetRecord>(parsed.Rows.Count);
            string now = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss");
            foreach (var row in parsed.Rows)
            {
                if (existingByMac.TryGetValue(row.Asset.MacAddress, out var prior))
                {
                    var merged = AssetRegistryCsv.MergeMissingFields(prior, row);
                    if (row.ProvidedFields.Contains(AssetRegistryCsv.FieldLastSeen)) merged.LastSeen = row.Asset.LastSeen;
                    else merged.LastSeen = prior.LastSeen;
                    toSave.Add(merged);
                }
                else
                {
                    if (!row.ProvidedFields.Contains(AssetRegistryCsv.FieldLastSeen)) row.Asset.LastSeen = now;
                    toSave.Add(row.Asset);
                }
            }

            await _storage.SaveEnterpriseAssetsAsync(projectId, toSave);
            await WriteJsonAsync(response, new
            {
                imported = toSave.Count,
                rowsRead = parsed.RowsRead,
                rejected = parsed.Rejected,
                warnings = parsed.Warnings
            });
        }

        private async Task HandleEnterpriseAssetsExportAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use GET for /api/assets/export.");
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "A valid projectId is required to export assets.");
                return;
            }

            var assets = await _storage.GetEnterpriseAssetsAsync(projectId);
            string csv = AssetRegistryCsv.Serialize(assets);
            byte[] payload = Encoding.UTF8.GetBytes(csv);
            byte[] bom = Encoding.UTF8.GetPreamble();

            response.StatusCode = (int)HttpStatusCode.OK;
            response.ContentType = "text/csv; charset=utf-8";
            response.AddHeader("Content-Disposition", $"attachment; filename=\"WinWiFi-Assets-{projectId}.csv\"");
            response.ContentLength64 = bom.Length + payload.Length;
            await response.OutputStream.WriteAsync(bom, 0, bom.Length);
            await response.OutputStream.WriteAsync(payload, 0, payload.Length);
        }

        private static async Task<byte[]?> ReadBodyAsync(HttpListenerRequest request, HttpListenerResponse response, long maxBytes, string tooLargeMessage)
        {
            if (request.ContentLength64 > maxBytes)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.RequestEntityTooLarge, "payload_too_large", tooLargeMessage);
                return null;
            }

            using var ms = new MemoryStream();
            byte[] buffer = new byte[81920];
            int read;
            long total = 0;
            while ((read = await request.InputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > maxBytes)
                {
                    await WriteJsonErrorAsync(response, HttpStatusCode.RequestEntityTooLarge, "payload_too_large", tooLargeMessage);
                    return null;
                }
                ms.Write(buffer, 0, read);
            }
            return ms.ToArray();
        }

        private async Task HandleProjectsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(response, await _storage.GetProjectsAsync());
                return;
            }

            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use GET or POST for projects.");
                return;
            }

            var project = await JsonSerializer.DeserializeAsync<AuditProject>(request.InputStream, JsonOptions);
            if (project is null || !IsValidProjectId(project.Id))
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_project", "A project with a valid id (letters, digits, dot, dash, underscore; max 64) is required.");
                return;
            }

            project.Id = project.Id.Trim();
            project.Name = string.IsNullOrWhiteSpace(project.Name) ? project.Id : project.Name.Trim();
            await _storage.SaveProjectAsync(project);
            await WriteJsonAsync(response, project);
        }

        private sealed class ProjectSelection
        {
            public string ProjectId { get; set; } = string.Empty;
            public string? ProjectName { get; set; }
        }

        private async Task HandleProjectSelectAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to select a project.");
                return;
            }

            var selection = await JsonSerializer.DeserializeAsync<ProjectSelection>(request.InputStream, JsonOptions)
                ?? new ProjectSelection();
            string? projectId = NormalizeProjectId(selection.ProjectId);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_project", "A valid projectId is required.");
                return;
            }

            _activeProjectId = projectId;
            _activeProjectName = string.IsNullOrWhiteSpace(selection.ProjectName) ? _activeProjectName : selection.ProjectName!.Trim();
            _scanner.SetProjectId(projectId);
            await _storage.EnsureProjectAsync(projectId, _activeProjectName);

            // Never carry the previous project's live grid or drift baseline into
            // the newly selected workspace.
            _latestAccessPoints = new List<AccessPoint>();
            _latestIncidents = new List<ThreatFinding>();
            _latestDrifts = new List<SecurityChange>();
            _previousScanByBssid = new Dictionary<string, AccessPoint>(StringComparer.OrdinalIgnoreCase);
            BroadcastSseEvent("project_changed", new { projectId, projectName = _activeProjectName });

            await WriteJsonAsync(response, new
            {
                activeProjectId = projectId,
                activeProjectName = _activeProjectName,
                message = "Project selected. Live telemetry will be persisted to this workspace."
            });
        }

        private async Task HandleNetworksAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, _latestAccessPoints);
        }

        private async Task HandleTriggerScanAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            var remaining = MinimumRefreshInterval - (DateTime.UtcNow - _lastRefreshUtc);
            if (remaining > TimeSpan.Zero)
            {
                response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                await WriteJsonAsync(response, new { error = "Refresh is rate limited.", retryAfterSeconds = (int)Math.Ceiling(remaining.TotalSeconds) });
                return;
            }
            string? requestedAdapterId = request.QueryString["adapterId"];
            if (!string.IsNullOrEmpty(requestedAdapterId))
            {
                _activeAdapterId = requestedAdapterId;
                _scanner.SetActiveAdapter(requestedAdapterId);
            }

            if (string.IsNullOrEmpty(_activeAdapterId))
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonAsync(response, new { error = "Choose a Wi-Fi adapter before requesting telemetry." });
                return;
            }
            // Ask Windows to refresh its WLAN cache before reading it. WlanScan is
            // asynchronous, so give the service a short bounded interval to return
            // current nearby BSS entries.
            await _wifiService.TriggerHardwareScanAsync(_activeAdapterId);
            await Task.Delay(TimeSpan.FromSeconds(2));
            List<AccessPoint> aps = await _wifiService.ScanNetworksAsync(_activeAdapterId);
            _lastRefreshUtc = DateTime.UtcNow;

            _latestAccessPoints = ReconcileLiveAccessPoints(aps);
            var threats = AnalyzeCurrentScan(_latestAccessPoints.Where(ap => ap.IsActiveInCurrentScan).ToList());
            _latestIncidents = threats.Findings;
            _latestDrifts = threats.DetectedDrifts;
            _scanCycleCount++;
            _lastScanCompletedAtUtc = DateTime.UtcNow.ToString("O");

            // Persist into the selected project only. Without an active project
            // the bridge still serves live telemetry but must not invent a
            // shared write target.
            string? projectId = ResolveProjectId(request);
            if (_storage != null && projectId is not null && aps.Count > 0)
            {
                try
                {
                    await _storage.EnsureProjectAsync(projectId, _activeProjectName);
                    await _storage.SaveAccessPointsAsync(projectId, aps);
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"[HttpBridgeServer] DB save error: {dbEx.Message}");
                }
            }

            BroadcastScanResult();
            BroadcastSseEvent("cycle_completed", new
            {
                state = _scanner.CurrentState.ToString(),
                timestamp = _lastScanCompletedAtUtc,
                isScanning = _scanner.IsScanning,
                lastError = _scanner.LastError,
                activeAdapterId = _activeAdapterId,
                scanCyclesCompleted = _scanCycleCount,
                lastDiscoveredCount = _latestAccessPoints.Count,
                lastScanCompletedAt = _lastScanCompletedAtUtc
            });

            await WriteJsonAsync(response, new
            {
                message = "Scan complete",
                count = _latestAccessPoints.Count,
                accessPoints = _latestAccessPoints,
                incidents = _latestIncidents,
                drifts = _latestDrifts
            });
        }

        private async Task HandleScanStartAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string? requestedAdapterId = request.QueryString["adapterId"];
            if (!string.IsNullOrEmpty(requestedAdapterId))
            {
                _activeAdapterId = requestedAdapterId;
                _scanner.SetActiveAdapter(requestedAdapterId);
            }

            if (string.IsNullOrEmpty(_activeAdapterId))
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonAsync(response, new { error = "Choose a Wi-Fi adapter before starting telemetry." });
                return;
            }
            _scanner.SetScanningState(true);
            await WriteJsonAsync(response, new
            {
                status = "scanning",
                isScanning = true,
                activeAdapterId = _activeAdapterId,
                message = $"Windows WLAN discovery started ({WifiBackgroundScanner.MinimumIntervalSeconds}s minimum interval)"
            });
        }

        private async Task HandleScanStopAsync(HttpListenerResponse response)
        {
            _scanner.SetScanningState(false);
            await WriteJsonAsync(response, new
            {
                status = "paused",
                isScanning = false,
                activeAdapterId = _activeAdapterId,
                message = "Scanning paused"
            });
        }

        private async Task HandleScanStatusAsync(HttpListenerResponse response)
        {
            var diag = _wifiService.GetDiagnostics();
            await WriteJsonAsync(response, new
            {
                isScanning = _scanner.IsScanning,
                state = _scanner.CurrentState.ToString(),
                lastError = _scanner.LastError,
                activeAdapterId = _activeAdapterId,
                scanCyclesCompleted = _scanCycleCount,
                lastDiscoveredCount = _latestAccessPoints.Count,
                lastScanCompletedAt = _lastScanCompletedAtUtc,
                diagnostics = diag
            });
        }

        private async Task HandleIncidentsAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, _latestIncidents);
        }

        private async Task HandleDriftsAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, _latestDrifts);
        }

        private async Task HandleClientsAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            // Station records dissected from a capture imported during this
            // session come first; after a restart the same records are read back
            // from the project database. Windows' WLAN API lists BSS entries only
            // and never names the stations attached to a neighbouring access
            // point, so an empty list means no capture was dissected, not no client.
            if (_latestClients.Count > 0)
            {
                await WriteJsonAsync(response, _latestClients);
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (_storage is not null && projectId is not null)
            {
                try
                {
                    await WriteJsonAsync(response, await _storage.GetStationClientsAsync(projectId));
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[HttpBridgeServer] Station client read error: {ex.Message}");
                }
            }

            await WriteJsonAsync(response, _latestClients);
        }

        private async Task HandleConnectionStatusAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            string adapterId = request.QueryString["adapterId"] ?? _activeAdapterId ?? string.Empty;
            if (_wifiService is NativeWifiService native)
                await WriteJsonAsync(response, native.GetConnectionStatus(adapterId));
            else
                await WriteJsonAsync(response, new NetworkConnectionStatus { State = "Unavailable", Reason = "Native Windows WLAN service is unavailable." });
        }

        private async Task HandleNetworkDoctorCheckAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed", "Use POST to check the currently connected Wi-Fi network.");
                return;
            }

            string? projectId = ResolveProjectId(request);
            if (projectId is null)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "project_required", "Select a project before saving a network fingerprint.");
                return;
            }

            NetworkDoctorRequest checkRequest;
            try { checkRequest = await JsonSerializer.DeserializeAsync<NetworkDoctorRequest>(request.InputStream, JsonOptions) ?? new(); }
            catch (JsonException)
            {
                response.StatusCode = (int)HttpStatusCode.BadRequest;
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request", "Network check request is invalid.");
                return;
            }

            string adapterId = string.IsNullOrWhiteSpace(checkRequest.AdapterId) ? _activeAdapterId ?? string.Empty : checkRequest.AdapterId;
            if (_wifiService is not NativeWifiService native)
            {
                await WriteJsonAsync(response, new NetworkDoctorCheck { Status = "Unavailable", Reason = "Windows WLAN connection status is unavailable in this runtime." });
                return;
            }

            var connection = native.GetConnectionStatus(adapterId);
            if (!string.Equals(connection.State, "Connected", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(response, new NetworkDoctorCheck { Status = "Unavailable", AdapterId = adapterId, Reason = string.IsNullOrWhiteSpace(connection.Reason) ? "Connect to a Wi-Fi network before checking it." : connection.Reason });
                return;
            }

            var network = LocalNetworkService.GetNetworkInfo(adapterId);
            var connectedAp = _latestAccessPoints.FirstOrDefault(ap => string.Equals(ap.Bssid, connection.Bssid, StringComparison.OrdinalIgnoreCase));
            var approvedAssets = (await _storage.GetEnterpriseAssetsAsync(projectId, _cts?.Token ?? CancellationToken.None))
                .Where(asset => string.Equals(asset.ApprovalStatus, "Approved", StringComparison.OrdinalIgnoreCase))
                .Select(asset => asset.MacAddress)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var scopedAps = _latestAccessPoints
                .Where(ap => ap.IsActiveInCurrentScan && (string.Equals(ap.ApprovedStatus, "Approved", StringComparison.OrdinalIgnoreCase)
                    || approvedAssets.Contains(ap.Bssid)
                    || string.Equals(ap.Bssid, connection.Bssid, StringComparison.OrdinalIgnoreCase)))
                .ToList();
            if (connectedAp is not null && scopedAps.All(ap => !string.Equals(ap.Bssid, connectedAp.Bssid, StringComparison.OrdinalIgnoreCase)))
                scopedAps.Add(connectedAp);

            NetworkFingerprint? baseline = await _storage.GetNetworkFingerprintAsync(projectId, connection.Ssid, _cts?.Token ?? CancellationToken.None);
            var check = await NetworkDoctorService.CheckAsync(adapterId, connection, network, connectedAp, scopedAps, baseline,
                checkRequest.ReplaceFingerprint, _cts?.Token ?? CancellationToken.None);

            bool recordable = check.FingerprintVerdict == "first-seen" || check.FingerprintVerdict == "matches"
                || checkRequest.ReplaceFingerprint && check.FingerprintVerdict == "changed";
            if (recordable && !string.IsNullOrWhiteSpace(check.Security) && check.Security != "Unknown" && !string.IsNullOrWhiteSpace(check.GatewayIp))
            {
                string now = DateTimeOffset.UtcNow.ToString("O");
                await _storage.SaveNetworkFingerprintAsync(new NetworkFingerprint
                {
                    ProjectId = projectId,
                    Ssid = check.Ssid,
                    Bssid = check.Bssid,
                    GatewayIp = check.GatewayIp,
                    GatewayMac = check.GatewayMac,
                    DnsServers = check.DnsServers,
                    Security = check.Security,
                    Cipher = check.Cipher,
                    AuthorizedApPattern = scopedAps.Where(ap => string.Equals(ap.Ssid, connection.Ssid, StringComparison.Ordinal))
                        .Select(ap => ap.Bssid).Append(connection.Bssid).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList(),
                    FirstSeenAt = baseline?.FirstSeenAt ?? now,
                    LastSeenAt = now
                }, _cts?.Token ?? CancellationToken.None);
                if (checkRequest.ReplaceFingerprint && check.FingerprintVerdict == "changed")
                    NetworkDoctorService.MarkFingerprintReplaced(check);
            }
            await WriteJsonAsync(response, check);
        }

        private sealed class ConnectRequest
        {
            public string AdapterId { get; set; } = string.Empty;
            public string Bssid { get; set; } = string.Empty;
            public string Ssid { get; set; } = string.Empty;
            public string? Password { get; set; }
            public bool AuthorizationConfirmed { get; set; }
            public List<string> AuthorizedBssids { get; set; } = new();
        }

        private async Task HandleConnectAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            if (!request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                await WriteJsonAsync(response, new { error = "Use POST to request a connection." });
                return;
            }
            var payload = await JsonSerializer.DeserializeAsync<ConnectRequest>(request.InputStream, JsonOptions) ?? new ConnectRequest();
            bool inLiveScan = _latestAccessPoints.Any(ap => ap.Bssid.Equals(payload.Bssid, StringComparison.OrdinalIgnoreCase) && ap.Ssid.Equals(payload.Ssid, StringComparison.Ordinal));
            bool authorized = payload.AuthorizationConfirmed && payload.AuthorizedBssids.Any(bssid => bssid.Equals(payload.Bssid, StringComparison.OrdinalIgnoreCase));
            if (!inLiveScan || !authorized)
            {
                response.StatusCode = (int)HttpStatusCode.Forbidden;
                await WriteJsonAsync(response, new { error = "Connection requires an observed BSSID and explicit Project & Scope authorization confirmation." });
                return;
            }
            if (_wifiService is not NativeWifiService native)
            {
                response.StatusCode = (int)HttpStatusCode.NotImplemented;
                await WriteJsonAsync(response, new { error = "Native Windows WLAN connection service is unavailable." });
                return;
            }
            // Password is deliberately not logged or persisted by WinWiFi.
            var result = native.ConnectToAuthorizedNetwork(string.IsNullOrWhiteSpace(payload.AdapterId) ? _activeAdapterId ?? string.Empty : payload.AdapterId, payload.Ssid, payload.Password);
            await WriteJsonAsync(response, result);
        }

        private async Task HandleImportNetshAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            const long MaxNetshSizeBytes = 10 * 1024 * 1024; // 10 MB limit
            if (request.ContentLength64 > MaxNetshSizeBytes)
            {
                response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
                await WriteJsonAsync(response, new { error = "Netsh import payload exceeds maximum limit of 10 MB." });
                return;
            }

            using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            string netshOutput = await reader.ReadToEndAsync();

            var nativeSvc = _wifiService as NativeWifiService;
            if (nativeSvc != null)
            {
                var aps = nativeSvc.ParseNetshBssidOutput(netshOutput);
                _latestAccessPoints = aps;
                var threats = AnalyzeCurrentScan(aps);
                _latestIncidents = threats.Findings;
                _latestDrifts = threats.DetectedDrifts;
                await WriteJsonAsync(response, new { message = "Netsh output parsed", count = aps.Count, accessPoints = aps, incidents = _latestIncidents, drifts = _latestDrifts });
            }
            else
            {
                await WriteJsonAsync(response, new { error = "Native service not available" });
            }
        }

        private async Task HandleImportPcapAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            const long MaxPcapSizeBytes = 50 * 1024 * 1024; // 50 MB limit
            if (request.ContentLength64 > MaxPcapSizeBytes)
            {
                response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
                await WriteJsonAsync(response, new { error = "PCAP import payload exceeds maximum limit of 50 MB." });
                return;
            }

            using var ms = new MemoryStream();
            byte[] buffer = new byte[81920];
            int read;
            long totalRead = 0;
            while ((read = await request.InputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                totalRead += read;
                if (totalRead > MaxPcapSizeBytes)
                {
                    response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
                    await WriteJsonAsync(response, new { error = "PCAP stream exceeded 50 MB limit." });
                    return;
                }
                ms.Write(buffer, 0, read);
            }
            byte[] bytes = ms.ToArray();

            PcapDissectorResult result;
            try
            {
                result = _pcapDissector.DissectBytes(bytes);
            }
            catch (InvalidDataException ex)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "invalid_capture", ex.Message);
                return;
            }
            catch (NotSupportedException ex)
            {
                await WriteJsonErrorAsync(response, HttpStatusCode.BadRequest, "unsupported_capture", ex.Message);
                return;
            }

            // Imported evidence is returned to the caller with IMPORTED
            // provenance. It must never replace the live scan state, because
            // /api/networks and the SSE stream are labelled as live telemetry.
            // Analyze without the live baseline so an import cannot alter drift
            // comparisons for the next real scan.
            result.Incidents = _securityAnalyzer.AnalyzeThreatsAndDrift(result.AccessPoints, null).Findings;

            // The dissected capture is the only real source of station records, so
            // they are held for this session and saved to the project database to
            // survive a restart.
            _latestClients = result.Clients;
            string? stationProjectId = ResolveProjectId(request);
            if (_storage is not null && stationProjectId is not null && result.Clients.Count > 0)
            {
                try
                {
                    await _storage.SaveStationClientsAsync(stationProjectId, result.Clients);
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"[HttpBridgeServer] Station client save error: {dbEx.Message}");
                }
            }

            await WriteJsonAsync(response, result);
        }

        private async Task HandleExportReportAsync(HttpListenerResponse response)
        {
            string report = _reportGenerator.GenerateMarkdownReport(
                "Audit-Session-Live",
                "WinWiFi Local Live Security Audit",
                _latestAccessPoints,
                _latestIncidents
            );

            response.ContentType = "text/markdown; charset=utf-8";
            byte[] buffer = Encoding.UTF8.GetBytes(report);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }

        private async Task HandleExportJsonAsync(HttpListenerResponse response)
        {
            var bundle = new
            {
                metadata = new
                {
                    generator = "WinWiFi 3.0.3",
                    exportedAt = DateTime.UtcNow,
                    platform = Environment.OSVersion.ToString()
                },
                accessPoints = _latestAccessPoints,
                incidents = _latestIncidents,
                clients = _latestClients
            };

            await WriteJsonAsync(response, bundle);
        }

        private async Task HandleExportCsvAsync(HttpListenerResponse response)
        {
            var sb = new StringBuilder();
            sb.AppendLine("BSSID,SSID,RSSI,Channel,Band,Security,Cipher,Vendor,SecurityScore,IssuesCount,LastSeen");
            foreach (var ap in _latestAccessPoints)
            {
                sb.AppendLine($"\"{ap.Bssid}\",\"{ap.Ssid.Replace("\"", "\"\"")}\",{ap.Rssi},{ap.Channel},\"{ap.Band}\",\"{ap.Security}\",\"{ap.Cipher}\",\"{ap.Vendor}\",{ap.SecurityScore},{ap.SecurityIssues.Count},\"{ap.LastSeen}\"");
            }

            response.ContentType = "text/csv; charset=utf-8";
            byte[] buffer = Encoding.UTF8.GetBytes(sb.ToString());
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }

        private async Task HandleSseAsync(HttpListenerContext context)
        {
            var response = context.Response;
            response.ContentType = "text/event-stream";
            response.Headers.Add("Cache-Control", "no-cache");
            response.Headers.Add("Connection", "keep-alive");

            string clientId = Guid.NewGuid().ToString();
            var writer = new StreamWriter(response.OutputStream, Encoding.UTF8) { AutoFlush = true };
            _sseClients[clientId] = writer;

            try
            {
                await writer.WriteLineAsync($"event: connected\ndata: {{\"clientId\":\"{clientId}\",\"time\":\"{DateTime.UtcNow:O}\"}}\n\n");

                // Keep SSE connection open until client disconnects or cancellation
                while (_cts != null && !_cts.IsCancellationRequested)
                {
                    await Task.Delay(15000);
                    try
                    {
                        await writer.WriteLineAsync(": ping\n\n");
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            catch
            {
                // client disconnected
            }
            finally
            {
                _sseClients.TryRemove(clientId, out _);
                try { writer.Dispose(); } catch { }
                try { response.Close(); } catch { }
            }
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true
        };

        private void BroadcastSseEvent(string eventName, object data)
        {
            string json = JsonSerializer.Serialize(data, JsonOptions);
            string message = $"event: {eventName}\ndata: {json}\n\n";

            lock (_sseWriteLock)
            {
                foreach (var kvp in _sseClients)
                {
                    try
                    {
                        kvp.Value.Write(message);
                        kvp.Value.Flush();
                    }
                    catch
                    {
                        _sseClients.TryRemove(kvp.Key, out _);
                    }
                }
            }
        }

        private static async Task WriteJsonAsync(HttpListenerResponse response, object data)
        {
            response.ContentType = "application/json; charset=utf-8";
            string json = JsonSerializer.Serialize(data, JsonOptions);
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }

        private static Task WriteJsonErrorAsync(HttpListenerResponse response, HttpStatusCode status, string code, string message)
        {
            response.StatusCode = (int)status;
            return WriteJsonAsync(response, new { error = new { code, message } });
        }
    }
}
