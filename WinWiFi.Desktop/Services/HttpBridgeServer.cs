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
        private readonly NativeSelfTests _selfTests;
        private readonly string? _dashboardRoot;

        private CancellationTokenSource? _cts;
        private Task? _listenerTask;
        private readonly ConcurrentDictionary<string, StreamWriter> _sseClients = new();
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
        private List<StationClientRecord> _latestClients = new();
        private Dictionary<string, AccessPoint> _previousScanByBssid = new(StringComparer.OrdinalIgnoreCase);
        private string? _activeAdapterId;
        private string? _activeProjectId;
        private string? _activeProjectName;
        private int _scanCycleCount = 0;
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
            _selfTests = new NativeSelfTests();

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
                timestamp = DateTime.UtcNow
            });
        }

        private void OnScannerDiagnosticsUpdated(ScanDiagnostics diag)
        {
            BroadcastSseEvent("diagnostics", diag);
        }

        private void OnNetworksDiscovered(List<AccessPoint> aps)
        {
            _latestAccessPoints = ReconcileLiveAccessPoints(aps);
            var threats = AnalyzeCurrentScan(_latestAccessPoints.Where(ap => ap.IsActiveInCurrentScan).ToList());
            _latestIncidents = threats.Findings;

            // Broadcast to SSE clients
            BroadcastSseEvent("scan_result", new
            {
                cycle = _scanCycleCount,
                timestamp = DateTime.UtcNow,
                accessPointsCount = _latestAccessPoints.Count,
                accessPoints = _latestAccessPoints,
                incidents = _latestIncidents
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
            BroadcastSseEvent("cycle_completed", stats);
        }

        public async Task StartAsync()
        {
            if (_listener.IsListening) return;

            _cts = new CancellationTokenSource();
            _listener.Start();
            PersistAuthToken();

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
                        _latestAccessPoints = ReconcileLiveAccessPoints(initialAps);
                        var initialThreats = AnalyzeCurrentScan(_latestAccessPoints);
                        _latestIncidents = initialThreats.Findings;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[HttpBridgeServer] Adapter discovery failed: {ex.Message}");
            }

            // Continue bounded Windows WLAN discovery after the startup scan.
            _ = _scanner.StartAsync(_cts.Token);

            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
            Console.WriteLine($"[HttpBridgeServer] Listening on http://127.0.0.1:{_port}/ (token file: {BridgeTokenFilePath()})");
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
                try { await _listenerTask; } catch { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
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
                response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
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

                    case "/api/diagnostics":
                        await HandleDiagnosticsAsync(response);
                        break;

                    case "/api/observations":
                        await HandleObservationsAsync(request, response);
                        break;

                    case "/api/projects":
                        await HandleProjectsAsync(request, response);
                        break;

                    case "/api/projects/select":
                        await HandleProjectSelectAsync(request, response);
                        break;

                    case "/api/access-points":
                        await HandleProjectAccessPointsAsync(request, response);
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

                    case "/api/clients":
                        await HandleClientsAsync(response);
                        break;

                    case "/api/connection/status":
                        await HandleConnectionStatusAsync(request, response);
                        break;

                    case "/api/connection/connect":
                        await HandleConnectAsync(request, response);
                        break;

                    case "/api/selftests":
                    case "/api/tests":
                        await HandleSelfTestsAsync(response);
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
                        if (path.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
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
            _scanCycleCount++;

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
                    await _storage.SaveScanObservationsBatchAsync(projectId, _activeAdapterId ?? "default", _scanCycleCount, aps);
                }
                catch (Exception dbEx)
                {
                    Console.WriteLine($"[HttpBridgeServer] DB save error: {dbEx.Message}");
                }
            }

            // Broadcast to SSE clients
            BroadcastSseEvent("scan_result", new
            {
                cycle = _scanCycleCount,
                timestamp = DateTime.UtcNow,
                accessPointsCount = _latestAccessPoints.Count,
                accessPoints = _latestAccessPoints,
                incidents = _latestIncidents
            });

            await WriteJsonAsync(response, new { message = "Scan complete", count = _latestAccessPoints.Count, accessPoints = _latestAccessPoints, incidents = _latestIncidents });
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
                diagnostics = diag
            });
        }

        private async Task HandleIncidentsAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, _latestIncidents);
        }

        private async Task HandleClientsAsync(HttpListenerResponse response)
        {
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

        private async Task HandleSelfTestsAsync(HttpListenerResponse response)
        {
            var results = await _selfTests.RunAllTestsAsync();
            await WriteJsonAsync(response, results);
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
                await WriteJsonAsync(response, new { message = "Netsh output parsed", count = aps.Count, accessPoints = aps, incidents = _latestIncidents });
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

            var result = _pcapDissector.DissectBytes(bytes);
            _latestAccessPoints = result.AccessPoints;
            _latestClients = result.Clients;
            var threats = AnalyzeCurrentScan(result.AccessPoints);
            _latestIncidents = threats.Findings;

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

            foreach (var kvp in _sseClients)
            {
                try
                {
                    Task.Run(async () =>
                    {
                        try
                        {
                            await kvp.Value.WriteLineAsync(message);
                        }
                        catch
                        {
                            _sseClients.TryRemove(kvp.Key, out _);
                        }
                    });
                }
                catch
                {
                    _sseClients.TryRemove(kvp.Key, out _);
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
