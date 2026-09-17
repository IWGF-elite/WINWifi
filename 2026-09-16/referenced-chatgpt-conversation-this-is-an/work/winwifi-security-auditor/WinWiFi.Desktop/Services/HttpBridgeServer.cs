using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Channels;
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
        private readonly WifiBackgroundScanner _scanner;
        private readonly NativeSelfTests _selfTests;

        private CancellationTokenSource? _cts;
        private Task? _listenerTask;
        private readonly ConcurrentDictionary<string, SseClient> _sseClients = new();

        private List<AccessPoint> _latestAccessPoints = new();
        private List<ThreatFinding> _latestIncidents = new();
        private List<StationClientRecord> _latestClients = new();
        private string _activeProjectId = "proj-default";
        private string? _activeAdapterId;
        private int _scanCycleCount = 0;
        private DateTime _lastRefreshUtc = DateTime.MinValue;
        private static readonly TimeSpan MinimumRefreshInterval = TimeSpan.FromSeconds(WifiBackgroundScanner.MinimumIntervalSeconds);

        public HttpBridgeServer(
            int port = 38989,
            INativeWifiService? wifiService = null,
            SecurityAnalyzer? securityAnalyzer = null,
            PcapDissector? pcapDissector = null,
            ReportGenerator? reportGenerator = null,
            SqliteStorageService? storage = null,
            WifiBackgroundScanner? scanner = null)
        {
            _port = port;
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
            _listener.Prefixes.Add($"http://localhost:{_port}/");

            _securityAnalyzer = securityAnalyzer ?? new SecurityAnalyzer();
            _wifiService = wifiService ?? new NativeWifiService(_securityAnalyzer);
            _pcapDissector = pcapDissector ?? new PcapDissector();
            _reportGenerator = reportGenerator ?? new ReportGenerator();
            _storage = storage ?? new SqliteStorageService();
            // Bridge and WPF must use the same persistence behavior.  Previously the bridge
            // constructed a scanner without storage, silently dropping periodic observations.
            _scanner = scanner ?? new WifiBackgroundScanner(_wifiService, _securityAnalyzer, _storage);
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
            _latestAccessPoints = aps;
            var threats = _securityAnalyzer.AnalyzeThreatsAndDrift(aps, null);
            _latestIncidents = threats.Findings;

            // Broadcast to SSE clients
            BroadcastSseEvent("scan_result", new
            {
                cycle = _scanCycleCount,
                timestamp = DateTime.UtcNow,
                accessPointsCount = aps.Count,
                accessPoints = aps,
                incidents = _latestIncidents
            });
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
            try
            {
                _listener.Start();
            }
            catch (HttpListenerException exception)
            {
                _cts.Dispose();
                _cts = null;
                throw new InvalidOperationException($"Unable to start the local HTTP bridge on port {_port}. Check that the port is available and that the host permits HttpListener. {exception.Message}", exception);
            }

            // The worker is started paused. The browser must select an adapter and explicitly start telemetry.
            _ = _scanner.StartAsync(_cts.Token);

            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
            Console.WriteLine($"[HttpBridgeServer] Listening on http://127.0.0.1:{_port}/");
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
                try { client.Writer.Dispose(); } catch { }
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
            _storage.Dispose();
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

            // CORS headers
            response.AddHeader("Access-Control-Allow-Origin", "*");
            response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            response.AddHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept");
            response.AddHeader("Access-Control-Max-Age", "86400");

            // Localhost-only security enforcement
            if (!request.IsLocal)
            {
                response.StatusCode = (int)HttpStatusCode.Forbidden;
                await WriteJsonAsync(response, new { error = "Forbidden: WinWiFi HTTP Bridge only accepts loopback (localhost) connections." });
                return;
            }

            if (request.HttpMethod.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                response.StatusCode = (int)HttpStatusCode.NoContent;
                response.Close();
                return;
            }

            string path = request.Url?.AbsolutePath.TrimEnd('/') ?? "";
            try
            {
                SetActiveProject(request);
                switch (path)
                {
                    case "":
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
                        await HandleObservationsAsync(response);
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
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                        await WriteJsonAsync(response, new { error = $"Endpoint '{path}' not found." });
                        break;
                }
            }
            catch (Exception ex)
            {
                response.StatusCode = (int)HttpStatusCode.InternalServerError;
                await WriteJsonAsync(response, new { error = ex.Message, stack = ex.StackTrace });
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
            int schemaVersion = await _storage.GetSchemaVersionAsync();
            var status = new
            {
                status = "online",
                version = "3.0.0",
                engine = "WinWiFi Native 802.11 Core (.NET 8)",
                platform = Environment.OSVersion.ToString(),
                isWindows = OperatingSystem.IsWindows(),
                isNativeWlanAvailable = isNativeWlan,
                isScanning = _scanner.IsScanning,
                activeAdapterId = _activeAdapterId,
                activeProjectId = _activeProjectId,
                databasePath = _storage.DatabasePath,
                databaseSchemaVersion = schemaVersion,
                activeAdapterName = _wifiService.GetDiagnostics().ActiveAdapterName,
                minimumRefreshIntervalSeconds = (int)MinimumRefreshInterval.TotalSeconds,
                telemetryMode = "Windows WLAN BSS-cache observation; no monitor-mode capture or packet injection",
                scanCyclesCompleted = _scanCycleCount,
                accessPointsCount = _latestAccessPoints.Count,
                incidentsCount = _latestIncidents.Count,
                timestampUtc = DateTime.UtcNow
            };
            await WriteJsonAsync(response, status);
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

        private async Task HandleObservationsAsync(HttpListenerResponse response)
        {
            var observations = await _storage.GetScanObservationsAsync(_activeProjectId, null, 200);
            int total = await _storage.GetTotalObservationsCountAsync(_activeProjectId);
            await WriteJsonAsync(response, new { totalObservationsCount = total, records = observations });
        }

        private async Task HandleNetworksAsync(HttpListenerResponse response)
        {
            if (_latestAccessPoints.Count == 0)
            {
                _latestAccessPoints = await _storage.GetAccessPointsAsync(_activeProjectId);
            }
            await WriteJsonAsync(response, _latestAccessPoints);
        }

        private async Task HandleTriggerScanAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            SetActiveProject(request);
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
            // NativeWifiService owns the scan lock and notification-driven scan lifecycle.
            // Do not duplicate WlanScan in the bridge.
            List<AccessPoint> aps = await _wifiService.ScanNetworksAsync(_activeAdapterId);
            _lastRefreshUtc = DateTime.UtcNow;

            _latestAccessPoints = aps;
            var threats = _securityAnalyzer.AnalyzeThreatsAndDrift(aps, null);
            _latestIncidents = threats.Findings;
            _scanCycleCount++;

            // Persist into SQLite storage
            if (_storage != null && aps.Count > 0)
            {
                try
                {
                    await _storage.SaveAccessPointsAsync(_activeProjectId, aps);
                    await _storage.SaveScanObservationsBatchAsync(_activeProjectId, _activeAdapterId ?? "default", _scanCycleCount, aps);
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
                accessPointsCount = aps.Count,
                accessPoints = aps,
                incidents = _latestIncidents
            });

            await WriteJsonAsync(response, new { message = "Scan complete", count = aps.Count, accessPoints = aps, incidents = _latestIncidents });
        }

        private async Task HandleScanStartAsync(HttpListenerRequest request, HttpListenerResponse response)
        {
            SetActiveProject(request);
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
            _scanner.SetActiveProject(_activeProjectId);
            await WriteJsonAsync(response, new
            {
                status = "scanning",
                isScanning = true,
                activeAdapterId = _activeAdapterId,
                message = $"Bounded BSS-cache telemetry started ({WifiBackgroundScanner.MinimumIntervalSeconds}s minimum interval)"
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
                activeAdapterId = _activeAdapterId,
                scanCyclesCompleted = _scanCycleCount,
                lastDiscoveredCount = _latestAccessPoints.Count,
                diagnostics = diag
            });
        }

        private async Task HandleIncidentsAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, await _storage.GetIncidentsAsync(_activeProjectId));
        }

        private async Task HandleClientsAsync(HttpListenerResponse response)
        {
            await WriteJsonAsync(response, await _storage.GetStationClientsAsync(_activeProjectId));
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
                var threats = _securityAnalyzer.AnalyzeThreatsAndDrift(aps, null);
                _latestIncidents = threats.Findings;
                if (aps.Count > 0)
                {
                    await _storage.SaveAccessPointsAsync(_activeProjectId, aps);
                    await _storage.SaveScanObservationsBatchAsync(_activeProjectId, "netsh-import", ++_scanCycleCount, aps);
                }
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
            var threats = _securityAnalyzer.AnalyzeThreatsAndDrift(result.AccessPoints, null);
            _latestIncidents = threats.Findings;

            // Imported forensic observations are durable. Native BSS scans intentionally do not
            // manufacture station records; these clients originate solely from the capture.
            if (result.AccessPoints.Count > 0)
            {
                await _storage.SaveAccessPointsAsync(_activeProjectId, result.AccessPoints);
                await _storage.SaveScanObservationsBatchAsync(_activeProjectId, "pcap-import", ++_scanCycleCount, result.AccessPoints);
            }
            if (result.Clients.Count > 0) await _storage.SaveStationClientsAsync(_activeProjectId, result.Clients);
            foreach (var handshake in result.Handshakes) await _storage.SaveHandshakeAsync(_activeProjectId, handshake);

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
                    generator = "WinWiFi 3.0.0",
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
            var client = new SseClient(new StreamWriter(response.OutputStream, Encoding.UTF8) { AutoFlush = true });
            _sseClients[clientId] = client;

            try
            {
                await client.Writer.WriteLineAsync($"event: connected\ndata: {{\"clientId\":\"{clientId}\",\"time\":\"{DateTime.UtcNow:O}\"}}\n\n");

                // A bounded per-client queue prevents slow browsers from delaying scans or
                // other subscribers. Old telemetry is intentionally discarded before newer state.
                while (_cts != null && !_cts.IsCancellationRequested)
                {
                    var waitForMessage = client.Messages.Reader.WaitToReadAsync(_cts.Token).AsTask();
                    var keepAlive = Task.Delay(TimeSpan.FromSeconds(15), _cts.Token);
                    if (await Task.WhenAny(waitForMessage, keepAlive) == waitForMessage)
                    {
                        while (client.Messages.Reader.TryRead(out var message))
                        {
                            await client.Writer.WriteAsync(message);
                        }
                    }
                    else
                    {
                        await client.Writer.WriteLineAsync(": ping\n");
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
                client.Messages.Writer.TryComplete();
                try { client.Writer.Dispose(); } catch { }
                try { response.Close(); } catch { }
            }
        }

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        private void BroadcastSseEvent(string eventName, object data)
        {
            string json = JsonSerializer.Serialize(data, JsonOptions);
            string message = $"event: {eventName}\ndata: {json}\n\n";

            foreach (var kvp in _sseClients)
            {
                if (!kvp.Value.Messages.Writer.TryWrite(message))
                {
                    _sseClients.TryRemove(kvp.Key, out _);
                }
            }
        }

        private sealed class SseClient
        {
            public SseClient(StreamWriter writer)
            {
                Writer = writer;
                Messages = Channel.CreateBounded<string>(new BoundedChannelOptions(64)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                });
            }

            public StreamWriter Writer { get; }
            public Channel<string> Messages { get; }
        }

        private void SetActiveProject(HttpListenerRequest request)
        {
            string? requestedProjectId = request.QueryString["projectId"];
            if (string.IsNullOrWhiteSpace(requestedProjectId)) return;
            _activeProjectId = requestedProjectId.Trim();
            _scanner.SetActiveProject(_activeProjectId);
        }

        private static async Task WriteJsonAsync(HttpListenerResponse response, object data)
        {
            response.ContentType = "application/json; charset=utf-8";
            string json = JsonSerializer.Serialize(data, JsonOptions);
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
        }
    }
}
