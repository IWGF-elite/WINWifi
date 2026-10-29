using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using WinWiFi.Services;
using WinWiFi.Tests;

namespace WinWiFi
{
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
#if WINDOWS_DESKTOP
            // WinExe applications do not inherit a console automatically. Attach to
            // an existing terminal (or create one when launched from Explorer) so
            // the documented CLI options can display their results.
            if (args.Length > 0) EnsureConsole();
#endif
            // 1. Help argument
            if (args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("-h", StringComparison.OrdinalIgnoreCase) || a.Equals("/?", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("==========================================================");
                Console.WriteLine("  WinWiFi 3.0.4 - Native 802.11 Security Auditor & Bridge ");
                Console.WriteLine("==========================================================");
                Console.WriteLine("Usage: winwifi-cli [options]\n");
                Console.WriteLine("Options:");
                Console.WriteLine("  --bridge, -b         Launch HTTP/SSE bridge daemon for Web UI (default port: 38989)");
                Console.WriteLine("  --port, -p <number>  Specify custom bridge port (default: 38989)");
                Console.WriteLine("  --scan, -s           Read the selected Windows WLAN BSS cache once and print results");
                Console.WriteLine("  --adapters, -a       List detected wireless network adapters and driver capabilities");
                Console.WriteLine("  --test, -t           Run native 802.11 security, RF math, and PCAP audit tests");
                Console.WriteLine("  --help, -h, /?       Display this help message\n");
                return 0;
            }

            // 2. Adapters argument
            if (args.Any(a => a.Equals("--adapters", StringComparison.OrdinalIgnoreCase) || a.Equals("-a", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("==========================================================");
                Console.WriteLine("  WinWiFi 3.0.4 - Detected Wireless Network Adapters       ");
                Console.WriteLine("==========================================================\n");

                var wifiService = new NativeWifiService(new SecurityAnalyzer());
                var adapters = wifiService.GetAdaptersAsync().GetAwaiter().GetResult();

                if (adapters.Count == 0)
                {
                    Console.WriteLine("No Wi-Fi adapters detected on this system.");
                }
                else
                {
                    Console.WriteLine($"Found {adapters.Count} Wi-Fi adapter(s):\n");
                    foreach (var ad in adapters)
                    {
                        Console.WriteLine($"  ID:          {ad.Id}");
                        Console.WriteLine($"  Name:        {ad.Name}");
                        Console.WriteLine($"  Description: {ad.Description}");
                        Console.WriteLine($"  Driver:      {ad.DriverVersion}");
                        Console.WriteLine($"  Status:      {ad.Status}");
                        Console.WriteLine($"  Monitor Mode:{ad.MonitorModeSupported}");
                        Console.WriteLine();
                    }
                }
                return 0;
            }

            // 3. One-shot Scan argument
            if (args.Any(a => a.Equals("--scan", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("==========================================================");
                Console.WriteLine("  WinWiFi 3.0.4 - One-Shot Windows WLAN Cache Observation ");
                Console.WriteLine("==========================================================\n");

                var wifiService = new NativeWifiService(new SecurityAnalyzer());
                var adapters = wifiService.GetAdaptersAsync().GetAwaiter().GetResult();
                string adapterId = adapters.Count > 0 ? adapters[0].Id : "";

                Console.WriteLine($"Target Adapter: {(adapters.Count > 0 ? adapters[0].Name : "Default/Netsh")}");
                Console.WriteLine("Reading the current Windows WLAN BSS cache (no monitor-mode capture or active scan trigger)...");

                var aps = wifiService.ScanNetworksAsync(adapterId).GetAwaiter().GetResult();
                Console.WriteLine($"\nDiscovered {aps.Count} Access Point(s):\n");
                Console.WriteLine(string.Format("{0,-26} {1,-18} {2,-4} {3,-8} {4,-7} {5,-22} {6}", "SSID", "BSSID", "CH", "BAND", "RSSI", "SECURITY", "VENDOR"));
                Console.WriteLine(new string('-', 98));

                foreach (var ap in aps)
                {
                    string ssid = ap.Ssid.Length > 24 ? ap.Ssid.Substring(0, 21) + "..." : ap.Ssid;
                    Console.WriteLine(string.Format("{0,-26} {1,-18} {2,-4} {3,-8} {4,-7} {5,-22} {6}",
                        ssid,
                        ap.Bssid,
                        ap.Channel,
                        ap.Band,
                        $"{ap.Rssi}dBm",
                        ap.Security.Length > 20 ? ap.Security.Substring(0, 18) + ".." : ap.Security,
                        ap.Vendor));
                }
                Console.WriteLine(new string('-', 98));
                return 0;
            }

            // 4. Check for Self-Test argument
            if (args.Any(a => a.Equals("--test", StringComparison.OrdinalIgnoreCase) || a.Equals("-t", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("==========================================================");
                Console.WriteLine("     WinWiFi 3.0.4 Native Security Audit & Math Tests     ");
                Console.WriteLine("==========================================================\n");

                var tests = new NativeSelfTests();
                var results = tests.RunAllTestsAsync().GetAwaiter().GetResult();
                int passed = 0;
                int failed = 0;

                foreach (var r in results)
                {
                    string status = r.Passed ? "[PASS]" : "[FAIL]";
                    Console.ForegroundColor = r.Passed ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.Write($"{status} ");
                    Console.ResetColor();
                    Console.WriteLine($"{r.TestId} - {r.Name} ({r.DurationMs}ms)");
                    Console.WriteLine($"       └─ {r.Details}\n");

                    if (r.Passed) passed++;
                    else failed++;
                }

                Console.WriteLine("==========================================================");
                Console.WriteLine($"Test Execution Finished: {passed} passed, {failed} failed (Total: {results.Count})");
                Console.WriteLine("==========================================================");

                return failed > 0 ? 1 : 0;
            }

            // 5. Check for Headless / Bridge Mode (or CLI default when no args specified)
            bool isBridgeRequested = args.Any(a => a.Equals("--bridge", StringComparison.OrdinalIgnoreCase) || 
                                                  a.Equals("--headless", StringComparison.OrdinalIgnoreCase) || 
                                                  a.Equals("--server", StringComparison.OrdinalIgnoreCase) || 
                                                  a.Equals("-b", StringComparison.OrdinalIgnoreCase));
#if !WINDOWS_DESKTOP
            // In CLI executable, default to bridge daemon if no other action argument was provided
            if (args.Length == 0) isBridgeRequested = true;
#endif

            if (isBridgeRequested)
            {
                int port = 38989;
                for (int i = 0; i < args.Length - 1; i++)
                {
                    if ((args[i] == "--port" || args[i] == "-p") && int.TryParse(args[i + 1], out int p))
                    {
                        port = p;
                    }
                }

                Console.WriteLine("==========================================================");
                Console.WriteLine($"  WinWiFi 3.0.4 Local Native Bridge Daemon (: {port})    ");
                Console.WriteLine("==========================================================");
                Console.WriteLine($"[Bridge] Starting HTTP / SSE bridge on http://127.0.0.1:{port}/");
                Console.WriteLine("[Bridge] Exposing real-time wlanapi.dll & netsh telemetry to Web UI");
                Console.WriteLine("[Bridge] Press Ctrl+C to terminate the bridge daemon.\n");

                var bridge = new HttpBridgeServer(port);
                bridge.StartAsync().GetAwaiter().GetResult();

                var tcs = new TaskCompletionSource();
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    Console.WriteLine("\n[Bridge] Shutdown signal received. Cleaning up...");
                    tcs.TrySetResult();
                };
                AppDomain.CurrentDomain.ProcessExit += (s, e) => tcs.TrySetResult();

                tcs.Task.GetAwaiter().GetResult();
                bridge.DisposeAsync().AsTask().GetAwaiter().GetResult();
                Console.WriteLine("[Bridge] Daemon stopped cleanly.");
                return 0;
            }

            // 3. Normal GUI Application Startup (Windows WPF)
#if WINDOWS_DESKTOP
            AddFileTraceListener();
            using var instanceGuard = SingleInstanceGuard.TryAcquire();
            if (instanceGuard is null)
            {
                // Another WinWiFi window is already open; bring it forward and quit.
                Trace.TraceInformation("Second launch detected; signaling the existing window and exiting.");
                SingleInstanceGuard.ActivateExistingInstance();
                return 0;
            }
            if (AppUpdateService.TryStartDeferredApply(Environment.ProcessPath ?? "", Environment.ProcessId)) return 0;
            try
            {
                Trace.TraceInformation($"WinWiFi desktop starting (PID {Environment.ProcessId}).");
                var app = new App();
                app.InitializeComponent();
                App.InstanceGuard = instanceGuard;
                int exitCode = app.Run();
                Trace.TraceInformation($"WinWiFi desktop message loop ended (exit {exitCode}).");
                return exitCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WinWiFi] Note: GUI desktop window requires Windows display host: {ex.Message}");
                Console.WriteLine("[WinWiFi] Use 'WinWiFi --test' to run self-tests or 'WinWiFi --bridge' for headless API bridge.");
                return 1;
            }
#else
            Console.WriteLine("[WinWiFi] CLI Mode. Run with '--test' to execute audit tests or '--bridge' to launch the HTTP API bridge.");
            return 0;
#endif
        }

#if WINDOWS_DESKTOP
        private static void AddFileTraceListener()
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinWiFi");
                Directory.CreateDirectory(dir);
                // Shared read/write so a second launch can still log while the
                // first instance holds the file open.
                var stream = new FileStream(
                    Path.Combine(dir, "desktop.log"), FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                Trace.Listeners.Add(new TextWriterTraceListener(new StreamWriter(stream) { AutoFlush = true }, "WinWiFiDesktopLog"));
                Trace.AutoFlush = true;
            }
            catch
            {
                // Diagnostics are optional; never block the window over a log file.
            }
        }

        private static void EnsureConsole()
        {
            if (!AttachConsole(uint.MaxValue)) AllocConsole();
            Console.SetOut(new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            Console.SetError(new System.IO.StreamWriter(Console.OpenStandardError()) { AutoFlush = true });
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AttachConsole(uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AllocConsole();
#endif
    }
}
