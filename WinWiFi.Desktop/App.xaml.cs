using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using WinWiFi.Data;
using WinWiFi.Services;

namespace WinWiFi;

/// <summary>Native shell startup. The desktop owns its local bridge and hands the per-launch token to its own WebView2 window; the user never sees it.</summary>
public partial class App : Application
{
    private const int PreferredBridgePort = 38989;
    private const int BridgePortAttempts = 10;

    public static IServiceProvider ServiceProvider { get; private set; } = null!;
    internal static string? BridgeToken { get; private set; }
    internal static int BridgePort { get; private set; } = PreferredBridgePort;
    internal static string? BridgeStartupError { get; private set; }

    internal static SingleInstanceGuard? InstanceGuard { get; set; }

    private static HttpBridgeServer? _bridgeServer;

    private async void Application_Startup(object sender, StartupEventArgs e)
    {
        var services = new ServiceCollection();
        services.AddSingleton<SecurityAnalyzer>();
        services.AddSingleton<PcapDissector>();
        services.AddSingleton<ReportGenerator>();
        services.AddSingleton<SqliteStorageService>();
        services.AddSingleton<INativeWifiService, NativeWifiService>();
        services.AddSingleton<WifiBackgroundScanner>();
        services.AddSingleton<AppUpdateService>();
        services.AddSingleton<MainWindow>();

        ServiceProvider = services.BuildServiceProvider();
        await StartBridgeAsync();
        ServiceProvider.GetRequiredService<AppUpdateService>().Start();

        // Application_Startup is async because bridge initialization is async.
        // With WPF's default OnLastWindowClose policy, an await here can leave
        // the application with no visible window long enough for WPF to shut
        // down before MainWindow.Show() resumes. Keep the process alive until
        // the shell exists, then restore normal close-to-exit behavior.
        try
        {
            var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
            MainWindow = mainWindow;
            mainWindow.Show();
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            InstanceGuard?.StartActivationListener(() => Dispatcher.Invoke(mainWindow.ActivateWindow));
        }
        catch (Exception ex)
        {
            Trace.TraceError($"Unable to create the WinWiFi desktop window: {ex}");
            MessageBox.Show(
                $"WinWiFi could not open its desktop window.\n\n{ex.Message}",
                "WinWiFi startup",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown();
        }
    }

    /// <summary>
    /// The desktop always starts its own bridge. The preferred port is 38989;
    /// when another local process holds it (for example a CLI bridge left
    /// running from a terminal), the app quietly binds the next free port and
    /// the embedded window is pointed at whichever port was actually used. The
    /// user never sees a raw listener error, a port number, or a token.
    /// </summary>
    private static async Task StartBridgeAsync()
    {
        var wifi = ServiceProvider.GetRequiredService<INativeWifiService>();
        var analyzer = ServiceProvider.GetRequiredService<SecurityAnalyzer>();
        var pcap = ServiceProvider.GetRequiredService<PcapDissector>();
        var reports = ServiceProvider.GetRequiredService<ReportGenerator>();
        var storage = ServiceProvider.GetRequiredService<SqliteStorageService>();
        var scanner = ServiceProvider.GetRequiredService<WifiBackgroundScanner>();
        var appUpdateService = ServiceProvider.GetRequiredService<AppUpdateService>();

        foreach (int candidate in CandidatePorts())
        {
            var server = new HttpBridgeServer(candidate, wifi, analyzer, pcap, reports, storage, scanner,
                appUpdateService: appUpdateService,
                shutdownAfterUpdate: () =>
                {
                    var app = Application.Current;
                    if (app is not null) _ = app.Dispatcher.BeginInvoke(new Action(app.Shutdown));
                });
            try
            {
                await server.StartAsync();
                _bridgeServer = server;
                BridgeToken = server.AuthToken;
                BridgePort = candidate;
                BridgeStartupError = null;
                Trace.TraceInformation($"Local Wi-Fi bridge is listening on port {candidate}.");
                if (candidate != PreferredBridgePort)
                {
                    Trace.TraceInformation($"Port {PreferredBridgePort} was already in use by another local WinWiFi bridge; this window uses port {candidate} instead.");
                }
                return;
            }
            catch (HttpListenerException)
            {
                // The port was claimed between the availability probe and the
                // bind (or by a stale HTTP.sys registration); try the next one.
                await server.DisposeAsync();
            }
            catch (Exception ex)
            {
                Trace.TraceError($"Unable to start the localhost dashboard bridge on port {candidate}: {ex}");
                await server.DisposeAsync();
            }
        }

        BridgeToken = null;
        BridgeStartupError =
            "WinWiFi could not start its local Wi-Fi bridge.\n\n" +
            "Close any other WinWiFi windows and start the app again.";
    }

    private static IEnumerable<int> CandidatePorts()
    {
        for (int port = PreferredBridgePort; port < PreferredBridgePort + BridgePortAttempts; port++)
        {
            if (BridgePortSelector.IsPortAvailable(port)) yield return port;
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Shutdown must never hold the process open: a step that does not finish
        // within a few seconds is logged and skipped, so the window closes, the
        // bridge port is released, and the next launch is not blocked by a
        // half-dead instance holding the single-instance lock.
        Trace.TraceInformation("WinWiFi desktop is shutting down.");
        try
        {
            RunBounded("stop the local Wi-Fi bridge", () => _bridgeServer is null ? null : Task.Run(async () => await _bridgeServer.DisposeAsync()));
            RunBounded("release registered services", () => Task.Run(() => (ServiceProvider as IDisposable)?.Dispose()));
            RunBounded("close local audit storage", () => Task.Run(SqliteStorageService.ReleaseAllPools));
            InstanceGuard?.Dispose();
        }
        catch (Exception ex)
        {
            Trace.TraceError($"WinWiFi shutdown failed: {ex}");
        }
        base.OnExit(e);
    }

    private static void RunBounded(string step, Func<Task?> action)
    {
        try
        {
            Task? task = action();
            if (task is null) return;
            if (!task.Wait(TimeSpan.FromSeconds(3)))
                Trace.TraceWarning($"Shutdown step '{step}' did not finish within 3 seconds; exiting anyway.");
        }
        catch (Exception ex)
        {
            Trace.TraceWarning($"Shutdown step '{step}' failed: {ex.Message}");
        }
    }
}
