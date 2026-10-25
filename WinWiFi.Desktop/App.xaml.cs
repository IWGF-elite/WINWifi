using System;
using System.Net;
using System.Net.Http;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using WinWiFi.Data;
using WinWiFi.Services;

namespace WinWiFi;

/// <summary>Native shell startup. Hardware telemetry is always started explicitly through the local bridge.</summary>
public partial class App : Application
{
    public static IServiceProvider ServiceProvider { get; private set; } = null!;
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
        services.AddSingleton<MainWindow>();

        ServiceProvider = services.BuildServiceProvider();
        _bridgeServer = new HttpBridgeServer(
            wifiService: ServiceProvider.GetRequiredService<INativeWifiService>(),
            securityAnalyzer: ServiceProvider.GetRequiredService<SecurityAnalyzer>(),
            pcapDissector: ServiceProvider.GetRequiredService<PcapDissector>(),
            reportGenerator: ServiceProvider.GetRequiredService<ReportGenerator>(),
            storage: ServiceProvider.GetRequiredService<SqliteStorageService>(),
            scanner: ServiceProvider.GetRequiredService<WifiBackgroundScanner>());
        try
        {
            await _bridgeServer.StartAsync();
        }
        catch (HttpListenerException ex)
        {
            // A second desktop window can safely use the already-running local
            // bridge. This happens when the user launches the app again from
            // Explorer, or when a prior instance is still running.
            if (!await IsExistingWinWiFiBridgeAsync())
            {
                MessageBox.Show(
                    $"WinWiFi could not start its local dashboard bridge.\n\n{ex.Message}",
                    "WinWiFi local bridge",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            Trace.TraceError($"Unable to start the localhost dashboard bridge: {ex}");
            MessageBox.Show(
                $"WinWiFi could not start its local dashboard bridge.\n\n{ex.Message}",
                "WinWiFi local bridge",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }

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

    private static async Task<bool> IsExistingWinWiFiBridgeAsync()
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            string status = await client.GetStringAsync("http://127.0.0.1:38989/api/health");
            return status.Contains("\"status\":\"online\"", StringComparison.OrdinalIgnoreCase) &&
                   status.Contains("WinWiFi Native 802.11 Core", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _bridgeServer?.DisposeAsync().AsTask().GetAwaiter().GetResult();
            (ServiceProvider as IDisposable)?.Dispose();
            SqliteStorageService.ReleaseAllPools();
        }
        catch { }
        base.OnExit(e);
    }
}
