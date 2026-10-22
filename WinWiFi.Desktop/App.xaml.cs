using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;
using WinWiFi.Data;
using WinWiFi.Services;
using WinWiFi.ViewModels;

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
        services.AddSingleton<MainViewModel>();
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
        catch (Exception ex)
        {
            Trace.TraceError($"Unable to start the localhost dashboard bridge: {ex}");
            MessageBox.Show(
                $"WinWiFi can still run as a desktop app, but its browser dashboard bridge did not start.\n\n{ex.Message}",
                "WinWiFi local bridge",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }

        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.DataContext = ServiceProvider.GetRequiredService<MainViewModel>();
        mainWindow.Show();
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
