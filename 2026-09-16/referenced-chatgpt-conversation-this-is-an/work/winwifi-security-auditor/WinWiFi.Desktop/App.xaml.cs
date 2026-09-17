using System;
using System.Threading;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using WinWiFi.Data;
using WinWiFi.Services;
using WinWiFi.ViewModels;

namespace WinWiFi;

/// <summary>Native shell startup and lifecycle management for the desktop telemetry service.</summary>
public partial class App : Application
{
    public static IServiceProvider ServiceProvider { get; private set; } = null!;
    private WifiBackgroundScanner? _backgroundScanner;

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
        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        var viewModel = ServiceProvider.GetRequiredService<MainViewModel>();
        _backgroundScanner = ServiceProvider.GetRequiredService<WifiBackgroundScanner>();
        mainWindow.DataContext = viewModel;
        mainWindow.Show();

        try
        {
            // The view model discovers the adapter and binds it to the scanner.
            // Starting the BackgroundService before this point leaves it paused with no adapter.
            await viewModel.InitializeAsync();
            _backgroundScanner.SetScanningState(viewModel.IsScanning);
            await _backgroundScanner.StartAsync(CancellationToken.None);
        }
        catch (Exception exception)
        {
            viewModel.IsInitializing = false;
            viewModel.InitializationStatus = "Startup failed — see the activity log.";
            viewModel.ScanDiagnosticsText = $"Startup error: {exception.Message}";
            viewModel.AddLog("ERROR", "STARTUP", $"Application initialization failed: {exception.Message}");
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _backgroundScanner?.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
            (ServiceProvider as IDisposable)?.Dispose();
            SqliteStorageService.ReleaseAllPools();
        }
        catch { }
        base.OnExit(e);
    }
}
