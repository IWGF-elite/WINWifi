using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using WinWiFi.Data;
using WinWiFi.Services;
using WinWiFi.ViewModels;

namespace WinWiFi;

/// <summary>Native shell startup. Hardware telemetry is always started explicitly through the local bridge.</summary>
public partial class App : Application
{
    public static IServiceProvider ServiceProvider { get; private set; } = null!;

    private void Application_Startup(object sender, StartupEventArgs e)
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
        mainWindow.DataContext = ServiceProvider.GetRequiredService<MainViewModel>();
        mainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            (ServiceProvider as IDisposable)?.Dispose();
            SqliteStorageService.ReleaseAllPools();
        }
        catch { }
        base.OnExit(e);
    }
}
