using System;
using System.IO;
using System.Diagnostics;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace WinWiFi;

public partial class MainWindow : Window
{
    private static readonly Uri DashboardUri = new("http://127.0.0.1:38989/");

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            // Fit the initial WPF window into the user's actual work area. The
            // old fixed 1440x900 size was taller and wider than many 1366x768
            // Windows displays, which made the dashboard look cropped.
            var workArea = SystemParameters.WorkArea;
            Width = Math.Min(1440, workArea.Width * 0.96);
            Height = Math.Min(900, workArea.Height * 0.96);
            Left = workArea.Left + (workArea.Width - Width) / 2;
            Top = workArea.Top + (workArea.Height - Height) / 2;

            string userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinWiFi", "WebView2");
            Directory.CreateDirectory(userDataFolder);
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userDataFolder);
            await Dashboard.EnsureCoreWebView2Async(environment);
            Dashboard.ZoomFactor = 0.9;
            Dashboard.CoreWebView2.Settings.AreDevToolsEnabled = false;
            Dashboard.CoreWebView2.Settings.IsStatusBarEnabled = false;
            Dashboard.CoreWebView2.DownloadStarting += (_, args) =>
            {
                try
                {
                    string fileName = Path.GetFileName(args.ResultFilePath);
                    string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    string destination = Path.Combine(desktop, fileName);
                    string stem = Path.GetFileNameWithoutExtension(destination);
                    string extension = Path.GetExtension(destination);
                    for (int suffix = 1; File.Exists(destination); suffix++)
                        destination = Path.Combine(desktop, $"{stem} ({suffix}){extension}");
                    args.ResultFilePath = destination;
                    args.Handled = true;
                }
                catch { /* Let WebView2 use its normal Downloads destination if Desktop is unavailable. */ }
            };
            Dashboard.CoreWebView2.NavigationStarting += (_, args) =>
            {
                if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var target) ||
                    !string.Equals(target.GetLeftPart(UriPartial.Authority), DashboardUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
                    args.Cancel = true;
            };
            Dashboard.Source = DashboardUri;
        }
        catch (Exception ex)
        {
            Dashboard.Visibility = Visibility.Collapsed;
            StartupErrorMessage.Text =
                $"{ex.Message}\n\nWinWiFi uses the Microsoft Edge WebView2 Runtime to show its dashboard. Install the runtime and relaunch the app.";
            InstallWebView2Button.Visibility = File.Exists(Path.Combine(AppContext.BaseDirectory, "Install-WebView2Runtime.exe"))
                ? Visibility.Visible
                : Visibility.Collapsed;
            StartupError.Visibility = Visibility.Visible;
        }
    }

    private void OnInstallWebView2Click(object sender, RoutedEventArgs e)
    {
        string installer = Path.Combine(AppContext.BaseDirectory, "Install-WebView2Runtime.exe");
        try
        {
            Process.Start(new ProcessStartInfo(installer) { UseShellExecute = true, Verb = "runas" });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "WebView2 Runtime installer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
