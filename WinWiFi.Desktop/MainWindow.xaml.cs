using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace WinWiFi;

public partial class MainWindow : Window
{
    private static readonly Uri DashboardUri = new("http://127.0.0.1:38989/");
    private bool _isFittedToWorkArea;

    public MainWindow()
    {
        InitializeComponent();
        ApplyWorkingAreaSize(fillWorkArea: false);
        Loaded += OnLoaded;
    }

    /// <summary>
    /// The shell owns its size so browser content cannot be manually stretched
    /// into a broken layout. SystemParameters.WorkArea is already expressed in
    /// WPF device independent pixels and excludes the taskbar at the active
    /// Windows DPI scale.
    /// </summary>
    private void ApplyWorkingAreaSize(bool fillWorkArea)
    {
        Rect workArea = SystemParameters.WorkArea;
        var size = fillWorkArea
            ? WindowLayoutSizing.FullWorkArea(workArea.Width, workArea.Height)
            : WindowLayoutSizing.FromWorkArea(workArea.Width, workArea.Height);
        Width = size.Width;
        Height = size.Height;
        Left = workArea.Left + (workArea.Width - Width) / 2;
        Top = workArea.Top + (workArea.Height - Height) / 2;
        _isFittedToWorkArea = fillWorkArea;

        // Prevent a future programmatic size change from extending behind the
        // taskbar while preserving ResizeMode="NoResize" for the user.
        MaxWidth = workArea.Width;
        MaxHeight = workArea.Height;
    }

    internal void BeginNativeDrag()
    {
        if (Dispatcher.CheckAccess()) DragMove();
        else Dispatcher.Invoke(DragMove);
    }

    private void ToggleWorkAreaFit()
    {
        WindowState = WindowState.Normal;
        ApplyWorkingAreaSize(!_isFittedToWorkArea);
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            string userDataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinWiFi", "WebView2");
            Directory.CreateDirectory(userDataFolder);
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userDataFolder);
            await Dashboard.EnsureCoreWebView2Async(environment);
            Dashboard.CoreWebView2.AddHostObjectToScript("winWifiWindow", new WindowHostObject(this));
            Dashboard.ZoomFactor = 0.9;
            Dashboard.CoreWebView2.Settings.AreDevToolsEnabled = false;
            Dashboard.CoreWebView2.Settings.IsStatusBarEnabled = false;
            Dashboard.CoreWebView2.WebMessageReceived += (_, args) =>
            {
                switch (args.TryGetWebMessageAsString())
                {
                    case "window:minimize": WindowState = WindowState.Minimized; break;
                    case "window:fit": ToggleWorkAreaFit(); break;
                    case "window:close": Close(); break;
                }
            };
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

/// <summary>Synchronous, same-origin WebView2 bridge for native title-bar dragging.</summary>
[ComVisible(true)]
[ClassInterface(ClassInterfaceType.AutoDual)]
public sealed class WindowHostObject
{
    private readonly MainWindow _window;
    public WindowHostObject(MainWindow window) => _window = window;
    public void BeginDrag() => _window.BeginNativeDrag();
}
