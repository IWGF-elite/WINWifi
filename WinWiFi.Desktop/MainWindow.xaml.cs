using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace WinWiFi;

public partial class MainWindow : Window
{
    // Set at load time from the port the app's bridge actually bound; the
    // preferred port can differ when another local bridge already owns it.
    private Uri _dashboardUri = new("http://127.0.0.1:38989/");
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

    internal void ActivateWindow()
    {
        Trace.TraceInformation("Activation requested by a second launch; focusing the existing window.");
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        // Windows can refuse Activate() for a background process; nudge with
        // the foreground call so the existing window visibly comes forward.
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
            if (!SetForegroundWindow(hwnd))
                Trace.TraceInformation($"Windows kept the foreground elsewhere (error {Marshal.GetLastWin32Error()}); the window is still activated in-app.");
        }
        catch (Exception ex)
        {
            Trace.TraceError($"SetForegroundWindow failed: {ex}");
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(App.BridgeToken))
        {
            // Rare: no free loopback port at all. Plain language only — the user
            // must never be shown a listener, port, or token detail.
            Dashboard.Visibility = Visibility.Collapsed;
            StartupErrorMessage.Text = App.BridgeStartupError ?? "WinWiFi could not start its local Wi-Fi bridge. Close any other WinWiFi windows and start the app again.";
            StartupError.Visibility = Visibility.Visible;
            return;
        }

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
                    !string.Equals(target.GetLeftPart(UriPartial.Authority), _dashboardUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
                    args.Cancel = true;
            };
            _dashboardUri = new Uri($"http://127.0.0.1:{App.BridgePort}/");
            Dashboard.Source = new Uri(_dashboardUri, $"?token={Uri.EscapeDataString(App.BridgeToken)}");
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
