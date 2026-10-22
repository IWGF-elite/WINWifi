using System;
using System.Windows;
using Microsoft.Win32;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Interop;
using WinWiFi.ViewModels;

namespace WinWiFi
{
    public partial class MainWindow : Window
    {
        private const int DwmwaUseImmersiveDarkMode = 20;

        public MainWindow()
        {
            InitializeComponent();
            Loaded += OnLoaded;
            Closing += OnClosing;
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            try
            {
                var useDarkMode = 1;
                DwmSetWindowAttribute(new WindowInteropHelper(this).Handle,
                    DwmwaUseImmersiveDarkMode, ref useDarkMode, sizeof(int));
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        [DllImport("dwmapi.dll", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute,
            ref int value, int valueSize);

        private MainViewModel? ViewModel => DataContext as MainViewModel;

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ViewModel != null) await ViewModel.InitializeAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"WinWiFi opened, but its startup checks did not complete.\n\n{ex.Message}",
                    "WinWiFi startup",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private async void OnClosing(object? sender, CancelEventArgs e)
        {
            if (ViewModel != null) await ViewModel.StopLiveScanningAsync();
        }

        private async void OnImportPcapClick(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Wi-Fi Capture Files (*.pcap;*.cap;*.pcapng)|*.pcap;*.cap;*.pcapng|All Files (*.*)|*.*",
                Title = "Select PCAP / PCAPNG Wireless Capture File"
            };

            if (dialog.ShowDialog() == true)
            {
                if (ViewModel != null)
                    await ViewModel.ImportPcapAsync(dialog.FileName);
            }
        }

        private void OnTabDiscoveryClick(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null) ViewModel.ActiveTab = "Discovery";
        }

        private void OnTabPacketsClick(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null) ViewModel.ActiveTab = "Packets";
        }

        private void OnTabHandshakesClick(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null) ViewModel.ActiveTab = "Handshakes";
        }

        private void OnTabDatabaseClick(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null) ViewModel.ActiveTab = "Database";
        }
    }
}
