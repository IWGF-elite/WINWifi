using System;
using System.Windows;
using WinWiFi.ViewModels;

namespace WinWiFi
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            Loaded += OnLoaded;
            Closing += OnClosing;
        }

        private MainViewModel? ViewModel => DataContext as MainViewModel;

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            if (ViewModel != null) await ViewModel.InitializeAsync();
        }

        private async void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            if (ViewModel != null) await ViewModel.StopLiveScanningAsync();
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
