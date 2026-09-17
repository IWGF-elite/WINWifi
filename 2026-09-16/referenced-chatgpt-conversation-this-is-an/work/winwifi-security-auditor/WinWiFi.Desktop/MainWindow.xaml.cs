using System;
using System.Windows;
using Microsoft.Win32;
using WinWiFi.ViewModels;

namespace WinWiFi
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private MainViewModel? ViewModel => DataContext as MainViewModel;

        private void OnImportPcapClick(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                Filter = "Wi-Fi Capture Files (*.pcap;*.cap;*.pcapng)|*.pcap;*.cap;*.pcapng|All Files (*.*)|*.*",
                Title = "Select PCAP / PCAPNG Wireless Capture File"
            };

            if (dialog.ShowDialog() == true)
            {
                ViewModel?.ImportPcap(dialog.FileName);
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
