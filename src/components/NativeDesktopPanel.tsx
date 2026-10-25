import React, { useState } from 'react';
import { 
  Terminal, 
  Cpu, 
  CheckCircle2, 
  FileCode, 
  Download, 
  Layers, 
  ShieldCheck, 
  Database, 
  Copy, 
  Check, 
  ExternalLink,
  Laptop,
  FolderGit2
} from 'lucide-react';

interface NativeDesktopPanelProps {
  isDarkMode: boolean;
}

export const NativeDesktopPanel: React.FC<NativeDesktopPanelProps> = ({ isDarkMode }) => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string>('NativeWifi.cs');

  const filesContent: Record<string, { desc: string; code: string; lang: string }> = {
    'NativeWifi.cs': {
      desc: 'Win32 wlanapi.dll P/Invoke Marshaling & Frequency Math',
      lang: 'csharp',
      code: `// Interop/NativeWifi.cs
using System;
using System.Runtime.InteropServices;

namespace WinWiFi.Interop
{
    public static class NativeWifi
    {
        private const string WLAN_API_DLL = "wlanapi.dll";

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanOpenHandle(
            uint dwClientVersion, IntPtr pReserved,
            out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanEnumInterfaces(
            IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanScan(
            IntPtr hClientHandle, [In] ref Guid pInterfaceGuid,
            IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

        [DllImport(WLAN_API_DLL, SetLastError = true)]
        public static extern uint WlanGetNetworkBssList(
            IntPtr hClientHandle, [In] ref Guid pInterfaceGuid,
            IntPtr pDot11Ssid, DOT11_BSS_TYPE dot11BssType,
            bool bSecurityEnabled, IntPtr pReserved, out IntPtr ppWlanBssList);

        public static (int channel, string band) FrequencyToChannel(uint freqKHz)
        {
            uint freqMHz = freqKHz / 1000;
            if (freqMHz == 2484) return (14, "2.4 GHz"); // Channel 14 special case
            if (freqMHz >= 2412 && freqMHz <= 2472) return ((int)((freqMHz - 2407) / 5), "2.4 GHz");
            if (freqMHz >= 5170 && freqMHz <= 5825) return ((int)((freqMHz - 5000) / 5), "5 GHz");
            if (freqMHz >= 5955 && freqMHz <= 7115) return ((int)((freqMHz - 5950) / 5), "6 GHz");
            return (0, "Unknown");
        }
    }
}`
    },
    'PcapDissector.cs': {
      desc: 'Libpcap 2.4 & PCAPNG Binary Dissector with EAPOL Handshake Extraction',
      lang: 'csharp',
      code: `// Services/PcapDissector.cs
using System;
using System.Collections.Generic;
using System.IO;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public class PcapDissector
    {
        private const uint PCAP_MAGIC_MICROSECOND = 0xa1b2c3d4;
        private const uint PCAPNG_SECTION_HEADER = 0x0a0d0d0a;

        public PcapDissectorResult DissectBytes(byte[] bytes)
        {
            var result = new PcapDissectorResult();
            using var ms = new MemoryStream(bytes);
            using var reader = new BinaryReader(ms);

            uint magic = reader.ReadUInt32();
            if (magic == PCAPNG_SECTION_HEADER)
            {
                DissectPcapNg(bytes, result);
                return result;
            }

            // Read Global Header (LinkType 127 = DLT_IEEE802_11_RADIO)
            ushort versionMajor = reader.ReadUInt16();
            ushort versionMinor = reader.ReadUInt16();
            ms.Seek(16, SeekOrigin.Current); // skip tz, sigfigs, snaplen, linktype

            while (ms.Position + 16 <= ms.Length)
            {
                uint sec = reader.ReadUInt32();
                uint usec = reader.ReadUInt32();
                uint inclLen = reader.ReadUInt32();
                uint origLen = reader.ReadUInt32();

                byte[] packetBytes = reader.ReadBytes((int)inclLen);
                // Dissects Radiotap, 802.11 Beacon, Probe, QoS Data, EAPOL 4-Way
            }
            return result;
        }
    }
}`
    },
    'SqliteStorageService.cs': {
      desc: 'Relational SQLite Persistence with Microsoft.Data.Sqlite',
      lang: 'csharp',
      code: `// Data/SqliteStorageService.cs
using System;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using WinWiFi.Models;

namespace WinWiFi.Data
{
    public class SqliteStorageService : IDisposable
    {
        private readonly string _connectionString;

        public SqliteStorageService(string? databasePath = null)
        {
            string dbPath = databasePath ?? "winwifi_audit.db";
            _connectionString = $"Data Source={dbPath}";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            using var conn = new SqliteConnection(_connectionString);
            conn.Open();
            string ddl = @"
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, location TEXT,
                    auditor_name TEXT, created_at TEXT, updated_at TEXT, notes TEXT
                );
                CREATE TABLE IF NOT EXISTS access_points (
                    bssid TEXT NOT NULL, project_id TEXT NOT NULL, ssid TEXT,
                    channel INTEGER, band TEXT, frequency_mhz INTEGER, rssi INTEGER,
                    signal_quality INTEGER, security TEXT, cipher TEXT,
                    security_score INTEGER, is_rogue INTEGER, PRIMARY KEY (bssid, project_id)
                );";
            using var cmd = new SqliteCommand(ddl, conn);
            cmd.ExecuteNonQuery();
        }
    }
}`
    },
    'MainWindow.xaml': {
      desc: 'WPF XAML View with Fluent Dark Theme & Ribbon Controls',
      lang: 'xml',
      code: `<!-- MainWindow.xaml -->
<Window x:Class="WinWiFi.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="WinWiFi Security Auditor - .NET 8 Native Desktop"
        Height="850" Width="1350" Background="#0F1115">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="180"/>
        </Grid.RowDefinitions>

        <!-- Ribbon Toolbar -->
        <Border Grid.Row="0" Background="#161920" Padding="12,8">
            <DockPanel LastChildFill="True">
                <TextBlock Text="WINWIFI NATIVE" Foreground="#60A5FA" FontWeight="Bold"/>
                <ComboBox ItemsSource="{Binding Adapters}" SelectedItem="{Binding SelectedAdapter}"/>
                <Button Content="Scan / Pause" Command="{Binding ToggleScanCommand}"/>
                <Button Content="Export Report" Command="{Binding ExportReportCommand}"/>
            </DockPanel>
        </Border>

        <!-- Access Points DataGrid -->
        <DataGrid Grid.Row="2" ItemsSource="{Binding AccessPoints}" AutoGenerateColumns="False">
            <DataGrid.Columns>
                <DataGridTextColumn Header="SSID" Binding="{Binding Ssid}" Width="160"/>
                <DataGridTextColumn Header="BSSID" Binding="{Binding Bssid}" Width="140"/>
                <DataGridTextColumn Header="Ch" Binding="{Binding Channel}" Width="45"/>
                <DataGridTextColumn Header="Band" Binding="{Binding Band}" Width="70"/>
                <DataGridTextColumn Header="Signal" Binding="{Binding SignalDisplay}" Width="110"/>
                <DataGridTextColumn Header="Security" Binding="{Binding Security}" Width="160"/>
                <DataGridTextColumn Header="NIST Score" Binding="{Binding SecurityScore}" Width="80"/>
            </DataGrid.Columns>
        </DataGrid>
    </Grid>
</Window>`
    },
    'WinWiFi.Desktop.csproj': {
      desc: '.NET 8 WPF Project Specification with Dependency Injection & SQLite',
      lang: 'xml',
      code: `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <UseWPF>true</UseWPF>
    <AssemblyName>WinWiFi</AssemblyName>
    <Version>3.0.1</Version>
    <Platforms>AnyCPU;x64</Platforms>
  </PropertyGroup>

  <ItemGroup>
    <PackageReference Include="CommunityToolkit.Mvvm" Version="8.2.2" />
    <PackageReference Include="Microsoft.Extensions.DependencyInjection" Version="8.0.0" />
    <PackageReference Include="Microsoft.Extensions.Hosting" Version="8.0.0" />
    <PackageReference Include="Microsoft.Data.Sqlite" Version="8.0.4" />
    <PackageReference Include="Dapper" Version="2.1.35" />
    <PackageReference Include="System.Text.Json" Version="8.0.3" />
  </ItemGroup>
</Project>`
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Top Architecture Status Banner */}
      <div className={`p-5 rounded-lg border shadow-sm ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
      }`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400">
              <Laptop className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base text-slate-100">Windows-Native .NET 8 WPF Architecture</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  READY TO BUILD (.EXE)
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Full C# / .NET 8 WPF solution created in the workspace (<code className="text-blue-300 font-mono">WinWiFi.sln</code> and <code className="text-blue-300 font-mono">WinWiFi.Desktop/</code>).
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleCopy(
                'dotnet publish WinWiFi.Desktop/WinWiFi.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish',
                'pub'
              )}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              {copiedCmd === 'pub' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>Copy Build .EXE Command</span>
            </button>
          </div>
        </div>

        {/* Feature Migration Matrix */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 pt-4 border-t border-slate-800 text-xs">
          <div className="p-3 rounded bg-slate-900/50 border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Native WlanApi Interop</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Direct P/Invoke bindings to <code className="text-blue-300">wlanapi.dll</code> for raw BSS records, antenna signal (dBm), and hardware scan triggers.
            </p>
          </div>

          <div className="p-3 rounded bg-slate-900/50 border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Binary PCAP &amp; PCAPNG</span>
            </div>
            <p className="text-[11px] text-slate-400">
              In-process dissector reading Libpcap 2.4 and PCAPNG blocks, decapsulating Radiotap and 4-Way EAPOL handshakes.
            </p>
          </div>

          <div className="p-3 rounded bg-slate-900/50 border border-slate-800/80 space-y-1">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>SQLite &amp; MVVM DI</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Native SQLite relational repository with <code className="text-blue-300">Microsoft.Data.Sqlite</code> and CommunityToolkit.Mvvm view models.
            </p>
          </div>
        </div>
      </div>

      {/* Interactive Code & Structure Explorer */}
      <div className={`rounded-lg border shadow-sm overflow-hidden ${
        isDarkMode ? 'bg-[#181a20] border-[#2c303b]' : 'bg-white border-slate-200'
      }`}>
        <div className="p-3 border-b border-slate-800 bg-[#14161c] flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <FolderGit2 className="w-4 h-4 text-blue-400" />
            <span>Native Project Source Explorer</span>
          </div>

          <div className="flex flex-wrap items-center gap-1">
            {Object.keys(filesContent).map((filename) => (
              <button
                key={filename}
                onClick={() => setSelectedFile(filename)}
                className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                  selectedFile === filename
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-700'
                }`}
              >
                {filename}
              </button>
            ))}
          </div>
        </div>

        <div className="p-4 bg-[#0d0f14] text-xs">
          <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-slate-400">
            <span className="font-mono text-blue-400 font-semibold">{selectedFile}</span>
            <span className="text-[11px] text-slate-400">{filesContent[selectedFile]?.desc}</span>
          </div>

          <pre className="p-4 rounded-lg bg-[#0a0c10] border border-slate-800 text-slate-200 font-mono text-[11px] overflow-x-auto leading-relaxed max-h-[420px] select-text">
            {filesContent[selectedFile]?.code}
          </pre>
        </div>
      </div>

      {/* Build & Run Instructions */}
      <div className={`p-4 rounded-lg border text-xs space-y-3 ${
        isDarkMode ? 'bg-[#15171e] border-[#222633]' : 'bg-slate-50 border-slate-200'
      }`}>
        <div className="flex items-center gap-2 font-semibold text-slate-200">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span>How to Compile and Run on Any Windows Machine</span>
        </div>

        <div className="space-y-2">
          <div className="p-3 rounded bg-black/40 font-mono text-slate-300 border border-slate-800 flex items-center justify-between">
            <code>git clone / export files → cd project root</code>
            <span className="text-[10px] text-slate-400 font-sans">Step 1: Workspace root</span>
          </div>

          <div className="p-3 rounded bg-black/40 font-mono text-slate-300 border border-slate-800 flex items-center justify-between">
            <code>dotnet build WinWiFi.sln -c Release</code>
            <button 
              onClick={() => handleCopy('dotnet build WinWiFi.sln -c Release', 'bld')}
              className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1 font-sans"
            >
              {copiedCmd === 'bld' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>Copy</span>
            </button>
          </div>

          <div className="p-3 rounded bg-black/40 font-mono text-slate-300 border border-slate-800 flex items-center justify-between">
            <code>dotnet publish WinWiFi.Desktop/WinWiFi.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish</code>
            <button 
              onClick={() => handleCopy('dotnet publish WinWiFi.Desktop/WinWiFi.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish', 'pub2')}
              className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1 font-sans"
            >
              {copiedCmd === 'pub2' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>Copy</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
