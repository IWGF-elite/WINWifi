# WinWiFi Security Auditor - Native Windows Desktop (.NET 8 WPF)

## Architecture Overview
WinWiFi is a native Windows desktop security audit suite built on **C# and .NET 8 WPF**, replacing browser sandbox constraints with direct Win32 hardware and OS integrations:

- **Native Wi-Fi Engine (`wlanapi.dll`)**: Direct P/Invoke bindings for `WlanOpenHandle`, `WlanEnumInterfaces`, `WlanScan`, and `WlanGetNetworkBssList`. Accesses raw `DOT11_BSS_ENTRY` records with BSSIDs, frequencies (kHz), RSSI (dBm), beacon intervals, and raw Information Elements (IE tags).
- **Fallback Ingestion Pipeline**: In non-elevated or restricted guest accounts, executes direct Windows `netsh wlan show networks mode=bssid` command-line parsing to extract live Wi-Fi signals with zero third-party drivers.
- **Binary PCAP & PCAPNG Dissector**: In-process binary parser supporting standard Libpcap 2.4 (`0xa1b2c3d4`, `0xd4c3b2a1`) and Next-Generation Capture PCAPNG (`0x0A0D0D0A`). Decapsulates IEEE 802.11 Radiotap headers, MAC frames, and EAPOL 4-Way Handshakes.
- **Cryptographic Validation & Hashcat Export**: Validates EAPOL M1/M2/M3/M4 key nonces (ANonce, SNonce) and Message Integrity Codes (MIC). Formats Hashcat Mode 22000 strings (`WPA*02*...`) for offline password auditing.
- **NIST SP 800-153 Compliance Heuristics**: Automated scoring engine detecting deprecated WEP-128 keys, cleartext Open networks, WPA-TKIP keystream degradation, WPS 1.0 Pixie Dust vulnerabilities, and Rogue AP / Evil Twin clones.
- **Relational SQLite Persistence**: SQLite database (`winwifi_audit.db`) using `Microsoft.Data.Sqlite` for multi-project management, captured handshakes, network history, and timestamped audit logs.
- **Enterprise Reporting**: Generates formatted executive HTML reports with vulnerability findings and remediation guidance.

## Building the Windows Executable

### Prerequisites
- Windows 10 (Build 19041+) or Windows 11
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022 or VS Code with C# Dev Kit

### Compilation Commands

To build the solution:
```powershell
dotnet build WinWiFi.sln -c Release
```

To publish as a single, self-contained Windows executable (`.exe`) that runs on any 64-bit Windows machine without requiring .NET pre-installed:
```powershell
dotnet publish WinWiFi.Desktop/WinWiFi.Desktop.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish
```

The resulting executable will be located at `./publish/WinWiFi.exe`.
