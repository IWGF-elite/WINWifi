# WinWiFi Security Auditor - Native Windows Desktop (.NET 8 WPF)

## Architecture Overview
WinWiFi is a Windows desktop app with a **C#/.NET 8 WPF shell** that embeds the same React dashboard used in browser development through WebView2. The native bridge provides Windows WLAN observations and local forensic services:

- **Native Wi-Fi Engine (`wlanapi.dll`)**: Reads the Windows WLAN BSS cache through native WLAN APIs. Observation is passive; it does not request channel scans, enter monitor mode, or inject packets.
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
- Node.js 18+ to build the React dashboard
- Microsoft Edge WebView2 Runtime (the Windows package includes its Microsoft bootstrapper if it is missing)

### Compilation Commands

To compile the native solution after building the dashboard:
```powershell
npm ci
npm run build
dotnet build WinWiFi.sln -c Release
```

To create the Explorer-ready Windows package:
```powershell
.\scripts\publish-windows.ps1
```

Run `publish/win-x64/WinWiFi.exe`. Keep the `dashboard` folder beside it; if WebView2 Runtime is missing, run `Install-WebView2Runtime.exe` from the same folder.
