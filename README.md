# WinWiFi Security Auditor

> ⚠️ **Status: Active development.** Core features work and are regularly tested, but expect ongoing changes.

A Wi-Fi security auditing tool for Windows. It scans nearby wireless networks,
evaluates their security configuration against known best practices (NIST SP
800-153), and helps you spot weak or misconfigured access points on networks
you own or are authorized to test — open networks, outdated encryption (WEP,
WPA-TKIP), unlocked WPS, missing Protected Management Frames, rogue/evil-twin
access points, and more.

It ships as a native Windows desktop app with a web-based dashboard, and can
also run as a standalone offline dashboard for reviewing imported capture
files without any native backend.

## Features

- Live Wi-Fi network scanning (SSID, BSSID, signal, channel, security type,
  vendor) via the Windows WLAN API
- Weighted security risk scoring with a transparent, explainable breakdown
- Full IEEE OUI vendor lookup and randomized-MAC detection
- PCAP/PCAPNG import with 802.11 frame and EAPOL handshake parsing
- A packet-frame inspector (filters, field tree, hex view) for
  imported captures
- Rogue/evil-twin detection and configuration drift tracking over time
- Policy compliance scoring and reporting
- Connect to networks directly from the app (using a password you provide)

## Defensive scope

This tool is passive and analysis-only: it does not perform deauthentication,
packet injection, or password cracking, and it will only act on networks
explicitly added to its authorized scope. Only use it against networks and
devices you own or are explicitly authorized to test.

## Built with

.NET 8 (WPF) for the Windows desktop shell and native WLAN/PCAP integration,
React + TypeScript for the dashboard UI, and SQLite for local persistence.

## Running the web dashboard (no native backend required)

**Prerequisites:** Node.js 18+

```bash
npm ci
npm run dev
```

This starts the dashboard at `http://127.0.0.1:3000`. It supports offline use
out of the box — import a `.pcap`/`.cap` file or `netsh wlan show networks
mode=bssid` output, or explore the built-in training lab.

## Running the native Windows app (live scanning)

**Prerequisites:**
- Windows 10 (Build 19041+) or Windows 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Node.js 18+
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
- Visual Studio 2022, or VS Code + the C# Dev Kit extension

```powershell
npm ci
npm run build
dotnet build WinWiFi.sln -c Release

# Run directly
dotnet run --project WinWiFi.Desktop\WinWiFi.Desktop.csproj -c Release

# ...or build a self-contained release
.\scripts\publish-windows.ps1
& .\publish\win-x64\WinWiFi.exe
```

For a headless/CLI build, see `WinWiFi.CLI/`.

## Running self-tests

```powershell
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --test
```

Or use the desktop app's built-in **Self-Test** panel.

## License

See repository settings for license information.
