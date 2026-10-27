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

## Install on Windows

### Recommended: use the installer

1. Open the repository's [Releases page](https://github.com/IWGF-elite/WINWifi/releases).
2. Download **`WinWiFi-Setup.exe`** from the latest release assets. This is the
   only file a normal Windows user needs to download.
3. Run the installer. It installs WinWiFi under `Program Files` and creates
   Start Menu and optional Desktop shortcuts.
4. Start **WinWiFi Security Auditor** from the Start Menu.

The installer bundles the .NET desktop runtime and the dashboard. If Microsoft
Edge WebView2 is not already installed, run the included
`Install-WebView2Runtime.exe` from the installation directory, then restart
WinWiFi. The installer is currently unsigned, so Windows may show an
**Unknown publisher** / SmartScreen prompt; verify you downloaded the file
from this repository's official Releases page before proceeding.

### Requirements for live Wi-Fi scanning

- Windows 10 version 19041 or later, or Windows 11
- A working Wi-Fi adapter enabled in Windows
- Microsoft Edge WebView2 Runtime (the installer includes Microsoft's official
  bootstrapper when it is needed)

Live scans work without an active Wi-Fi connection. Raw monitor-mode/EAPOL
capture is optional and requires Npcap plus an adapter and driver that support
802.11 monitor mode. The app reports that capability honestly when unavailable.

### Troubleshooting another PC

- **The dashboard is blank or does not open:** run
  `Install-WebView2Runtime.exe` from the WinWiFi installation folder, then
  restart the application.
- **"Could not start its local dashboard bridge":** close any other running
  WinWiFi window and start the app again. WinWiFi uses a local-only dashboard
  bridge on `127.0.0.1:38989`; it does not expose the bridge to the network.
- **No networks appear:** ensure the Windows Wi-Fi radio and adapter are
  enabled. An active Internet connection is not required for scanning.
- **Monitor-mode capture is unavailable:** this is expected unless both Npcap
  and a monitor-mode capable Wi-Fi adapter/driver are installed.

### Build from source

Use this path if no release installer is available yet, or if you want to
develop the application. You need Node.js 18+ and the .NET 8 SDK:

```powershell
git clone https://github.com/IWGF-elite/WINWifi.git
cd WINWifi
npm ci
npm run build
dotnet build WinWiFi.sln -c Release
dotnet run --project WinWiFi.Desktop\WinWiFi.Desktop.csproj -c Release
```

To create the same self-contained distribution used by the installer:

```powershell
.\scripts\publish-windows.ps1
& .\publish\win-x64\WinWiFi.exe

# Optional: compile the installer (requires Inno Setup 6)
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\WinWiFi.iss
```

The resulting installer is `publish\installer\WinWiFi-Setup.exe`.

## Running the web dashboard (no native backend required)

**Prerequisites:** Node.js 18+

```bash
npm ci
npm run dev
```

This starts the dashboard at `http://127.0.0.1:3000`. It supports offline use
out of the box — import a `.pcap`/`.cap` file or `netsh wlan show networks
mode=bssid` output, or explore the built-in training lab.

## Running the native Windows app from source (live scanning)

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

For a headless/CLI build, see `WinWiFi.CLI/`. A one-shot passive scan needs an
adapter ID from `--adapters` (there is no wildcard adapter):

```powershell
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --adapters
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --scan <adapterId>
```

`--scan` reads the Windows WLAN scan cache; it does not inject frames or change
adapter settings.

## Running self-tests

```powershell
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --test
```

Or use the desktop app's built-in **Self-Test** panel.

## License

See repository settings for license information.
