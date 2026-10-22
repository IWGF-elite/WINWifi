# WinWiFi Security Auditor

A Windows-focused 802.11 wireless security auditing platform combining a native
`.NET 8` scanning/forensics engine with a browser-based analyst dashboard.

- **`WinWiFi.Desktop/`** — Native `.NET 8` WPF desktop app. Talks directly to
  `wlanapi.dll` for live scanning, dissects raw PCAP/PCAPNG captures and
  EAPOL 4-way handshakes, scores networks against NIST SP 800-153, and
  persists everything to a local SQLite database. Exposes a local HTTP bridge
  (`http://127.0.0.1:38989`) that the web dashboard connects to.
- **`WinWiFi.CLI/`** — Headless console/daemon build of the same engine (no
  WPF dependency) for scripting or CI use.
- **`src/`** — The React/TypeScript analyst dashboard (dashboards, threat
  center, packet/handshake forensics, reporting, offline training lab). Can
  run standalone against imported `.pcap` files and Windows `netsh` output,
  or live against `WinWiFi.Desktop`'s HTTP bridge for real-time scanning.

## Defensive scope

This tool is passive/analysis-only by design: it does not perform active
deauthentication or packet injection, and does not crack passwords itself.
It exports standardized Hashcat 22000 hash lines for authorized offline
auditing on your own equipment. Only use this against networks and devices
you own or are explicitly authorized to test.

## Running the web dashboard

**Prerequisites:** Node.js 18+

```bash
npm install
npm run dev
```

This starts the dashboard on this PC only at `http://127.0.0.1:3000`. It fully supports offline use: import a `.pcap`/`.cap`
file or `netsh wlan show networks mode=bssid` output, or explore the built-in
training lab, with no native backend required.

## Running the native Windows engine (live scanning)

**Prerequisites:**
- Windows 10 (Build 19041+) or Windows 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Visual Studio 2022, or VS Code + the C# Dev Kit extension

```powershell
# Build everything
dotnet build WinWiFi.sln -c Release

# Run the WPF desktop app directly
dotnet run --project WinWiFi.Desktop\WinWiFi.Desktop.csproj -c Release

# ...or create a self-contained Windows release (no separate .NET install needed)
.\scripts\publish-windows.ps1
& .\publish\win-x64\WinWiFi.exe
```

The desktop app starts the local-only HTTP bridge on `127.0.0.1:38989` and
begins passive WLAN-cache observation when it finds an adapter. The web
dashboard can connect from **Settings → Native Bridge**. The bridge only
accepts loopback traffic and the dashboard's known localhost origins.

For headless/CLI use:

```powershell
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --test
```

See [`README_NATIVE.md`](README_NATIVE.md) for architecture details and
[`BUILD_STATUS.md`](BUILD_STATUS.md) for the full feature/capability matrix.

## Running self-tests

The native engine ships an in-process self-test suite covering native
interop fallbacks, PCAP parsing, EAPOL handshake extraction, and SQLite
persistence — run it from the desktop app's **Self-Test** panel, or:

```powershell
dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -c Release -- --test
```

Run `dotnet run --project WinWiFi.CLI\WinWiFi.CLI.csproj -- --help` to see
all CLI flags (`--bridge`, `--scan`, `--adapters`, `--test`, `--port`).
