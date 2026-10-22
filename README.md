# WinWiFi Security Auditor

A Windows-focused 802.11 wireless security auditing platform combining a native
`.NET 8` scanning/forensics engine with a browser-based analyst dashboard.

- **`WinWiFi.Desktop/`** — Native `.NET 8` WPF shell with the React dashboard
  embedded through WebView2. The local bridge serves that dashboard and the
  native Windows WLAN/PCAP/SQLite APIs on `http://127.0.0.1:38989`.
- **`WinWiFi.CLI/`** — Headless console/daemon build of the same engine (no
  WPF dependency) for scripting or CI use.
- **`src/`** — The React/TypeScript analyst dashboard (dashboards, threat
  center, packet/handshake forensics, reporting, offline training lab). The
  same UI runs in a browser for development and inside the Windows app.

## Defensive scope

This tool is passive/analysis-only by design: it does not perform active
deauthentication or packet injection, and does not crack passwords itself.
It exports standardized Hashcat 22000 hash lines for authorized offline
auditing on your own equipment. Only use this against networks and devices
you own or are explicitly authorized to test.

## Running the web dashboard

**Prerequisites:** Node.js 18+

```bash
npm ci
npm run dev
```

This starts the dashboard on this PC only at `http://127.0.0.1:3000`. It fully supports offline use: import a `.pcap`/`.cap`
file or `netsh wlan show networks mode=bssid` output, or explore the built-in
training lab, with no native backend required.

## Running the native Windows engine (live scanning)

**Prerequisites:**
- Windows 10 (Build 19041+) or Windows 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- Node.js 18+ to build/package the React dashboard
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) to display the dashboard inside the desktop window
- Visual Studio 2022, or VS Code + the C# Dev Kit extension

```powershell
# Build everything
npm ci
npm run build
dotnet build WinWiFi.sln -c Release

# Run the single-window desktop app directly (after building the dashboard)
dotnet run --project WinWiFi.Desktop\WinWiFi.Desktop.csproj -c Release

# ...or create a self-contained Windows release (no separate .NET install needed)
.\scripts\publish-windows.ps1
& .\publish\win-x64\WinWiFi.exe
```

The desktop app starts the local-only HTTP bridge on `127.0.0.1:38989`, serves
the built dashboard from that address, and opens it in the app window. It begins
passive WLAN-cache observation when it finds an adapter. No separate browser
window or dashboard development server is needed for the packaged Windows app.
The bridge only accepts loopback traffic and approved localhost origins.
The default development origins are `localhost`/`127.0.0.1` on ports 3000 and
5173. To override them, set `WINWIFI_ALLOWED_ORIGINS` before launching the app
to a semicolon-separated list of loopback origins, for example
`http://localhost:4173;http://127.0.0.1:4173`. Remote origins and origin URLs
with paths are always rejected. Chromium private-network preflights are
answered explicitly; if SSE cannot stay connected, the dashboard polls and
retries the event stream every 10 seconds.

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
