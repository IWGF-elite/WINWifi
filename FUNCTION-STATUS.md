# WinWiFi Windows feature check

Checked on Windows on 2026-10-23 after the shared React dashboard was embedded in the WebView2 desktop host.

## Verification run

- **14/14 web/service checks passed** with `npm test`, including the new policy selection and evidence persistence check.
- **20/20 native checks passed** with `dotnet run --project WinWiFi.CLI/WinWiFi.CLI.csproj -c Release --no-build -- --test`.
- `npm run lint` passed, `npm run build` passed, and `dotnet build WinWiFi.sln -c Release` passed with 0 warnings and 0 errors.
- The Vite bundle is about 604 kB minified (about 163 kB gzip) and emits the existing advisory about chunks larger than 500 kB.
- The bridge was checked separately for dashboard and asset serving, SPA fallback, local origin checks, private-network preflight, health/status responses, and SSE connection/recovery.
- A full click-through of every control in the running WebView2 window was not available in this session. This document reports service/native checks and source-level control wiring; it does not claim every control was manually clicked on screen.

## Visible sections and actions

| Section / control | Status | Behavior and limits |
|---|---|---|
| Command Center | Works with data | Summaries and findings use loaded observations. Threat promotion requires a selected finding; baseline action uses current observations. |
| Networks / Live Discovery | Works with Windows limits | Reads nearby APs from the Windows WLAN BSS cache. Refresh is passive OS telemetry; it is not monitor-mode capture or active channel hopping. |
| Stations & Clients | Works with imported data | Parses station/probe information available in supported PCAP/PCAPNG captures. Windows WLAN cache does not expose passive client observations here. |
| RF Spectrum | Works with observations | Band/channel and congestion visualizations derive from loaded AP observations. |
| Threats & Rogues | Works with observations | Heuristic findings support analyst classification and incident promotion. Findings depend on enough real or explicitly loaded training observations. |
| Investigations / incidents | Works | Status transitions, notes, evidence descriptions, and target AP snapshots are linked to incident records and persisted locally. Legacy evidence IDs without a stored record are shown as unresolved. |
| Forensics & PCAP | Works with imported data | Supported capture files populate parsed frames and inspection views. Export produces a PCAP file from available parsed packet data. |
| Handshakes | Works with imported data | Shows handshake records present in the capture. Hashcat output is available only for complete, exportable records. The Windows app does not capture real handshakes itself. |
| Projects | Works | Create, switch, rename, and delete projects. The final project cannot be deleted. Deletion removes that project's saved AP observations and analyst overrides; shared incidents and handshake records are retained. |
| Project query preview | Limited | Supports a small in-app SELECT subset over loaded access points and saved project/handshake/log data. This is not a general SQL engine and unsupported query syntax is not guaranteed to behave like SQLite. SQL dump export is a text export. |
| Reports | Works | Generates a standalone HTML report and invokes browser print for PDF. Desktop-host downloads are directed to the Desktop, with suffixes to avoid overwriting existing files. Print/PDF depends on the Windows print dialog. |
| Hardware diagnostics | Works with adapter limits | Displays interfaces and driver/scanner capabilities reported by Windows. Actual results depend on the adapter, driver, and permissions. |
| Settings / Lab | Works | Beginner/expert mode, persisted security-policy selection and evaluations, and explicitly synthetic offline training scenarios. Training observations are labeled and are not live radio data. |
| Native Desktop panel | Informational | Shows Windows build/publish instructions and bridge information; it does not invoke arbitrary build commands inside the running app. |
| Adapter selector | Works | Selects the Windows adapter used for WLAN cache reads. |
| Scan / Pause | Works with Windows limits | Starts or pauses periodic passive observation; it does not force an active radio scan. |
| Import PCAP / PCAPNG | Works with supported captures | Imports supported captures; empty station or handshake views mean those records were absent from the selected file. |
| Import netsh output | Works | Parses pasted Windows `netsh wlan show networks mode=bssid` output. |
| Self-Tests | Works | Runs the available verification suite. The automated suites cover services and native features, not every visual click path. |
| Bridge settings | Works | Connects to the local Windows bridge, reports health/diagnostic errors, and exposes supported endpoints. Remote origin access is subject to the bridge allowlist. |
| Download actions | Works | Blob downloads are kept alive through the browser download handoff; the Windows host routes WebView2 downloads to Desktop. |

## Known limits

The UI has no standalone Compliance or History navigation tab. Compliance checks are available through the policy results; event history appears in the diagnostic event stream. The Settings page displays the implemented bridge endpoints `/api/networks`, `/api/incidents`, `/api/diagnostics`, and `/api/health`.

Windows live discovery is limited to what the OS WLAN cache and adapter driver expose. Stations, frames, and handshakes remain empty until a compatible capture contains those records. WinWiFi does not perform monitor-mode capture, packet injection, or active channel hopping on Windows.

## Windows package

Build a self-contained x64 package with `scripts/publish-windows.ps1`. The output is `publish/win-x64/WinWiFi.exe`; keep its sibling `dashboard` folder beside the executable. The package includes the Microsoft WebView2 Runtime bootstrapper for machines that need the runtime installed.
