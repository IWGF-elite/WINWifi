# WinWiFi Windows feature check

Checked on Windows on 2026-10-23 with the desktop workflow suite, native verification suite, web type-check, and production web build.

## Automated verification

- **22/22 desktop/native checks passed** using `WinWiFi.Desktop --test`.
- **12/12 web/service checks passed** using `test/runTests.ts`.
- The desktop workflow test exercises pause/resume, beginner/expert toggle, enrolling an access point as an enterprise asset, promoting a threat into an incident, incident status and notes, importing a sample PCAP, saving data, and switching tabs.
- Project workflow checks verify project creation, selection/loading, saved AP isolation, and activating a new empty project. HTML report generation is checked against project and network content.
- The native checks cover WLAN structure parsing, channel math, PCAP and handshake parsing, security scoring, SQLite, rogue AP heuristics, drift detection, OUI lookup, scan states, and legacy database migration.
- Windows desktop build succeeds with 0 warnings and 0 errors. Web TypeScript check passes and Vite production build succeeds.
- UI automation could not be run in this session because local browser access is disabled. The UI is covered by source inspection plus view-model/service workflows; this is not a claim that every visible control was clicked through on screen.

## What the visible sections do

| Section / control | Status | Behavior / requirement |
|---|---|---|
| Command Center | Works | Summary, alerts, RF summary, threat-to-incident action, and set-baseline action. Actions requiring a selected threat need one selected first. |
| Live Discovery | Works with Windows limits | Reads nearby AP observations from the Windows WLAN BSS cache. Select an AP to inspect it or enroll it as an asset. This is passive OS telemetry, not monitor-mode capture. |
| Stations & Clients | Works with imported data | Shows clients and probes parsed from PCAP/PCAPNG. Windows WLAN cache does not expose passive client observations here. |
| Threat Center | Works | Heuristic detections and selected-threat dossier; selected findings can be promoted to incidents. |
| Drift Monitor | Works | Compare current observations with a saved baseline; updating the baseline uses current AP observations. |
| RF Intelligence | Works | Channel, band, signal, and congestion summaries calculated from observed APs. |
| Packet Forensics | Works with imported data | Parsed 802.11 frames and selected-frame byte view appear after importing a supported capture. |
| Handshake Forensics | Works with imported data | EAPOL/PMKID results appear only when present in the imported capture; copying a Hashcat 22000 line requires a complete exportable handshake. |
| Incident Center | Works | Select an incident to change status through investigation, confirmation, false positive, or resolution. |
| Enterprise Assets | Works | Enroll a selected AP into the local approved-asset inventory. |
| Project Database | Works | Create a project and load the selected project; saved networks and related records load from that project's SQLite scope. Rename/delete controls are not provided. |
| Compliance | Works | Displays rules and findings derived from observed network data. |
| Investigations | Works with a selected incident | Add and persist a note on the selected incident. |
| Evidence | Read-only view | Displays generated/recorded forensic artifacts. The screen currently has no manual artifact-add control. |
| Diagnostics | Works | Lists detected interfaces and scan/driver capability information. Actual capabilities depend on the adapter and driver. |
| Reports | Works | Generates and exports the current project's HTML report to the Desktop. Content generation is tested; interactive Desktop save-path behavior is not UI-automated. Requires a current project. |
| History | Works | Shows the persisted subsystem event stream. |
| Settings / Lab | Partial | Beginner/expert display toggle and self-tests work. Scenario list is informational; scenario launch and database-maintenance actions are not implemented in this screen. |
| Adapter selector | Works | Selects the Windows wireless adapter used for WLAN cache reads. |
| Pause / Resume scan | Works | Pauses/resumes periodic passive observation; it does not force an active radio scan. |
| Import PCAP | Works | Imports supported packet captures and populates forensic, station, and handshake views when the capture contains those records. |
| Self-Tests | Works | Runs the automated verification suite and reports outcomes in the event log. |
| Export HTML Report | Works | Writes a timestamped HTML report to the current user’s Desktop. |

## Limits that can look like broken features

Stations, packet frames, and handshakes remain empty until a capture containing those records is imported. Live Windows discovery is limited to what the OS WLAN cache and adapter driver expose. The app does not perform monitor-mode capture, packet injection, or active channel hopping on Windows.

## Windows build

The packaged `WinWiFi.exe` in this folder is the self-contained Windows x64 desktop build. Run it on Windows 10/11 x64.
