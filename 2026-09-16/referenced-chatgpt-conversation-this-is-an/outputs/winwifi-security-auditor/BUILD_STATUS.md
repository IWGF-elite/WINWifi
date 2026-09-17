# WinWiFi Security Auditor: Next-Generation Enterprise Platform Status

## Overview
WinWiFi has evolved from a foundational Wi-Fi scanner and PCAP dissector into a **next-generation Windows wireless security and intelligence platform**. It integrates deep 802.11 Layer-2 forensics with automated threat detection, NIST SP 800-153 policy compliance auditing, progressive disclosure UX (Beginner vs. Expert mode), offline interactive training, and enterprise SecOps workflows.

---

## Operational Capabilities Matrix

### 1. Executive & Security Operations Dashboard (`CommandCenterDashboard`)
- **Executive Posture Metric**: Real-time aggregated security score (0–100) reflecting weighted posture across all detected BSSIDs.
- **Threat Indicator Summary**: Immediate counters for Critical Rogue APs, High-Risk Findings (WEP, Open, vulnerable WPS PIN), and Observed Active Clients.
- **Plain-English Executive Synthesis**: Grounded natural-language summary detailing what is safe, what is risky, recent changes, and recommended operational priorities.
- **Rapid Filter Jump**: One-click navigation to pre-filtered views (e.g. view Rogues, view Vulnerable, view Handshakes).

### 2. Wireless Asset Inventory & Classification (`AssetInventory`)
- **Asset Categories**: Corporate, Guest, IoT, Unknown, Suspicious, Rogue, and Trusted.
- **Lifecycle & Governance**: Status tracking (`Approved`, `Unapproved`, `Investigating`, `Pending Review`) with custom tags and location metadata (Site, Building, Floor, Notes).
- **Search & Quick Toggles**: Filter by SSID, BSSID, vendor, or direct tokens (`wps`, `tkip`, `rogue`, `wep`, `wpa3`).
- **Progressive Disclosure**: Beginner view highlights intuitive status cards and plain-English risk tags; Expert mode exposes full RSN Information Elements, PMF bit flags, and raw beacon rates.

### 3. Passive Station & Client Observer (`ClientObserver`)
- **Station Monitoring**: Tracks connected client MACs, hardware vendors, RSSI signal, TX/RX data rates, and probe requests.
- **Association Mapping**: Correlates stations to their associated AP BSSID or flags unassociated probing devices.
- **EAPOL Activity Tracking**: Displays observed handshake key exchange steps without active deauthentication.

### 4. RF Spectrum & Overlap Visualizer (`SpectrumVisualizer`)
- **Multi-Band Support**: 2.4 GHz, 5 GHz, and 6 GHz spectrum visualization.
- **Channel Overlap & Interference**: Identifies co-channel and adjacent-channel contention and recommends cleaner channels for corporate APs.
- **Interactive Inspection**: Direct selection of AP curves highlights channel boundaries and spectral density.

### 5. Threats & Rogue AP Intelligence (`ThreatCenter`)
- **Multi-Factor Correlation**:
  1. *SSID Collision Check*: Identical SSID broadcasting on multiple BSSIDs.
  2. *OUI & Hardware Divergence*: Flags APs where the manufacturer OUI does not match the enterprise vendor baseline.
  3. *Security Profile Downgrade*: Detects Evil Twins offering Open or TKIP while the authentic AP mandates WPA2/WPA3.
  4. *Channel & Band Anomalies*: Highlights rogue APs operating outside authorized radio bands.
- **Analyst Override**: Security analysts can mark candidates as "Confirmed Rogue", "Authorized Clone", or "False Positive".
- **Security Change Timeline**: Real-time audit log of configuration shifts (cipher changes, WPS toggles, new BSSID appearances).

### 6. Incident Investigation Center (`IncidentCenter`)
- **Formal Case Files**: Structured incident tickets (e.g., `INC-00042`) with severity ranking, confidence scores, and assigned investigators.
- **Evidence Vault**: Bidirectional linking to raw capture packets, observations, and handshake nonces (`EVD-xxxx`).
- **Analyst Journal & Resolution Workflow**: Chronological note logging and state transition (`Open` → `Investigating` → `Resolved`).

### 7. 802.11 Layer-2 Binary Forensics & PCAP Dissector (`PacketAnalyzer`, `PcapService`)
- **Multi-Format PCAP/PCAPNG Parsing**: Decodes raw Libpcap (magic `0xa1b2c3d4`, `0xa1b23c4d`, `0xd4c3b2a1`) and PCAPNG block structures (`0x0A0D0D0A`).
- **Full 802.11 Stack Decapsulation**: LinkType 127 Radiotap headers (RSSI, Channel frequency, Antenna flags), MAC Frame Control (Beacon, Probe, Auth, Deauth, EAPOL-Key), and Variable Information Elements (SSID, Supported Rates, RSN/WPA Tag 48, WPS Tag 221).
- **Hex/ASCII Dissection Inspector**: Color-coded byte viewers showing raw frame bytes alongside decoded protocol structures.

### 8. Cryptographic Handshake & Key Dissector (`HandshakeManager`)
- **EAPOL 4-Way Exchange**: Dissects Messages 1 through 4, extracting AP Nonce (ANonce), Client Nonce (SNonce), Replay Counters, and Message Integrity Code (MIC).
- **Quality & Integrity Scoring**: Validates MIC against frame HMAC/CRC32 and checks sequential replay counter increments.
- **Audit Export**: Generates compliant Hashcat Mode 22000 / PMKID strings (`WPA*02*<MIC>*<BSSID>*<CLIENT>*...`) for authorized password audits.

### 9. Multi-Site Enterprise Scope & SQLite Storage (`EnterpriseProjectManager`, `SqliteDatabaseService`)
- **Enterprise Hierarchy**: Organization → Site → Building → Area → Assessment.
- **Persistent Storage**: Client-side SQLite architecture storing project sessions, network baselines, captured handshakes, and diagnostic logs.
- **Interactive SQL Terminal**: Execute ad-hoc queries (`SELECT ssid, rssi, security FROM access_points ORDER BY rssi DESC`) directly against the local audit database.

### 10. Reporting Center & Executive Briefing (`ReportingCenter`, `ReportingModal`)
- **Dual-Audience Reporting**:
  - *Executive Briefing*: Non-technical summary focused on business risk, compliance status, and high-level priorities.
  - *Technical Audit Report*: Comprehensive tabular breakdown with NIST SP 800-153 section references, raw BSSIDs, and remediation guides.
- **Standalone Exports**: Print-ready format and standalone HTML file generation with zero external CSS dependencies.

### 12. Windows .NET 8 Native WPF Platform & Workspaces
- **Full-Spectrum Multi-Workspace Architecture**:
  1. *Command Center*: Operational dashboard featuring 6 KPI metrics cards, RF health summary, high-priority security alert stream, and immediate incident triage actions.
  2. *Live Discovery*: Persistent observation model tracking observation counts, first seen, last seen timestamps, signal quality, hardware vendor, and deep 802.11 Information Element inspector.
  3. *Stations & Clients*: Real client station tracking with observed MAC, vendor/OUI, RSSI, associated AP or unassociated probing state, and probe request history.
  4. *Threat Center*: Multi-factor threat engine identifying Rogue APs, Evil Twins, security downgrades, PMF stripped, WPS exposed, and LAA anomalies with NIST SP 800-153 references.
  5. *Drift Monitor*: Baseline snapshot comparison tracking unauthorized encryption changes, PMF status drift, and channel shifts.
  6. *RF Intelligence*: Non-fabricated RF distribution covering 2.4 GHz, 5 GHz, and 6 GHz spectrum with co-channel interference detection.
  7. *Packet Forensics*: Dissected frames list with Radiotap headers, IEEE 802.11 frame control flags, and dual-pane Hex + ASCII byte inspector.
  8. *Handshake Forensics*: EAPOL 4-way handshake reconstruction with ANonce, SNonce, MIC, PMKID, and 1-click Hashcat Mode 22000 copy/export.
  9. *Incident Center*: Operational incident triage lifecycle (New -> Investigating -> Confirmed Rogue -> False Positive -> Resolved) with evidence links.
  10. *Enterprise Asset Inventory*: Corporate wireless repository with approval status, lifecycle classification, and location tagging (Site, Building, Floor).
  11. *Project Database*: SQLite relational storage in WAL mode with concurrent access and automated self-test verification.
- **Dual Presentation Modes**: Instant toggling between Beginner Mode (plain-English executive summaries) and Expert Mode (raw cryptographic nonces, bitmasks, and IE tags).
- **100% Offline-First**: Zero external cloud or internet runtime dependencies. Runs completely self-contained.

### 12. Settings, Policy Engine & Interactive Offline Lab (`SettingsAndLab`, `OfflineLab`)
- **NIST SP 800-153 Compliance Engine**: Evaluates networks against configurable rules (WEP ban, TKIP ban, Open network restriction, WPS registrar prohibition, PMF requirement).
- **8 Pre-Built Training Scenarios**:
  - `LAB-01`: Standard Enterprise Baseline (WPA3/WPA2 with PMF)
  - `LAB-02`: Evil Twin Rogue AP Downgrade
  - `LAB-03`: Legacy WEP Warehouse Vulnerability
  - `LAB-04`: WPS PIN Registrar Flaw
  - `LAB-05`: Unencrypted Cleartext Guest Hotspot
  - `LAB-06`: Missing PMF & Deauth Vulnerability
  - `LAB-07`: Multi-Band RF Channel Overlap
  - `LAB-08`: Complete EAPOL 4-Way Handshake
- **Local Automation API**: REST endpoint documentation for CI/CD or headless automation (`GET /api/v1/scan/networks`, `POST /api/v1/audit/evaluate`).

### 13. Native .NET 8 WPF Desktop Integration (`NativeDesktopPanel`, `WinWiFi.Desktop`)
- Complete C# / WPF solution mirroring all data models, native P/Invoke calls to `wlanapi.dll`, binary PCAP dissector, and report generators.

---

## Defensive Compliance Boundary
- **Active Deauthentication**: Strictly omitted. WinWiFi relies entirely on passive radio observation and authorized capture analysis.
- **Raw Attack Packet Injection**: Strictly omitted.
- **Password/Credential Cracking**: Strictly omitted. WinWiFi exports standardized audit hashes (Hashcat Mode 22000) for processing on authorized, dedicated enterprise cracking clusters.

---

## Verification & Build Status
- **TypeScript Compiler (`tsc --noEmit`)**: 0 errors, clean compilation.
- **Vite Production Build (`vite build`)**: Complete; all assets bundled cleanly into `/dist`.
