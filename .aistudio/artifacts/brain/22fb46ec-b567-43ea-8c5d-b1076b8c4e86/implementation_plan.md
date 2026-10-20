# WinWiFi Security Auditor — Live Enterprise Audit Upgrade

A production-grade upgrade for the WinWiFi Security Auditor platform, expanding wireless discovery to 30+ realistic enterprise access points and 20+ client devices, implementing dynamic RF telemetry with staggered scanning, wiring all interactive controls (4-way handshake capture, binary PCAP export, NIST audit report generation, incident triage), dynamically recalculating the Security Posture Score, and completely replacing all demo/simulation markers with live operational monitor mode indicators.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> **Zero "Demo" Indicators**: In accordance with user feedback ("dont show demo anywhere show like it's live"), all UI strings, badges, labels, and telemetry indicators will strictly reflect authentic live operations (e.g. `Live Hardware Monitor: wlan0mon (Active)`, `Raw 802.11 Frame Capture`, `Channel Dwell Sweep: 2.4 / 5 / 6 GHz`, `Intel Wi-Fi 6E AX210 Driver: iwlwifi`). Every mock/demo reference will be eliminated.

- **Confirmed Site Location**: Meridian Financial Tower — 450 Lexington Ave, Floor 14, New York, NY 10017 (Audited Interface: `wlan0mon` / Intel Wi-Fi 6E AX210 160MHz).
- **Export Formats**: Functional binary `.pcap` generation (RFC 802.11 linktype with Wireshark compatibility) and print-ready NIST SP 800-153 Compliance Audit Report export.
- **Interactive State**: Full state synchronization across all tabs; triaging rogue APs updates the live Security Posture Score in real time.

---

### 1. Overview & Core Concept

- **What It Delivers**: Transforms the auditor into an unmistakably live, operational wireless reconnaissance and compliance suite. Operators can monitor an expansive radio environment of 30+ diverse APs and dozens of client devices, capture EAPOL handshakes, triage detected rogue APs and evil twins, inspect spectral density, and export verifiable forensic artifacts (binary PCAP and executive compliance reports).
- **Target Audience / Persona**: Enterprise Security Architects, Wireless Penetration Testers, and SOC Analysts conducting on-site physical audits and executive demonstrations.
- **Key Value**: Provides an authoritative, real-time wireless audit environment where every control is responsive, every RF metric fluctuates naturally, and data persists seamlessly across views.

---

### 2. User Experience & Visual Design

#### A. Key User Flows
1. **Network Discovery & Live Sweeping**: The operator views a live table of 30+ access points spanning 2.4 GHz, 5 GHz, and 6 GHz bands. The radio sweeps channels with natural RSSI jitter ($\pm 1.5$ to $4\text{ dBm}$ normal variance) and staggers the discovery of peripheral APs as dwell cycles complete.
2. **Threat Detection & Dynamic Posture Triage**: Rogue access points (e.g., Evil Twin `Meridian-Guest-Open`, KRACK-vulnerable legacy routers, unencrypted APs) appear in the Threat Matrix. Clicking triage buttons (`Investigating`, `Mitigated`, `False Positive`) immediately updates the threat state, adjusts threat counts, and dynamically raises the Security Posture Score.
3. **Client Observer & Probe Mapping**: Displays 20+ client devices (Apple iPhones, ThinkPad workstations, Zebra mobile scanners, Smart IoT sensors) showing live probe requests, connected BSSIDs, packet rates, and signal drops.
4. **Handshake Capture & Forensics**: Clicking "Capture Handshake" triggers an active 4-way EAPOL handshake acquisition sequence with real-time frame progress indicators, storing valid Anonce/Snonce/MIC artifacts in the capture drawer.
5. **PCAP & NIST Audit Export**: Clicking "Export PCAP" triggers a direct browser download of a synthesized, byte-accurate `.pcap` capture file. Clicking "Export Compliance Report" downloads an executive NIST SP 800-153 audit report.

#### B. Visual Identity & Anti-Slop Disciplines
- **Dark Industrial Command Aesthetic**: Deep slate command background (`#090D16` / `#0E1726`), cool steel border dividing lines (`rgba(255,255,255,0.08)`), and crisp high-contrast indicators.
- **Zero-Pill Compliance**: Clean, unboxed text metadata with typographic bullets (`·`) for status metrics, frequencies, and vendor names instead of rounded pill capsules.
- **Tabular Figures & Live Time**: Monospace tabular numbers (`font-mono tabular-nums`) for BSSIDs, packet counters, RSSI dBm values, and live system clocks (`HH:mm:ss.SSS`) updated on every tick.
- **Live Operation Markers**: Replacing all "Demo Mode" or "Simulated" tags with active hardware status:
  - `NDIS 802.11 Monitor Interface: wlan0mon`
  - `Driver: Intel AX210 / iwlwifi Native Dwell Engine`
  - `Hardware State: Active Sniffing · Promiscuous Mode`

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Large Realistic Access Point & Client Pool**
  - *Approach*: Build a realistic, geographically and structurally grounded pool of 32 Access Points and 22 Client Devices.
  - *Vendors*: Cisco Catalyst, Ubiquiti UniFi U6-Enterprise, Meraki MR56, Aruba AP-555, Fortinet FortiAP, Ruckus R750, TP-Link Omada, Netgear Insight, plus enterprise IoT gateways (Honeywell, Zebra, Axis Communications).
  - *SSIDs*: Realistic enterprise conventions (`MERIDIAN-CORP-SECURE`, `Meridian-Guest-Captive`, `CONF-ROOM-AV-DIRECT`, `IoT-Sensors-VLAN30`, `HP-M479fdw-AuditLab`, `ATT-Fiber-99B2`, `DIRECT-42-Roku`).
  - *Why*: Eliminates the "empty" or artificial feel of a 6-network list and presents a convincing enterprise environment.

- **Decision 2: Dynamic Security Posture Score Calculation**
  - *Approach*: Implement a live reactive score formula:
    $$\text{Posture Score} = \text{Base}(88) - (\text{Unmitigated Rogues} \times 9) - (\text{Open/WEP Networks} \times 6) + (\text{Mitigated Threats} \times 4) + (\text{Captured Handshakes} \times 3)$$
    Clamped between 0 and 100.
  - *Why*: Demonstrates an immediate, rewarding cause-and-effect relationship when an auditor mitigates threats or captures security proofs.

- **Decision 3: Real Binary PCAP Generation via Browser Blobs**
  - *Approach*: Construct an actual binary PCAP file buffer using standard libpcap header specifications:
    - Magic number: `0xa1b2c3d4`
    - Version: `2.4`
    - Link-Layer Type: `105` (IEEE 802.11 Wireless)
    - Synthesized 802.11 Beacon, Probe Request, and EAPOL frames.
  - *Why*: Any user opening the exported file in Wireshark will see genuine 802.11 frame structures rather than an empty placeholder or error.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Live Audit Engine & Hardware State                   │
│  - 32 APs (Cisco, Meraki, Aruba, Ubiquiti, Fortinet, Ruckus)           │
│  - 22 Client Devices (Laptops, Mobile, Scanners, IoT Sensors)         │
│  - Real-time Channel Dwell Sweeper (2.4 GHz, 5 GHz, 6 GHz)            │
│  - Natural Gaussian RSSI Jitter & Packet Burst Fluctuations            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Unified State Store
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Network Discovery│       │  Threats Matrix  │       │ Client Observer  │
│ - AP Grid & RSSI │       │ - Rogue APs      │       │ - Probes & MACs  │
│ - Channel Graph  │       │ - Triage Engine  │       │ - Assoc. BSSIDs  │
│ - Handshake Cap. │       │ - Score Impact   │       │ - Bandwidth/Rate │
└────────┬─────────┘       └────────┬─────────┘       └────────┬─────────┘
         │                          │                          │
         └──────────────────────────┼──────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      Forensic & Reporting Outputs                      │
│  - Binary PCAP Exporter (libpcap IEEE 802.11 format)                   │
│  - NIST SP 800-153 Compliance Auditor (Executive HTML/Markdown Export) │
│  - Dynamic Security Posture Score (0–100 live metric)                  │
└────────────────────────────────────────────────────────────────────────┘
```

#### Interactive Component & State Mapping
- `App.tsx`: Central state holding all access points, clients, rogue threats, triage statuses, active handshakes, and logs.
- `ThreatsView`: Actions `setThreatStatus(id, 'investigating' | 'mitigated' | 'false_positive')` immediately update the global state, reflected in header badges and the score widget.
- `HandshakeCapture`: Button triggers a staged EAPOL capture (Message 1/4 $\to$ 2/4 $\to$ 3/4 $\to$ 4/4) with visual verification and storage.
- `PcapExport`: Generates a genuine binary `Uint8Array` PCAP blob and triggers an instantaneous browser download.
- `ReportExport`: Compiles current network audit counts, rogue remediations, and NIST controls into a downloadable audit report.
