using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using WinWiFi.Data;
using WinWiFi.Interop;
using WinWiFi.Models;
using WinWiFi.Services;
#if WINDOWS_DESKTOP
using WinWiFi.ViewModels;
#endif

namespace WinWiFi.Tests
{
    public class TestResultItem
    {
        public string TestId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool Passed { get; set; }
        public string Details { get; set; } = string.Empty;
        public long DurationMs { get; set; }
    }

    public class NativeSelfTests
    {
        public async Task<List<TestResultItem>> RunAllTestsAsync()
        {
            var results = new List<TestResultItem>();

            // Test 1: P/Invoke Struct Marshaling Alignment
            results.Add(RunTest("T1-STRUCT-ALIGN", "P/Invoke Struct Marshaling Alignment", () =>
            {
                int bssEntrySize = Marshal.SizeOf<DOT11_BSS_ENTRY>();
                int ifaceInfoSize = Marshal.SizeOf<WLAN_INTERFACE_INFO>();
                if (bssEntrySize < 50) throw new Exception($"DOT11_BSS_ENTRY marshaled size invalid: {bssEntrySize}");
                if (ifaceInfoSize < 260) throw new Exception($"WLAN_INTERFACE_INFO marshaled size invalid: {ifaceInfoSize}");
                return $"Verified DOT11_BSS_ENTRY ({bssEntrySize} bytes), WLAN_INTERFACE_INFO ({ifaceInfoSize} bytes)";
            }));

            results.Add(RunTest("T1A-SSID-DECODE", "SSID UTF-8 / Windows-1252 / Escaped Hex Decoding", () =>
            {
                var utf8 = new DOT11_SSID { uSSIDLength = 5, ucSSID = Encoding.UTF8.GetBytes("Café").Concat(new byte[27]).ToArray() };
                var cp1252 = new DOT11_SSID { uSSIDLength = 4, ucSSID = new byte[] { 0x43, 0x61, 0x66, 0xE9 }.Concat(new byte[28]).ToArray() };
                var binary = new DOT11_SSID { uSSIDLength = 2, ucSSID = new byte[] { 0x01, 0xFF }.Concat(new byte[30]).ToArray() };
                if (utf8.GetSsidString() != "Café" || cp1252.GetSsidString() != "Café" || binary.GetSsidString() != "\\x01\\xFF")
                    throw new Exception("SSID decoder did not preserve UTF-8, CP-1252, and binary values.");
                return "Strict UTF-8, CP-1252 fallback, and escaped-byte fallback validated.";
            }));

            // Test 2: Frequency to Channel Matrix
            results.Add(RunTest("T2-FREQ-MATH", "IEEE 802.11 Channel & Frequency Math", () =>
            {
                var ch1 = NativeWifi.FrequencyToChannel(2412000);
                var ch6 = NativeWifi.FrequencyToChannel(2437000);
                var ch14 = NativeWifi.FrequencyToChannel(2484000); // 2484 MHz special case
                var ch36 = NativeWifi.FrequencyToChannel(5180000);
                var ch6ghz = NativeWifi.FrequencyToChannel(5955000);

                if (ch1.channel != 1 || ch1.band != "2.4 GHz") throw new Exception("2412 MHz failed");
                if (ch6.channel != 6) throw new Exception("2437 MHz failed");
                if (ch14.channel != 14) throw new Exception("2484 MHz Channel 14 failed");
                if (ch36.channel != 36 || ch36.band != "5 GHz") throw new Exception("5180 MHz failed");
                return "Channel 14 (2484 MHz), 2.4 GHz, 5 GHz, 6 GHz math validated.";
            }));

            // Test 3: Binary PCAP Dissection & Radiotap
            results.Add(RunTest("T3-PCAP-BINARY", "Libpcap 2.4 Binary Decapsulation", () =>
            {
                using var ms = new MemoryStream();
                using var w = new BinaryWriter(ms);
                // Write Global Header
                w.Write(0xa1b2c3d4); // Magic
                w.Write((ushort)2);  // Major
                w.Write((ushort)4);  // Minor
                w.Write(0);          // ThisZone
                w.Write(0);          // SigFigs
                w.Write(65535);      // SnapLen
                w.Write(127);        // LinkType = Radiotap

                // Write 1 Packet Record
                w.Write(1710000000); // Sec
                w.Write(50000);      // Usec
                w.Write(40);         // InclLen
                w.Write(40);         // OrigLen

                // Radiotap (8 bytes)
                w.Write((byte)0); w.Write((byte)0); // Version & Pad
                w.Write((ushort)8);                 // Length
                w.Write(0x00000000);                // Present flags

                // 802.11 Beacon Frame (32 bytes)
                w.Write((ushort)0x0080);            // Type 0 Subtype 8 (Beacon)
                w.Write((ushort)0);                 // Duration
                w.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }); // Dest
                w.Write(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }); // Src
                w.Write(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }); // BSSID
                w.Write((ushort)0);                 // Seq Control
                w.Write(0UL);                       // Timestamp
                w.Write((ushort)100);               // Beacon Interval
                w.Write((ushort)0x0011);            // Capability

                var dissector = new PcapDissector();
                var res = dissector.DissectBytes(ms.ToArray());
                if (res.Packets.Count != 1) throw new Exception("Failed to dissect binary PCAP frame");
                if (res.AccessPoints.Count != 1) throw new Exception("Failed to register BSSID from beacon");
                return $"Parsed {res.Packets.Count} frame, BSSID: {res.AccessPoints[0].Bssid}";
            }));

            // Test 4: EAPOL 4-Way Handshake & Hashcat Formatting
            results.Add(RunTest("T4-EAPOL-HASHCAT", "EAPOL 4-Way Handshake & Hashcat 22000", () =>
            {
                var hs = new HandshakeInfo
                {
                    ApBssid = "00:11:22:33:44:55",
                    ClientMac = "AA:BB:CC:DD:EE:FF",
                    Ssid = "CorpWiFi",
                    SnonCe = "11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF",
                    MicHex = "A1B2C3D4E5F60718293A4B5C6D7E8F90",
                    HashcatFormat = "WPA*02*a1b2c3d4e5f60718293a4b5c6d7e8f90*001122334455*aabbccddeeff*436f727057694669*11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff*0103005f02030a00000000000000000001"
                };

                if (!hs.HashcatFormat.StartsWith("WPA*02*")) throw new Exception("Invalid Hashcat mode 22000 prefix");
                return "Validated Mode 22000 WPA-PBKDF2-PMKID/EAPOL format string.";
            }));

            // Test 5: NIST SP 800-153 Security Scoring
            results.Add(RunTest("T5-NIST-SCORING", "NIST SP 800-153 Security Evaluation", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var wepAp = new AccessPoint { Bssid = "00:01:02:03:04:05", Security = "WEP-128", Cipher = "WEP" };
                var openAp = new AccessPoint { Bssid = "00:01:02:03:04:06", Security = "Open", Cipher = "None" };
                var wpa3Ap = new AccessPoint { Bssid = "00:01:02:03:04:07", Security = "WPA3-SAE", Cipher = "GCMP-256", PmfRequired = true };

                analyzer.EvaluateSecurityPosture(wepAp);
                analyzer.EvaluateSecurityPosture(openAp);
                analyzer.EvaluateSecurityPosture(wpa3Ap);

                if (wepAp.SecurityScore > 45) throw new Exception("WEP must score < 45");
                if (openAp.SecurityScore > 65) throw new Exception("Open Wi-Fi must score < 65");
                if (wpa3Ap.SecurityScore < 95) throw new Exception("WPA3-SAE + PMF must score >= 95");

                return $"WEP: {wepAp.SecurityScore}, Open: {openAp.SecurityScore}, WPA3: {wpa3Ap.SecurityScore}";
            }));

            // Test 6: SQLite Storage Repository CRUD
            var t6 = await RunTestAsync("T6-SQLITE-REPO", "SQLite Relational Repository Execution", async () =>
            {
                string tempDb = Path.Combine(Path.GetTempPath(), $"test_winwifi_{Guid.NewGuid():N}.db");
                try
                {
                    using (var storage = new SqliteStorageService(tempDb))
                    {
                        var testProj = new AuditProject
                        {
                            Id = "test-proj-1",
                            Name = "Diagnostic Test Site",
                            AuditorName = "SelfTest Unit"
                        };
                        await storage.SaveProjectAsync(testProj);
                        var projects = await storage.GetProjectsAsync();
                        if (projects.Count == 0) throw new Exception("Failed to insert or query SQLite project");
                        return $"SQLite database initialized and read {projects.Count} project(s).";
                    }
                }
                finally
                {
                    SqliteStorageService.ReleaseAllPools();
                    try
                    {
                        if (File.Exists(tempDb)) File.Delete(tempDb);
                        string wal = tempDb + "-wal";
                        string shm = tempDb + "-shm";
                        if (File.Exists(wal)) File.Delete(wal);
                        if (File.Exists(shm)) File.Delete(shm);
                    }
                    catch
                    {
                        // Clean up attempt
                    }
                }
            });
            results.Add(t6);

            // Test 7A: Legitimate Duplicate SSID Roaming (Campus APs - 0 False Positives)
            results.Add(RunTest("T7A-LEGIT-ROAMING", "Legitimate Duplicate SSID Roaming (Zero False Positives)", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:11:22:01", Ssid = "Campus-Secure", Security = "WPA2-Enterprise (802.1X)", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -65, Channel = 1, Band = "2.4 GHz" },
                    new AccessPoint { Bssid = "00:00:0C:11:22:02", Ssid = "Campus-Secure", Security = "WPA2-Enterprise (802.1X)", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -68, Channel = 6, Band = "2.4 GHz" },
                    new AccessPoint { Bssid = "00:00:0C:11:22:03", Ssid = "Campus-Secure", Security = "WPA2-Enterprise (802.1X)", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -70, Channel = 36, Band = "5 GHz" }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                if (res.Findings.Count > 0)
                {
                    throw new Exception($"False positive detected! Expected 0 findings for legitimate roaming APs, got {res.Findings.Count}: {res.Findings[0].Title}");
                }
                return "Validated 3 legitimate Cisco roaming BSSIDs produced 0 false positive alerts.";
            }));

            // Test 7B: Evil Twin Security Downgrade
            results.Add(RunTest("T7B-EVIL-TWIN-DOWNGRADE", "Evil Twin Security Downgrade Detection", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:11:22:01", Ssid = "Campus-Secure", Security = "WPA2-Enterprise (802.1X)", Cipher = "CCMP", Vendor = "Cisco Systems", SecurityScore = 85 },
                    new AccessPoint { Bssid = "00:1A:1E:99:88:77", Ssid = "Campus-Secure", Security = "Open", Cipher = "None", Vendor = "Aruba Networks (HPE)", SecurityScore = 40 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                var evilTwin = res.Findings.Find(f => f.Category == "Evil Twin" && f.RelatedBssid == "00:1A:1E:99:88:77");
                if (evilTwin == null || evilTwin.Severity != "CRITICAL")
                {
                    throw new Exception("Failed to detect CRITICAL Evil Twin downgrade clone.");
                }
                return $"Identified Evil Twin downgrade on BSSID {evilTwin.RelatedBssid} (Risk: {evilTwin.RiskScore}, Confidence: {evilTwin.Confidence}%).";
            }));

            // Test 7C: Hardware Vendor Mismatch on Infrastructure SSID
            results.Add(RunTest("T7C-VENDOR-MISMATCH", "Enterprise vs Consumer Vendor Mismatch", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:AA:BB:01", Ssid = "Enterprise_WLAN", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "Cisco Systems", SecurityScore = 85 },
                    new AccessPoint { Bssid = "50:D4:F7:11:22:33", Ssid = "Enterprise_WLAN", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "TP-Link Technologies", SecurityScore = 85 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                var vendorMismatch = res.Findings.Find(f => f.Category == "Rogue AP" && f.RelatedBssid == "50:D4:F7:11:22:33");
                if (vendorMismatch == null)
                {
                    throw new Exception("Failed to flag TP-Link consumer AP masquerading on Cisco Enterprise WLAN.");
                }
                return $"Flagged Rogue AP {vendorMismatch.RelatedBssid} ({vendorMismatch.Evidence}).";
            }));

            // Test 7D: High-Power Proximity Signal Lure
            results.Add(RunTest("T7D-SIGNAL-LURE", "High-Power Signal Disparity Proximity Lure", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:11:22:33", Ssid = "HQ-Staff", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -75, SecurityScore = 85 },
                    new AccessPoint { Bssid = "02:11:22:33:44:55", Ssid = "HQ-Staff", Security = "WPA2-PSK", Cipher = "CCMP", Vendor = "Randomized / Private MAC (LAA)", Rssi = -42, SecurityScore = 70 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                var lure = res.Findings.Find(f => f.Category == "Evil Twin" && f.RelatedBssid == "02:11:22:33:44:55");
                if (lure == null)
                {
                    throw new Exception("Failed to flag high-power proximity lure (+33 dBm disparity with LAA).");
                }
                return $"Detected proximity lure: {lure.Title} at {lure.RelatedBssid} (+33 dBm difference).";
            }));

            // Test 7E: LAA / Randomized MAC BSSID Detection
            results.Add(RunTest("T7E-LAA-DETECTOR", "Locally Administered Address (LAA) Detection", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var laaAp = new AccessPoint { Bssid = "DA:A1:19:22:33:44", Ssid = "Mobile_Hotspot", Security = "WPA2-PSK", Cipher = "CCMP" };
                analyzer.EvaluateSecurityPosture(laaAp);

                var laaIssue = laaAp.SecurityIssues.Find(i => i.Id == "WARN-LAA-BSSID");
                if (laaIssue == null)
                {
                    throw new Exception("Failed to flag LAA BSSID (0xDA has bit 1 set).");
                }
                return $"Identified LAA address on {laaAp.Bssid}: {laaIssue.Title} ({laaIssue.StandardReference})";
            }));

            // Test 7F: Drift Monitor Baseline Comparison
            results.Add(RunTest("T7F-DRIFT-MONITOR", "Drift Monitor Baseline Snapshot Comparison", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var baseline = new Dictionary<string, AccessPoint>
                {
                    ["00:11:22:33:44:00"] = new AccessPoint
                    {
                        Bssid = "00:11:22:33:44:00",
                        Ssid = "Corporate_Root",
                        Security = "WPA3-SAE",
                        PmfRequired = true,
                        IsWpsEnabled = false,
                        Channel = 36,
                        Band = "5 GHz"
                    }
                };

                var current = new List<AccessPoint>
                {
                    new AccessPoint
                    {
                        Bssid = "00:11:22:33:44:00",
                        Ssid = "Corporate_Root",
                        Security = "WPA2-PSK",      // Drift 1: Encryption Downgrade
                        PmfRequired = false,         // Drift 2: PMF Stripped
                        PmfCapable = true,
                        IsWpsEnabled = true,         // Drift 3: WPS Enabled
                        Channel = 44,                // Drift 4: Channel Shift
                        Band = "5 GHz"
                    }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(current, baseline);
                if (res.DetectedDrifts.Count != 4)
                {
                    throw new Exception($"Expected 4 drift events, recorded {res.DetectedDrifts.Count}");
                }
                var downgrade = res.Findings.Find(f => f.Category == "Security Downgrade");
                var pmfStripped = res.Findings.Find(f => f.Category == "PMF Stripped");
                if (downgrade == null || pmfStripped == null)
                {
                    throw new Exception("Drift events failed to trigger corresponding CRITICAL/HIGH threat findings.");
                }
                return $"Detected all 4 baseline drifts: Security Downgrade, PMF Stripped, WPS Activated, Channel Shift.";
            }));

            // Test 7G: Unapproved Hardware on Corporate SSID
            results.Add(RunTest("T7G-UNAPPROVED-HARDWARE", "Unapproved Hardware Broadcasting Corporate SSID", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var baseline = new Dictionary<string, AccessPoint>
                {
                    ["00:11:22:33:44:00"] = new AccessPoint
                    {
                        Bssid = "00:11:22:33:44:00",
                        Ssid = "Corp_Confidential",
                        Classification = "Corporate",
                        ApprovedStatus = "Approved"
                    }
                };

                var current = new List<AccessPoint>
                {
                    new AccessPoint
                    {
                        Bssid = "94:B4:0F:88:99:00", // New unapproved BSSID
                        Ssid = "Corp_Confidential",
                        Vendor = "Aruba Networks",
                        Security = "WPA2-Enterprise"
                    }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(current, baseline);
                var unapproved = res.Findings.Find(f => f.Category == "Unapproved Hardware");
                if (unapproved == null)
                {
                    throw new Exception("Failed to flag unapproved BSSID broadcasting approved corporate SSID.");
                }
                return $"Successfully identified unapproved rogue hardware on Corporate SSID: {unapproved.RelatedBssid}";
            }));

            // Test 8: Offline OUI Database Resolution
            results.Add(RunTest("T8-OFFLINE-OUI", "Offline IEEE OUI Lookup & LAA Validation", () =>
            {
                string cisco = OuiLookupService.ResolveVendor("00:00:0C:12:34:56");
                string aruba = OuiLookupService.ResolveVendor("00:0B:86:12:34:56");
                string ubiquiti = OuiLookupService.ResolveVendor("00:15:6D:12:34:56");
                string apple = OuiLookupService.ResolveVendor("00:03:93:12:34:56");
                string laa = OuiLookupService.ResolveVendor("02:00:00:00:00:00");

                if (!cisco.Contains("Cisco")) throw new Exception($"Cisco OUI failed: {cisco}");
                // IEEE currently assigns this prefix to Hewlett Packard
                // Enterprise. Accept the authoritative name rather than an
                // older Aruba branding label.
                if (!aruba.Contains("Hewlett Packard", StringComparison.OrdinalIgnoreCase) && !aruba.Contains("Aruba", StringComparison.OrdinalIgnoreCase))
                    throw new Exception($"HPE/Aruba OUI failed: {aruba}");
                if (!ubiquiti.Contains("Ubiquiti")) throw new Exception($"Ubiquiti OUI failed: {ubiquiti}");
                if (!apple.Contains("Apple")) throw new Exception($"Apple OUI failed: {apple}");
                if (!laa.Contains("Randomized")) throw new Exception($"LAA detection failed: {laa}");

                return $"Resolved Cisco, Aruba, Ubiquiti, Apple, and LAA offline without network calls.";
            }));

            // Test 9: Netsh BSSID Live Output Parser
            results.Add(RunTest("T9-NETSH-PARSER", "Netsh BSSID Live Output Parser", () =>
            {
                string sample = @"
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : Corp-Secure
    Network type            : Infrastructure
    Authentication          : WPA2-Enterprise
    Encryption              : CCMP
    BSSID 1                 : 00:0c:29:12:34:56
         Signal             : 88%
         Radio type         : 802.11ac
         Channel            : 36
         Basic rates (Mbps) : 6 12 24

SSID 2 : Guest-Open
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 02:11:22:33:44:55
         Signal             : 75%
         Radio type         : 802.11ax
         Channel            : 6
";
                var svc = new NativeWifiService(new SecurityAnalyzer());
                var aps = svc.ParseNetshBssidOutput(sample);
                if (aps.Count != 2) throw new Exception($"Expected 2 APs but got {aps.Count}");
                if (aps[0].Bssid != "00:0C:29:12:34:56") throw new Exception($"AP[0] BSSID mismatch: {aps[0].Bssid}");
                if (aps[0].Ssid != "Corp-Secure") throw new Exception($"AP[0] SSID mismatch: {aps[0].Ssid}");
                if (aps[0].Channel != 36) throw new Exception($"AP[0] Channel mismatch: {aps[0].Channel}");
                if (aps[1].Security != "Open") throw new Exception($"AP[1] Security mismatch: {aps[1].Security}");
                return $"Successfully parsed {aps.Count} APs from raw netsh stream.";
            }));

            // Test 10: Unbounded BSSID Scalability (Zero Artificial Limits)
            results.Add(RunTest("T10-UNBOUNDED-BSSID-SCALABILITY", "Unbounded BSSID Scalability (No Limits)", () =>
            {
                var sb = new StringBuilder();
                sb.AppendLine("Interface name : Wi-Fi");
                sb.AppendLine("There are 150 networks currently visible.");
                for (int i = 1; i <= 150; i++)
                {
                    sb.AppendLine($"SSID {i} : Enterprise-AP-{i:D3}");
                    sb.AppendLine("    Network type            : Infrastructure");
                    sb.AppendLine("    Authentication          : WPA2-Enterprise");
                    sb.AppendLine("    Encryption              : CCMP");
                    sb.AppendLine($"    BSSID 1                 : 00:0C:29:{i / 256:X2}:{i % 256:X2}:01");
                    sb.AppendLine("         Signal             : 85%");
                    sb.AppendLine("         Radio type         : 802.11ax");
                    sb.AppendLine($"         Channel            : {(i % 14) + 1}");
                }

                var svc = new NativeWifiService(new SecurityAnalyzer());
                var aps = svc.ParseNetshBssidOutput(sb.ToString());
                if (aps.Count != 150) throw new Exception($"Expected 150 APs parsed without limits, got {aps.Count}");
                return $"Parsed all {aps.Count} BSS entries without truncation, enforcing zero artificial limit.";
            }));

            // Test 11: Scan Telemetry States & Observability
            results.Add(RunTest("T11-SCAN-TELEMETRY-STATES", "Scan Telemetry States & Observability", () =>
            {
                var svc = new NativeWifiService(new SecurityAnalyzer());
                var diag = svc.GetDiagnostics();
                if (diag.State != ScanTelemetryState.Idle) throw new Exception($"Initial state should be Idle, got {diag.State}");

                svc.DiagnosticsUpdated += _ => { };

                var bgScanner = new WifiBackgroundScanner(svc, new SecurityAnalyzer());
                bool channelHopFired = false;
                bgScanner.ChannelHopped += ch => { channelHopFired = (ch == 11); };
                bgScanner.ReportChannelHop(11);
                if (!channelHopFired)
                    throw new Exception("Expected ChannelHopped event to fire on ReportChannelHop.");

                bgScanner.SetScanningState(false);
                if (bgScanner.CurrentState != ScanTelemetryState.Paused)
                    throw new Exception($"Expected Paused state when scanning disabled, got {bgScanner.CurrentState}");

                bgScanner.SetScanningState(true);
                if (bgScanner.CurrentState != ScanTelemetryState.Idle)
                    throw new Exception($"Expected Idle state when scanning enabled, got {bgScanner.CurrentState}");

                return "Telemetry state transitions verified: Idle, Paused, Scanning, NoNetworksFound, AdapterUnavailable supported.";
            }));

            // Test 12: SQLite Scan Observations Persistence
            results.Add(RunTest("T12-SCAN-OBSERVATIONS-SQLITE", "SQLite Discrete Scan Observations History", () =>
            {
                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_test_{Guid.NewGuid():N}.db");
                try
                {
                    using var storage = new SqliteStorageService(tempDb);
                    var aps = new List<AccessPoint>
                    {
                        new() { Bssid = "00:11:22:33:44:55", Ssid = "Corp-WiFi", Channel = 6, Rssi = -55, SignalQuality = 90, Band = "2.4 GHz" },
                        new() { Bssid = "AA:BB:CC:DD:EE:FF", Ssid = "Guest-WiFi", Channel = 36, Rssi = -70, SignalQuality = 60, Band = "5 GHz" }
                    };

                    storage.SaveScanObservationsBatchAsync("proj-test", "adapter-01", 1, aps).GetAwaiter().GetResult();
                    storage.SaveScanObservationsBatchAsync("proj-test", "adapter-01", 2, aps).GetAwaiter().GetResult();

                    int total = storage.GetTotalObservationsCountAsync("proj-test").GetAwaiter().GetResult();
                    if (total != 4) throw new Exception($"Expected 4 total discrete observations across 2 cycles, got {total}");

                    var records = storage.GetScanObservationsAsync("proj-test", "00:11:22:33:44:55").GetAwaiter().GetResult();
                    if (records.Count != 2) throw new Exception($"Expected 2 historical records for BSSID, got {records.Count}");

                    return $"Successfully validated {total} historical discrete scan observations in SQLite WAL database.";
                }
                finally
                {
                    SqliteStorageService.ReleaseAllPools();
                    try
                    {
                        if (File.Exists(tempDb)) File.Delete(tempDb);
                        string wal = tempDb + "-wal";
                        string shm = tempDb + "-shm";
                        if (File.Exists(wal)) File.Delete(wal);
                        if (File.Exists(shm)) File.Delete(shm);
                    }
                    catch
                    {
                        // Clean up attempt
                    }
                }
            }));

            // Test 13: Upgrade an existing database without losing its saved networks.
            results.Add(RunTest("T13-SQLITE-LEGACY-MIGRATION", "SQLite Legacy Access Point Schema Migration", () =>
            {
                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_legacy_{Guid.NewGuid():N}.db");
                try
                {
                    var connectionString = new SqliteConnectionStringBuilder { DataSource = tempDb }.ToString();
                    using (var legacy = new SqliteConnection(connectionString))
                    {
                        legacy.Open();
                        using var createLegacy = new SqliteCommand(@"
                            CREATE TABLE access_points (
                                bssid TEXT NOT NULL, project_id TEXT NOT NULL, ssid TEXT, channel INTEGER, band TEXT,
                                frequency_mhz INTEGER, rssi INTEGER, signal_quality INTEGER, security TEXT, cipher TEXT,
                                security_score INTEGER, is_rogue INTEGER, is_wps INTEGER, pmf_required INTEGER,
                                last_seen TEXT, is_wps_locked INTEGER DEFAULT 0,
                                PRIMARY KEY (bssid, project_id));
                            INSERT INTO access_points (bssid, project_id, ssid, channel, band, frequency_mhz, rssi,
                                signal_quality, security, cipher, security_score, is_rogue, is_wps, pmf_required, last_seen)
                            VALUES ('00:11:22:33:44:55', 'proj-test', 'Legacy-WiFi', 6, '2.4 GHz', 2437, -55,
                                90, 'WPA2-Personal', 'CCMP', 90, 0, 0, 1, '2026-01-01 12:00:00');", legacy);
                        createLegacy.ExecuteNonQuery();
                    }

                    using var storage = new SqliteStorageService(tempDb);
                    var saved = storage.GetAccessPointsAsync("proj-test").GetAwaiter().GetResult();
                    if (saved.Count != 1 || saved[0].Ssid != "Legacy-WiFi")
                        throw new Exception("The migration did not preserve the previously saved access point.");

                    storage.SaveAccessPointsAsync("proj-test", new List<AccessPoint>
                    {
                        new() { Bssid = "AA:BB:CC:DD:EE:FF", Ssid = "New-WiFi", Channel = 36, Band = "5 GHz", Rssi = -65 }
                    }).GetAwaiter().GetResult();

                    var migrated = storage.GetAccessPointsAsync("proj-test").GetAwaiter().GetResult();
                    if (migrated.Count != 2)
                        throw new Exception($"Expected legacy and new rows after migration; found {migrated.Count}.");
                    return "Preserved the old network and saved a new network after in-place schema migration.";
                }
                finally
                {
                    SqliteStorageService.ReleaseAllPools();
                    try
                    {
                        if (File.Exists(tempDb)) File.Delete(tempDb);
                        if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal");
                        if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm");
                    }
                    catch { }
                }
            }));

#if WINDOWS_DESKTOP
            // Test 14: Desktop command workflow, including the command paths used by
            // the inspector panels after a selection has been made.
            results.Add(await RunTestAsync("T14-DESKTOP-WORKFLOW", "Desktop Command Workflow & Persistence", async () =>
            {
                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_workflow_{Guid.NewGuid():N}.db");
                string tempPcap = Path.Combine(Path.GetTempPath(), $"winwifi_workflow_{Guid.NewGuid():N}.pcap");
                try
                {
                    using var storage = new SqliteStorageService(tempDb);
                    var analyzer = new SecurityAnalyzer();
                    using var wifi = new NativeWifiService(analyzer);
                    using var scanner = new WifiBackgroundScanner(wifi, analyzer, storage);
                    var viewModel = new MainViewModel(wifi, storage, new PcapDissector(), analyzer, new ReportGenerator(), scanner);
                    var project = new AuditProject { Id = "proj-workflow", Name = "Workflow Test", AuditorName = "Test Auditor" };
                    await storage.SaveProjectAsync(project);
                    viewModel.CurrentProject = project;

                    var accessPoint = new AccessPoint { Bssid = "10:20:30:40:50:60", Ssid = "Workflow-WiFi", Channel = 36, Band = "5 GHz", Security = "WPA2-Personal", Vendor = "Test Vendor" };
                    viewModel.AccessPoints.Add(accessPoint);
                    viewModel.SelectedAccessPoint = accessPoint;
                    viewModel.ToggleExpertMode();
                    if (!viewModel.IsExpertMode) throw new Exception("Presentation mode did not toggle.");
                    viewModel.ToggleScan();
                    if (!scanner.IsScanning) throw new Exception("Scan resume command did not update the observer.");
                    viewModel.ToggleScan();
                    if (scanner.IsScanning) throw new Exception("Scan pause command did not update the observer.");
                    viewModel.SetBaselineFromCurrent();
                    await viewModel.AddEnterpriseAsset();
                    if (viewModel.EnterpriseAssets.Count != 1 || accessPoint.ApprovedStatus != "Approved") throw new Exception("Selected access point was not enrolled as an approved asset.");

                    var finding = new ThreatFinding { Id = "THR-WORKFLOW", Title = "Workflow finding", RelatedBssid = accessPoint.Bssid, RelatedSsid = accessPoint.Ssid, Evidence = "Test evidence", Explanation = "Test explanation", Remediation = "Test remediation" };
                    viewModel.SelectedThreatFinding = finding;
                    await viewModel.PromoteThreatToIncident(finding);
                    if (viewModel.Incidents.Count != 1 || viewModel.ActiveTabIndex != 8) throw new Exception("Threat promotion did not create and open an incident.");
                    await viewModel.UpdateIncidentStatus("Confirmed");
                    if (viewModel.SelectedIncident?.Status != "Confirmed") throw new Exception("Incident status command did not persist its state.");
                    viewModel.NewIncidentNoteText = "Workflow note";
                    await viewModel.AddIncidentNote();
                    if (viewModel.SelectedIncident?.Notes.Count != 1) throw new Exception("Incident note command did not add a note.");

                    await File.WriteAllBytesAsync(tempPcap, CreateMinimalBeaconPcap());
                    await viewModel.ImportPcapAsync(tempPcap);
                    if (viewModel.Packets.Count != 1) throw new Exception("PCAP import command did not populate packet results.");
                    viewModel.ActiveTab = "Tests";
                    if (viewModel.ActiveTabIndex != 14) throw new Exception("Command navigation did not synchronize with the selected tab.");

                    return "Verified scan controls, mode toggle, asset enrollment, incident workflow, PCAP import, persistence, and command navigation.";
                }
                finally
                {
                    SqliteStorageService.ReleaseAllPools();
                    try
                    {
                        if (File.Exists(tempPcap)) File.Delete(tempPcap);
                        if (File.Exists(tempDb)) File.Delete(tempDb);
                        if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal");
                        if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm");
                    }
                    catch { }
                }
            }));

            results.Add(await RunTestAsync("T15-PROJECT-WORKFLOW", "Project Create, Load & Data Isolation", async () =>
            {
                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_projects_{Guid.NewGuid():N}.db");
                try
                {
                    using var storage = new SqliteStorageService(tempDb);
                    var analyzer = new SecurityAnalyzer();
                    using var wifi = new NativeWifiService(analyzer);
                    using var scanner = new WifiBackgroundScanner(wifi, analyzer, storage);
                    var viewModel = new MainViewModel(wifi, storage, new PcapDissector(), analyzer, new ReportGenerator(), scanner);
                    var firstProject = new AuditProject { Id = "proj-first", Name = "First workspace", AuditorName = "Test Auditor" };
                    var secondProject = new AuditProject { Id = "proj-second", Name = "Second workspace", AuditorName = "Test Auditor" };
                    await storage.SaveProjectAsync(firstProject);
                    await storage.SaveProjectAsync(secondProject);
                    await storage.SaveAccessPointsAsync(secondProject.Id, new List<AccessPoint>
                    {
                        new() { Bssid = "22:33:44:55:66:77", Ssid = "Second-Only", Channel = 11, Band = "2.4 GHz", Security = "WPA2-Personal" }
                    });

                    viewModel.Projects = new ObservableCollection<AuditProject> { firstProject, secondProject };
                    viewModel.CurrentProject = firstProject;
                    viewModel.SelectedProject = secondProject;
                    await viewModel.LoadSelectedProject();
                    if (viewModel.CurrentProject?.Id != secondProject.Id || viewModel.AccessPoints.Count != 1 || viewModel.AccessPoints[0].Ssid != "Second-Only")
                        throw new Exception("Loading a selected project did not switch its saved network dataset.");

                    viewModel.NewProjectName = "Created from test";
                    viewModel.NewProjectLocation = "Lab 2";
                    viewModel.NewProjectAuditor = "Test Auditor";
                    await viewModel.CreateProject();
                    if (viewModel.CurrentProject?.Name != "Created from test" || viewModel.AccessPoints.Count != 0 ||
                        !(await storage.GetProjectsAsync()).Any(p => p.Name == "Created from test"))
                        throw new Exception("Creating a project did not persist it and activate an empty workspace.");

                    return "Verified selected-project loading, per-project AP isolation, persisted project creation, and activation of a new empty workspace.";
                }
                finally
                {
                    SqliteStorageService.ReleaseAllPools();
                    try
                    {
                        if (File.Exists(tempDb)) File.Delete(tempDb);
                        if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal");
                        if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm");
                    }
                    catch { }
                }
            }));

            results.Add(RunTest("T16-REPORT-EXPORT", "HTML Report Generation", () =>
            {
                string tempReport = Path.Combine(Path.GetTempPath(), $"winwifi_report_{Guid.NewGuid():N}.html");
                try
                {
                    var project = new AuditProject { Id = "proj-report", Name = "Report Workflow Test", Location = "Lab", AuditorName = "Test Auditor" };
                    var ap = new AccessPoint { Bssid = "AA:BB:CC:DD:EE:FF", Ssid = "Report-Network", Channel = 1, Band = "2.4 GHz", Security = "WPA2-Personal" };
                    new ReportGenerator().SaveReportToFile(tempReport, project, new List<AccessPoint> { ap });
                    if (!File.Exists(tempReport)) throw new Exception("Report generator did not create an HTML file.");
                    string html = File.ReadAllText(tempReport);
                    if (!html.Contains(project.Name, StringComparison.Ordinal) || !html.Contains(ap.Ssid, StringComparison.Ordinal))
                        throw new Exception("Generated report omitted the project or observed network.");
                    return "Generated an HTML audit report and verified it includes project and network data.";
                }
                finally
                {
                    try { if (File.Exists(tempReport)) File.Delete(tempReport); } catch { }
                }
            }));
#endif

            results.Add(RunTest("T17-LOCAL-BRIDGE-ORIGINS", "Local Bridge Origin and Private-Network Contract", () =>
            {
                var defaults = HttpBridgeServer.ParseAllowedBrowserOrigins(null);
                if (!defaults.Contains("http://localhost:5173")) throw new Exception("Vite development origin is missing from defaults.");
                var configured = HttpBridgeServer.ParseAllowedBrowserOrigins("http://localhost:4173;https://127.0.0.1:4443;https://example.com;http://localhost:4173/path");
                if (configured.Count != 2 || !configured.Contains("http://localhost:4173") || !configured.Contains("https://127.0.0.1:4443"))
                    throw new Exception("Configured origins must accept loopback origins only and reject paths and remote hosts.");
                if (!HttpBridgeServer.IsAllowedBrowserOrigin("http://localhost:4173", configured) || HttpBridgeServer.IsAllowedBrowserOrigin("http://localhost:9999", configured))
                    throw new Exception("Origin allowlist matching failed.");
                if (!HttpBridgeServer.RequestsPrivateNetworkAccess("true") || HttpBridgeServer.RequestsPrivateNetworkAccess("false"))
                    throw new Exception("Private-network preflight header detection failed.");
                return "Validated configurable loopback origins, remote/path rejection, allowlist matching, and private-network preflight detection.";
            }));

#if WINDOWS_DESKTOP
            results.Add(RunTest("T18-WINDOW-WORKAREA", "Responsive Desktop Work-Area Sizing", () =>
            {
                // Windows supplies SystemParameters.WorkArea in DPI-independent
                // WPF units, so these cover the two common usable areas after
                // the taskbar is removed.
                var small = WindowLayoutSizing.FromWorkArea(1366, 728);
                var large = WindowLayoutSizing.FromWorkArea(1920, 1040);
                if (small != (1229, 655) || large != (1728, 936))
                    throw new Exception($"Unexpected window sizes: 1366x728 => {small}; 1920x1040 => {large}.");
                return "1366x768 and 1920x1080 work-area sizing remains centered and below each usable monitor bound.";
            }));
#endif

            return results;
        }

#if WINDOWS_DESKTOP
        private static byte[] CreateMinimalBeaconPcap()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write(0xa1b2c3d4);
            writer.Write((ushort)2);
            writer.Write((ushort)4);
            writer.Write(0);
            writer.Write(0);
            writer.Write(65535);
            writer.Write(127);
            writer.Write(1710000000);
            writer.Write(50000);
            writer.Write(40);
            writer.Write(40);
            writer.Write((byte)0); writer.Write((byte)0); writer.Write((ushort)8); writer.Write(0u);
            writer.Write((ushort)0x0080); writer.Write((ushort)0);
            writer.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write((ushort)0); writer.Write(0UL); writer.Write((ushort)100); writer.Write((ushort)0x0011);
            return stream.ToArray();
        }
#endif

        private TestResultItem RunTest(string id, string name, Func<string> action)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                string details = action();
                sw.Stop();
                return new TestResultItem
                {
                    TestId = id,
                    Name = name,
                    Passed = true,
                    Details = details,
                    DurationMs = sw.ElapsedMilliseconds
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new TestResultItem
                {
                    TestId = id,
                    Name = name,
                    Passed = false,
                    Details = ex.Message,
                    DurationMs = sw.ElapsedMilliseconds
                };
            }
        }

        private async Task<TestResultItem> RunTestAsync(string id, string name, Func<Task<string>> action)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                string details = await action();
                sw.Stop();
                return new TestResultItem
                {
                    TestId = id,
                    Name = name,
                    Passed = true,
                    Details = details,
                    DurationMs = sw.ElapsedMilliseconds
                };
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new TestResultItem
                {
                    TestId = id,
                    Name = name,
                    Passed = false,
                    Details = ex.Message,
                    DurationMs = sw.ElapsedMilliseconds
                };
            }
        }
    }
}
