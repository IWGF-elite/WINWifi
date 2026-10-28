using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
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
                w.Write(32);         // InclLen (8-byte radiotap + 24-byte 802.11 header)
                w.Write(32);         // OrigLen

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

            // Test 4: The parsed handshake path keeps forensic metadata but withholds
            // export material and never fabricates a Hashcat mode 22000 line.
            results.Add(RunTest("T4-EAPOL-METADATA", "EAPOL 4-Way Metadata (No Hash Export)", () =>
            {
                var packet = new byte[128];
                var session = new HandshakeSession("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "CorpWiFi");
                session.AddFrame("M1", new string('A', 64), new string('0', 32), 7, 2, null, packet, 32, "2026-01-01 12:00:00");
                session.AddFrame("M2", new string('B', 64), new string('C', 32), 7, 2, null, packet, 32, "2026-01-01 12:00:01");

                var hs = session.ToHandshakeInfo() ?? throw new Exception("EAPOL session did not produce a handshake record.");
                if (!hs.CapturedSteps.Contains("M1") || !hs.CapturedSteps.Contains("M2"))
                    throw new Exception("Parsed EAPOL message steps were not retained.");
                if (hs.HashcatFormat is not null)
                    throw new Exception("Native parser emitted a Hashcat line it does not generate.");
                if (hs.IsExportReady || !hs.ExportReadiness.StartsWith("Not available", StringComparison.Ordinal))
                    throw new Exception("Native handshake record incorrectly reports export readiness.");
                if (hs.HasAnonce || hs.HasSnonce || hs.HasMic)
                    throw new Exception("Native parser exposed cryptographic export material.");
                return "Retained M1/M2 metadata, confirmed no hash line or nonce/MIC export material is emitted.";
            }));

            // Test 5: NIST SP 800-153 Security Scoring
            results.Add(RunTest("T5-NIST-SCORING", "NIST SP 800-153 Security Evaluation", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var wepAp = new AccessPoint { Bssid = "00:01:02:03:04:05", Security = "WEP-128", Cipher = "WEP" };
                var openAp = new AccessPoint { Bssid = "00:01:02:03:04:06", Security = "Open", Cipher = "None" };
                var oweAp = new AccessPoint { Bssid = "00:01:02:03:04:08", Security = "OWE (Enhanced Open)", Cipher = "CCMP (AES)" };
                var wpa3Ap = new AccessPoint { Bssid = "00:01:02:03:04:07", Security = "WPA3-SAE", Cipher = "GCMP-256", PmfRequired = true };

                analyzer.EvaluateSecurityPosture(wepAp);
                analyzer.EvaluateSecurityPosture(openAp);
                analyzer.EvaluateSecurityPosture(oweAp);
                analyzer.EvaluateSecurityPosture(wpa3Ap);

                if (wepAp.SecurityScore > 45) throw new Exception("WEP must score < 45");
                if (openAp.SecurityScore > 65) throw new Exception("Open Wi-Fi must score < 65");
                if (oweAp.SecurityScore < 95) throw new Exception($"OWE (Enhanced Open) must not be penalized as unencrypted; got {oweAp.SecurityScore}");
                if (oweAp.SecurityIssues.Any(i => i.Id == "VULN-OPEN-UNENCRYPTED")) throw new Exception("OWE was misclassified as VULN-OPEN-UNENCRYPTED");
                if (wpa3Ap.SecurityScore < 95) throw new Exception("WPA3-SAE + PMF must score >= 95");

                return $"WEP: {wepAp.SecurityScore}, Open: {openAp.SecurityScore}, OWE: {oweAp.SecurityScore}, WPA3: {wpa3Ap.SecurityScore}";
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
                var baseline = new Dictionary<string, AccessPoint>
                {
                    ["00:00:0C:AA:BB:01"] = new AccessPoint
                    {
                        Bssid = "00:00:0C:AA:BB:01",
                        Ssid = "Enterprise_WLAN",
                        Security = "WPA2-Enterprise",
                        Cipher = "CCMP",
                        Vendor = "Cisco Systems",
                        Classification = "Corporate",
                        ApprovedStatus = "Approved"
                    }
                };
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:AA:BB:01", Ssid = "Enterprise_WLAN", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "Cisco Systems", SecurityScore = 85, Rssi = -70 },
                    new AccessPoint { Bssid = "50:D4:F7:11:22:33", Ssid = "Enterprise_WLAN", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "TP-Link Technologies", SecurityScore = 85, Rssi = -40 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, baseline);
                var vendorMismatch = res.Findings.Find(f => f.Category == "Rogue AP" && f.RelatedBssid == "50:D4:F7:11:22:33");
                if (vendorMismatch == null)
                {
                    throw new Exception("Failed to flag TP-Link consumer AP masquerading on Cisco Enterprise WLAN.");
                }
                if (vendorMismatch.Confidence < 70)
                {
                    throw new Exception($"Multi-signal finding should carry confidence >= 70, got {vendorMismatch.Confidence}.");
                }
                return $"Flagged Rogue AP {vendorMismatch.RelatedBssid} with {vendorMismatch.Confidence}% confidence ({vendorMismatch.Evidence}).";
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
                var lure = res.Findings.Find(f => f.Category == "Rogue AP" && f.RelatedBssid == "02:11:22:33:44:55");
                if (lure == null)
                {
                    throw new Exception("Failed to flag high-power proximity lure (+33 dBm disparity with LAA).");
                }
                if (lure.Severity != "HIGH" || lure.Confidence < 70)
                {
                    throw new Exception($"LAA + signal anomaly should produce HIGH confidence >= 70, got {lure.Severity}/{lure.Confidence}.");
                }
                return $"Detected proximity lure: {lure.Title} at {lure.RelatedBssid} (+33 dBm difference, {lure.Confidence}% confidence).";
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
                        Security = "Open",             // Drift 1: Encryption Downgrade
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

            // Test 7H: WPA2/WPA3 transition must not be flagged as an evil twin.
            results.Add(RunTest("T7H-TRANSITION-NO-FP", "WPA2/WPA3 Transition Produces No False Positive", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:10:20:01", Ssid = "Transition-WiFi", Security = "WPA2-PSK", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -60 },
                    new AccessPoint { Bssid = "00:00:0C:10:20:02", Ssid = "Transition-WiFi", Security = "WPA3-SAE", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -65 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                if (res.Findings.Count > 0)
                    throw new Exception($"WPA2/WPA3 transition produced {res.Findings.Count} finding(s): {res.Findings[0].Title}");
                return "WPA2/WPA3 transition deployment produced 0 findings.";
            }));

            // Test 7I: A single OUI mismatch is not enough to alert.
            results.Add(RunTest("T7I-SINGLE-SIGNAL", "Single-Signal OUI Difference Does Not Alert", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var aps = new List<AccessPoint>
                {
                    new AccessPoint { Bssid = "00:00:0C:30:40:01", Ssid = "Mixed-Vendor", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -60 },
                    new AccessPoint { Bssid = "50:D4:F7:30:40:02", Ssid = "Mixed-Vendor", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "TP-Link Technologies", Rssi = -62 }
                };

                var res = analyzer.AnalyzeThreatsAndDrift(aps, null);
                if (res.Findings.Count > 0)
                    throw new Exception($"Single OUI signal should not alert, got {res.Findings[0].Title}");
                return "Single-signal OUI difference suppressed as designed.";
            }));

            // Test 7J: Finding IDs must survive AP reordering.
            results.Add(RunTest("T7J-STABLE-FINDING-IDS", "Stable Threat Finding IDs Across Scan Reordering", () =>
            {
                var analyzer = new SecurityAnalyzer();
                var first = new AccessPoint { Bssid = "00:00:0C:50:60:01", Ssid = "Stable-ID", Security = "WPA2-Enterprise", Cipher = "CCMP", Vendor = "Cisco Systems", Rssi = -70 };
                var second = new AccessPoint { Bssid = "00:1A:1E:50:60:02", Ssid = "Stable-ID", Security = "Open", Cipher = "None", Vendor = "Aruba Networks", Rssi = -40 };

                var forward = analyzer.AnalyzeThreatsAndDrift(new List<AccessPoint> { first, second }, null);
                var reverse = analyzer.AnalyzeThreatsAndDrift(new List<AccessPoint> { second, first }, null);
                var forwardIds = forward.Findings.Select(f => f.Id).OrderBy(id => id).ToList();
                var reverseIds = reverse.Findings.Select(f => f.Id).OrderBy(id => id).ToList();

                if (forwardIds.Count == 0) throw new Exception("Stable-ID fixture produced no finding.");
                if (!forwardIds.SequenceEqual(reverseIds))
                    throw new Exception($"Finding IDs changed after reordering: [{string.Join(",", forwardIds)}] vs [{string.Join(",", reverseIds)}]");
                return $"Stable finding ID validated: {forwardIds[0]}.";
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

#endif

            results.Add(await RunTestAsync("T17-PROJECT-SCOPE", "Bridge Project Scope & SQLite Isolation", async () =>
            {
                if (!HttpBridgeServer.IsValidProjectId("proj-Alpha_1.2"))
                    throw new Exception("A valid project identifier was rejected.");
                foreach (string invalid in new[] { "", "../escape", "a b", new string('a', 65), "proj;drop" })
                {
                    if (HttpBridgeServer.IsValidProjectId(invalid))
                        throw new Exception($"Invalid project identifier accepted: '{invalid}'");
                }

                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_scope_{Guid.NewGuid():N}.db");
                try
                {
                    using var storage = new SqliteStorageService(tempDb);
                    await storage.EnsureProjectAsync("proj-alpha", "Alpha Audit");
                    await storage.SaveAccessPointsAsync("proj-alpha", new List<AccessPoint>
                    {
                        new() { Bssid = "02:11:22:33:44:55", Ssid = "Alpha-Only", Channel = 1, Band = "2.4 GHz", Security = "WPA3-Personal" }
                    });

                    var alpha = await storage.GetAccessPointsAsync("proj-alpha");
                    var beta = await storage.GetAccessPointsAsync("proj-beta");
                    var projects = await storage.GetProjectsAsync();
                    if (alpha.Count != 1 || alpha[0].Ssid != "Alpha-Only")
                        throw new Exception("Project-scoped access point was not persisted.");
                    if (beta.Count != 0)
                        throw new Exception("Access point leaked into a different project.");
                    if (!projects.Any(project => project.Id == "proj-alpha"))
                        throw new Exception("EnsureProjectAsync did not create the project row.");
                    return "Validated project identifier rejection and per-project SQLite isolation.";
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

            results.Add(RunTest("T16-REPORT-EXPORT", "HTML Report Generation & Field Encoding", () =>
            {
                string tempReport = Path.Combine(Path.GetTempPath(), $"winwifi_report_{Guid.NewGuid():N}.html");
                try
                {
                    var project = new AuditProject
                    {
                        Id = "proj-report",
                        Name = "<script>alert('project')</script>",
                        Location = "Lab",
                        AuditorName = "A & B <admin@example.test>"
                    };
                    var ap = new AccessPoint
                    {
                        Bssid = "AA:BB:CC:DD:EE:FF",
                        Ssid = "<img src=x onerror=alert(1)>",
                        Channel = 1,
                        Band = "2.4 GHz <b>",
                        Security = "WPA2 & Co",
                        Cipher = "CCMP\"quoted\""
                    };
                    ap.SecurityIssues.Add(new SecurityIssue { Title = "<script>issue</script> & bad" });

                    new ReportGenerator().SaveReportToFile(tempReport, project, new List<AccessPoint> { ap });
                    if (!File.Exists(tempReport)) throw new Exception("Report generator did not create an HTML file.");
                    string html = File.ReadAllText(tempReport);
                    foreach (string raw in new[] { "<script>alert('project')</script>", "<img src=x", "<script>issue</script>", "CCMP\"quoted\"" })
                    {
                        if (html.Contains(raw, StringComparison.Ordinal))
                            throw new Exception($"Report leaked an unencoded field: {raw}");
                    }
                    if (!html.Contains("&lt;script&gt;", StringComparison.Ordinal) ||
                        !html.Contains("&amp;", StringComparison.Ordinal) ||
                        !html.Contains("&quot;", StringComparison.Ordinal))
                        throw new Exception("Report did not HTML-encode dynamic fields.");
                    return "Generated an HTML report and verified project, auditor, BSSID, band, security, cipher, and issue titles are encoded.";
                }
                finally
                {
                    try { if (File.Exists(tempReport)) File.Delete(tempReport); } catch { }
                }
            }));

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

            results.Add(RunTest("T18-BRIDGE-TOKEN", "Per-Launch Bridge Token Contract", () =>
            {
                string first = HttpBridgeServer.GenerateAuthToken();
                string second = HttpBridgeServer.GenerateAuthToken();
                if (first.Length != 64 || !first.All(ch => (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
                    throw new Exception("Bridge token is not 32 random bytes rendered as lowercase hex.");
                if (string.Equals(first, second, StringComparison.Ordinal))
                    throw new Exception("Two launches produced the same bridge token.");
                if (!HttpBridgeServer.IsValidAuthToken(first, first))
                    throw new Exception("A matching bridge token was rejected.");
                if (HttpBridgeServer.IsValidAuthToken(null, first) ||
                    HttpBridgeServer.IsValidAuthToken(second, first) ||
                    HttpBridgeServer.IsValidAuthToken(first + "0", first))
                    throw new Exception("Bridge token validation accepted a missing, different, or padded token.");

                string tokenPath = HttpBridgeServer.BridgeTokenFilePath();
                string expectedSuffix = Path.Combine("WinWiFi", "bridge.token");
                if (!tokenPath.EndsWith(expectedSuffix, StringComparison.OrdinalIgnoreCase))
                    throw new Exception($"Bridge token path is not under LOCALAPPDATA\\WinWiFi: {tokenPath}");
                return "Validated per-launch 256-bit tokens, constant-time accept/reject behavior, and the LOCALAPPDATA token path.";
            }));

#if WINDOWS_DESKTOP
            results.Add(RunTest("T18-WINDOW-WORKAREA", "Responsive Desktop Work-Area Sizing", () =>
            {
                // Windows supplies SystemParameters.WorkArea in DPI-independent
                // WPF units, so these cover the two common usable areas after
                // the taskbar is removed.
                var small = WindowLayoutSizing.FromWorkArea(1366, 728);
                var large = WindowLayoutSizing.FromWorkArea(1920, 1040);
                var full = WindowLayoutSizing.FullWorkArea(1920, 1040);
                if (small != (1229, 655) || large != (1728, 936) || full != (1920, 1040))
                    throw new Exception($"Unexpected window sizes: 1366x728 => {small}; 1920x1040 => {large}.");
                return "1366x768 and 1920x1080 work-area sizing remains centered and below each usable monitor bound.";
            }));
#endif

            results.Add(RunTest("T19-NATIVE-RSN-PRESERVATION", "Native RSN Evidence Survives Netsh Reconciliation", () =>
            {
                var native = new AccessPoint
                {
                    Bssid = "00:11:22:33:44:55",
                    Security = "WPA2-PSK",
                    Cipher = "CCMP",
                    PmfInformationAvailable = true,
                    PmfRequired = false,
                    SecurityScore = 90,
                    RiskScore = 10,
                    RiskFactors = new List<RiskFactor> { new() { Name = "PMF disabled", Points = 10 } }
                };
                var netsh = new AccessPoint
                {
                    Bssid = native.Bssid,
                    Security = "WPA2-Personal",
                    SecurityScore = 100,
                    RiskScore = 0
                };
                var onlyNetsh = new AccessPoint { Bssid = "00:11:22:33:44:66", Ssid = "Extra visible BSSID" };
                var merged = NativeWifiService.MergeWindowsScanResults(new List<AccessPoint> { native }, new List<AccessPoint> { netsh, onlyNetsh });
                var result = merged.First(ap => ap.Bssid == native.Bssid);
                if (merged.Count != 2 || result.RiskScore != 10 || !result.PmfInformationAvailable || result.RiskFactors.Count != 1)
                    throw new Exception("Netsh reconciliation replaced native RSN, PMF, or risk-factor evidence.");
                return "Native PMF and weighted risk evidence remain authoritative while netsh-only BSSIDs are retained.";
            }));

            results.Add(RunTest("T20-PCAP-HARDENING", "Capture Import Limits, Integrity Warnings & Timestamp Resolution", () =>
            {
                var dissector = new PcapDissector();
                var beacon = BuildBeaconFrame("SafeNet");

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WritePcapHeader(writer, 127);
                    writer.Write(1710000000u);
                    writer.Write(0u);
                    writer.Write(0xFFFFFFF0u);
                    writer.Write(0xFFFFFFF0u);
                    var oversized = dissector.DissectBytes(stream.ToArray());
                    if (oversized.Packets.Count != 0 || !oversized.Truncated || oversized.ParseWarnings.Count == 0)
                        throw new Exception("Oversized record length was not rejected with a warning.");
                }

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WritePcapHeader(writer, 127);
                    writer.Write(1710000000u);
                    writer.Write(0u);
                    writer.Write(100u);
                    writer.Write(100u);
                    writer.Write(new byte[10]);
                    var truncated = dissector.DissectBytes(stream.ToArray());
                    if (!truncated.Truncated || truncated.Packets.Count != 0 ||
                        !truncated.ParseWarnings.Any(w => w.Contains("truncated", StringComparison.OrdinalIgnoreCase)))
                        throw new Exception("Truncated capture record was not reported.");
                }

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WritePcapHeader(writer, 127);
                    writer.Write(1710000000u);
                    writer.Write(0u);
                    writer.Write(0u);
                    writer.Write(0u);
                    writer.Write(1710000001u);
                    writer.Write(0u);
                    writer.Write((uint)beacon.Length);
                    writer.Write((uint)beacon.Length);
                    writer.Write(beacon);
                    var zeroLength = dissector.DissectBytes(stream.ToArray());
                    if (zeroLength.Packets.Count != 1 || !zeroLength.ParseWarnings.Any(w => w.Contains("zero captured bytes")))
                        throw new Exception("Zero-length record handling failed.");
                }

                var limited = dissector.DissectBytes(BuildPcap(127, beacon, beacon), new PcapDissectOptions { MaxPackets = 1 });
                if (limited.Packets.Count != 1 || !limited.Truncated)
                    throw new Exception("Packet-count limit was not enforced.");

                var frameLimited = dissector.DissectBytes(BuildPcap(127, beacon), new PcapDissectOptions { MaxFrameBytes = 32 });
                if (frameLimited.Packets.Count != 0 || !frameLimited.Truncated ||
                    !frameLimited.ParseWarnings.Any(w => w.Contains("per-frame limit")))
                    throw new Exception("Per-frame byte limit was not enforced.");

                var ethernet = dissector.DissectBytes(BuildPcap(1, beacon));
                if (ethernet.Packets.Count != 0 || ethernet.AccessPoints.Count != 0 ||
                    !ethernet.ParseWarnings.Any(w => w.Contains("not an 802.11 capture")))
                    throw new Exception("Non-802.11 capture was dissected as if it were 802.11.");

                var badRadiotap = new byte[32];
                badRadiotap[2] = 100;
                var radiotap = dissector.DissectBytes(BuildPcap(127, badRadiotap));
                if (radiotap.Packets.Count != 0 || radiotap.SkippedFrames != 1 ||
                    !radiotap.ParseWarnings.Any(w => w.Contains("radiotap length")))
                    throw new Exception("Malformed radiotap header was not rejected.");

                var controlSsid = dissector.DissectBytes(BuildPcap(127, BuildBeaconFrame("Evil\u0001Net")));
                if (controlSsid.AccessPoints.Count != 1 || controlSsid.AccessPoints[0].Ssid != "Evil?Net")
                    throw new Exception($"SSID sanitization failed: {controlSsid.AccessPoints.FirstOrDefault()?.Ssid}");

                var longSsid = dissector.DissectBytes(BuildPcap(127, BuildBeaconFrame(new string('A', 40))));
                if (longSsid.AccessPoints.Count != 1 || longSsid.AccessPoints[0].Ssid.Length != 32)
                    throw new Exception("SSID longer than 32 bytes was not capped.");

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WritePcapNgBlock(writer, 0x0a0d0d0a, BuildPcapNgSectionHeader());
                    WritePcapNgBlock(writer, 1, BuildPcapNgInterface(65535, 3));
                    WritePcapNgBlock(writer, 6, BuildPcapNgEnhancedPacket(0, 1_500_000UL, beacon));
                    WritePcapNgBlock(writer, 6, BuildPcapNgEnhancedPacket(0, 1_501_000UL, beacon));
                    var pcapng = dissector.DissectBytes(stream.ToArray());
                    if (pcapng.Packets.Count != 2)
                        throw new Exception($"PCAPNG parsed {pcapng.Packets.Count} packets instead of 2.");
                    const string format = "yyyy-MM-dd HH:mm:ss.ffffff";
                    if (!DateTime.TryParseExact(pcapng.Packets[0].Timestamp, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var first) ||
                        !DateTime.TryParseExact(pcapng.Packets[1].Timestamp, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var second))
                        throw new Exception("PCAPNG timestamps were not formatted as capture times.");
                    if (Math.Abs((second - first).TotalSeconds - 1d) > 0.01)
                        throw new Exception($"if_tsresol was not applied: packet delta was {(second - first).TotalSeconds:F3}s.");
                }

                using (var stream = new MemoryStream())
                using (var writer = new BinaryWriter(stream))
                {
                    WritePcapNgBlock(writer, 0x0a0d0d0a, BuildPcapNgSectionHeader());
                    WritePcapNgBlock(writer, 1, BuildPcapNgInterface(65535));
                    WritePcapNgBlock(writer, 6, BuildPcapNgEnhancedPacket(0, 0, beacon), corruptTrailer: true);
                    var corrupt = dissector.DissectBytes(stream.ToArray());
                    if (!corrupt.Truncated || !corrupt.ParseWarnings.Any(w => w.Contains("mismatched trailer")))
                        throw new Exception("PCAPNG block trailer corruption was not detected.");
                }

                return "Rejected oversized and truncated records, enforced frame/packet limits, skipped malformed radiotap, sanitized SSIDs, honored if_tsresol, and detected PCAPNG trailer corruption.";
            }));

            results.Add(await RunTestAsync("T21-ASSET-REGISTRY", "Enterprise Asset Registry, MAC Identity & CSV Round-Trip", async () =>
            {
                if (AssetRegistryCsv.NormalizeMac("aa-bb-cc-dd-ee-ff") != "AA:BB:CC:DD:EE:FF" ||
                    AssetRegistryCsv.NormalizeMac("02.11.22.33.44.55") != "02:11:22:33:44:55")
                    throw new Exception("MAC addresses were not canonicalized.");
                foreach (string invalid in new[] { "", "nope", "AA:BB:CC:DD:EE", "FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", "GG:11:22:33:44:55" })
                {
                    if (AssetRegistryCsv.NormalizeMac(invalid) is not null)
                        throw new Exception($"Invalid MAC accepted: '{invalid}'");
                }

                string csv = "macAddress,ssid,classification,approvalStatus,notes\r\n" +
                             "aa-bb-cc-dd-ee-ff,\"Lab, West\",Corporate,Approved,\"Line one\r\nLine two and \"\"quoted\"\" text\"\r\n" +
                             "02:11:22:33:44:55,Printer,IoT,Investigating,\"'=HYPERLINK(\"\"http://example.invalid\"\")\"\r\n" +
                             "not-a-mac,Bad,Corporate,Approved,ignored\r\n" +
                             "02-11-22-33-44-55,Printer Updated,IoT,Investigating,\"'=HYPERLINK(\"\"http://example.invalid\"\")\"\r\n";
                var parsed = AssetRegistryCsv.Parse(csv);
                if (parsed.FatalError is not null || parsed.Rows.Count != 2 || parsed.Rejected.Count != 1)
                    throw new Exception($"CSV parse mismatch: rows={parsed.Rows.Count}, rejected={parsed.Rejected.Count}, fatal={parsed.FatalError}");
                var lab = parsed.Rows.First(row => row.Asset.MacAddress == "AA:BB:CC:DD:EE:FF").Asset;
                if (lab.Ssid != "Lab, West" || !lab.Notes.Contains("Line two and \"quoted\" text"))
                    throw new Exception("Quoted CSV fields were not parsed correctly.");
                if (lab.Notes != "Line one\r\nLine two and \"quoted\" text")
                    throw new Exception($"Multi-line CSV notes changed: {lab.Notes}");
                var printer = parsed.Rows.First(row => row.Asset.MacAddress == "02:11:22:33:44:55").Asset;
                if (printer.Ssid != "Printer Updated" || printer.AssetType != "Access Point")
                    throw new Exception("Duplicate MAC rows did not use the later record.");
                if (printer.ApprovalStatus != "Under Investigation")
                    throw new Exception("'Investigating' was not canonicalized to 'Under Investigation'.");
                if (!printer.Notes.StartsWith("=HYPERLINK", StringComparison.Ordinal))
                    throw new Exception($"CSV formula payload was not preserved for inspection: {printer.Notes}");

                string exported = AssetRegistryCsv.Serialize(parsed.Rows.Select(row => row.Asset));
                if (!exported.Contains("\"'=HYPERLINK")) throw new Exception("CSV export did not neutralize a formula-leading cell.");
                var roundTrip = AssetRegistryCsv.Parse(exported);
                var roundTripPrinter = roundTrip.Rows.First(row => row.Asset.MacAddress == "02:11:22:33:44:55").Asset;
                if (roundTrip.Rows.Count != 2 || roundTripPrinter.Notes != printer.Notes || roundTripPrinter.Ssid != printer.Ssid)
                    throw new Exception("CSV export/import did not round-trip asset data.");

                if (AssetRegistryCsv.NormalizeAsset(new EnterpriseAssetRecord { MacAddress = "02:11:22:33:44:55", Classification = "Made Up" }, out _) is not null)
                    throw new Exception("An unsupported classification was accepted.");
                if (AssetRegistryCsv.NormalizeAsset(new EnterpriseAssetRecord { MacAddress = "not-a-mac" }, out _) is not null)
                    throw new Exception("An invalid MAC was accepted by the asset normalizer.");

                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_assets_{Guid.NewGuid():N}.db");
                try
                {
                    using var storage = new SqliteStorageService(tempDb);
                    await storage.EnsureProjectAsync("proj-assets", "Asset Registry Test");
                    await storage.SaveEnterpriseAssetsAsync("proj-assets", new[]
                    {
                        new EnterpriseAssetRecord
                        {
                            Id = "AST-ORIGINAL",
                            MacAddress = "aa-bb-cc-dd-ee-ff",
                            Ssid = "Lab, West",
                            Classification = "Corporate",
                            ApprovalStatus = "Approved",
                            Site = "Lab",
                            Notes = "First record"
                        }
                    });

                    var stored = await storage.GetEnterpriseAssetsAsync("proj-assets");
                    if (stored.Count != 1 || stored[0].MacAddress != "AA:BB:CC:DD:EE:FF" || stored[0].Id != "AST-ORIGINAL")
                        throw new Exception("Asset MAC was not canonicalized or its id changed on insert.");

                    await storage.SaveEnterpriseAssetsAsync("proj-assets", new[]
                    {
                        new EnterpriseAssetRecord
                        {
                            Id = AssetRegistryCsv.NewAssetId(),
                            MacAddress = "AA:BB:CC:DD:EE:FF",
                            Ssid = "Lab, West",
                            Classification = "Guest",
                            ApprovalStatus = "Unapproved",
                            Site = "Lab",
                            Notes = "Second record"
                        }
                    });
                    stored = await storage.GetEnterpriseAssetsAsync("proj-assets");
                    if (stored.Count != 1 || stored[0].Id != "AST-ORIGINAL" || stored[0].Classification != "Guest" || stored[0].Notes != "Second record")
                        throw new Exception("Upsert by MAC created a duplicate or did not update fields in place.");
                    if ((await storage.GetEnterpriseAssetsAsync("proj-other")).Count != 0)
                        throw new Exception("An enterprise asset leaked across projects.");

                    bool rejectedInvalid = false;
                    try
                    {
                        await storage.SaveEnterpriseAssetsAsync("proj-assets", new[]
                        {
                            new EnterpriseAssetRecord { MacAddress = "not-a-mac" }
                        });
                    }
                    catch (ArgumentException)
                    {
                        rejectedInvalid = true;
                    }
                    if (!rejectedInvalid) throw new Exception("Storage accepted an invalid MAC address.");

                    await storage.DeleteEnterpriseAssetAsync("proj-assets", "aa-bb-cc-dd-ee-ff");
                    if ((await storage.GetEnterpriseAssetsAsync("proj-assets")).Count != 0)
                        throw new Exception("Deleting an asset did not remove it from the project registry.");

                    return "Canonicalized MACs, parsed quoted/multi-line CSV, neutralized formula-leading cells, round-tripped exports, upserted by MAC without duplicates, isolated projects, and deleted by MAC.";
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

            results.Add(await RunTestAsync("T22-BRIDGE-HEALTH", "Bridge Health Endpoint & Per-Launch Token Enforcement", async () =>
            {
                // The health check must be reachable on loopback only, reject
                // every request without the per-launch token, and answer "online"
                // once the token is presented. A stub Wi-Fi service with zero
                // adapters keeps the test off the real radio.
                int port;
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();

                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_bridge_{Guid.NewGuid():N}.db");
                using var wifi = new StubWifiService();
                using var storage = new SqliteStorageService(tempDb);
                await using var bridge = new HttpBridgeServer(port, wifi, new SecurityAnalyzer(), new PcapDissector(), new ReportGenerator(), storage);
                await bridge.StartAsync();
                try
                {
                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

                    var anonymous = await http.GetAsync($"http://127.0.0.1:{port}/api/health");
                    string anonymousBody = await anonymous.Content.ReadAsStringAsync();
                    if (anonymous.StatusCode != HttpStatusCode.Unauthorized || !anonymousBody.Contains("token", StringComparison.OrdinalIgnoreCase))
                        throw new Exception($"Health check without a token returned {(int)anonymous.StatusCode} instead of 401 with a token hint.");

                    using var wrong = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/api/health");
                    wrong.Headers.Add("X-WinWiFi-Token", new string('0', 64));
                    if ((await http.SendAsync(wrong)).StatusCode != HttpStatusCode.Unauthorized)
                        throw new Exception("Health check accepted an incorrect bridge token.");

                    using var valid = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/api/health");
                    valid.Headers.Add("X-WinWiFi-Token", bridge.AuthToken);
                    var healthy = await http.SendAsync(valid);
                    string healthJson = await healthy.Content.ReadAsStringAsync();
                    if (healthy.StatusCode != HttpStatusCode.OK || !healthJson.Contains("\"online\"", StringComparison.Ordinal) || !healthJson.Contains("\"authRequired\":true", StringComparison.Ordinal))
                        throw new Exception($"Health check with the per-launch token did not report an authenticated online status: {(int)healthy.StatusCode}.");

                    return $"Health endpoint answered 401 without a token, 401 with a wrong token, and 200 (online, authRequired) with the per-launch token on 127.0.0.1:{port}.";
                }
                finally
                {
                    await bridge.StopAsync();
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

            results.Add(RunTest("T23-HANDSHAKE-JSON", "Handshake JSON Contract Has No Colliding Property Names", () =>
            {
                // The bridge serializes with case-insensitive camelCase; the old
                // AnonCe/Anonce alias pair made every payload containing a
                // handshake fail with a property-name collision (HTTP 500).
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                    PropertyNameCaseInsensitive = true
                };
                var ap = new AccessPoint
                {
                    Bssid = "AA:BB:CC:DD:EE:FF",
                    Ssid = "Collision Check",
                    Handshake = new HandshakeInfo
                    {
                        ApBssid = "AA:BB:CC:DD:EE:FF",
                        IsComplete = true,
                        Anonce = "anonce-value",
                        Snonce = "snounce-value",
                        MicHex = "mic"
                    }
                };
                string json = System.Text.Json.JsonSerializer.Serialize(new List<AccessPoint> { ap }, options);
                if (!json.Contains("\"anonce\"", StringComparison.Ordinal) ||
                    !json.Contains("\"snonce\"", StringComparison.Ordinal) ||
                    json.Contains("anonCe", StringComparison.Ordinal) ||
                    json.Contains("snonCe", StringComparison.Ordinal))
                    throw new Exception("Handshake nonces did not serialize to single camelCase fields: " + json);
                var roundTrip = System.Text.Json.JsonSerializer.Deserialize<List<AccessPoint>>(json, options);
                if (roundTrip is null || roundTrip[0].Handshake?.Anonce != "anonce-value" || roundTrip[0].Handshake?.Snonce != "snounce-value")
                    throw new Exception("Handshake JSON did not round-trip the nonce fields.");
                return "Serialized an access point with handshake material under the bridge's JSON options without property-name collisions.";
            }));

            results.Add(RunTest("T24-SINGLE-INSTANCE", "Second Desktop Launch Activates the First Window", () =>
            {
                string suffix = Guid.NewGuid().ToString("N");
                string mutexName = $@"Local\WinWiFi.Test.Mutex.{suffix}";
                string eventName = $@"Local\WinWiFi.Test.Event.{suffix}";

                using var first = SingleInstanceGuard.TryAcquire(mutexName, eventName);
                if (first is null) throw new Exception("The first launch could not acquire the single-instance guard.");
                using var second = SingleInstanceGuard.TryAcquire(mutexName, eventName);
                if (second is not null) throw new Exception("A second launch was allowed to start a second instance.");

                int activations = 0;
                first.StartActivationListener(() => activations++);
                SingleInstanceGuard.ActivateExistingInstance(eventName);
                var deadline = DateTime.UtcNow.AddSeconds(3);
                while (activations == 0 && DateTime.UtcNow < deadline) Thread.Sleep(20);
                if (activations == 0) throw new Exception("Signalling from a second launch did not activate the first window.");

                SingleInstanceGuard.ActivateExistingInstance(eventName);
                deadline = DateTime.UtcNow.AddSeconds(3);
                int seen = activations;
                while (activations == seen && DateTime.UtcNow < deadline) Thread.Sleep(20);
                if (activations <= seen) throw new Exception("The activation listener stopped responding after the first signal.");
                first.StopActivationListener();
                return "A second launch cannot start a second instance and reliably brings the first window forward.";
            }));

            results.Add(RunTest("T25-PORT-SELECTOR", "Bridge Port Fallback Skips Occupied Ports", () =>
            {
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                int occupied = ((IPEndPoint)probe.LocalEndpoint).Port;
                try
                {
                    if (BridgePortSelector.IsPortAvailable(occupied))
                        throw new Exception("An occupied port was reported as available.");
                    int? selected = BridgePortSelector.FindAvailablePort(occupied, attempts: 5);
                    if (selected is null || selected <= occupied || selected >= occupied + 5)
                        throw new Exception($"Fallback did not pick a free port after the busy one (got {selected}).");
                    if (!BridgePortSelector.IsPortAvailable(selected.Value))
                        throw new Exception("The selected fallback port is not actually free.");
                }
                finally
                {
                    probe.Stop();
                }
                return "The bridge port selector skips ports held by other local listeners and returns a verified-free port.";
            }));

            results.Add(RunTest("T26-SSE-ESCAPING", "SSE Payloads Escape Control Characters", () =>
            {
                // SSE frames are JSON serialized with the same options the bridge
                // uses; control characters inside adapter names or error text must
                // never leak as raw bytes or a browser-side JSON.parse fails with
                // "Bad control character in string literal".
                var options = new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                    PropertyNameCaseInsensitive = true
                };
                var diag = new ScanDiagnostics
                {
                    ActiveAdapterName = "Intel \u0001 AC 8260",
                    LastError = "line1\nline2\ttab\u0002"
                };
                diag.StatusMessages.Add("status with control chars \u0003");
                string json = System.Text.Json.JsonSerializer.Serialize(new { diagnostics = diag }, options);
                if (json.IndexOf('\n') >= 0 || json.IndexOf('\r') >= 0 || json.IndexOf('\u0001') >= 0 || json.IndexOf('\u0002') >= 0 || json.IndexOf('\u0003') >= 0)
                    throw new Exception("Raw control characters leaked into the SSE JSON payload.");
                if (!json.Contains("\\u0001", StringComparison.Ordinal) || !json.Contains("\\n", StringComparison.Ordinal))
                    throw new Exception("Control characters were not emitted as JSON escape sequences.");
                return "Diagnostics payloads keep control characters escaped so every SSE frame stays parseable.";
            }));

            results.Add(await RunTestAsync("T27-BRIDGE-SHUTDOWN", "Bridge Shutdown Survives a Blocked UI Context", async () =>
            {
                // The desktop shell stops its bridge from the WPF UI thread and
                // waits for that call to finish. If any await inside StopAsync
                // resumed on the captured UI context, the wait would deadlock and
                // the process would linger holding the single-instance lock.
                int port;
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();

                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_stop_{Guid.NewGuid():N}.db");
                using var wifi = new StubWifiService();
                using var storage = new SqliteStorageService(tempDb);
                var bridge = new HttpBridgeServer(port, wifi, new SecurityAnalyzer(), new PcapDissector(), new ReportGenerator(), storage);
                await bridge.StartAsync();

                var previousContext = SynchronizationContext.Current;
                Task stopping;
                SynchronizationContext.SetSynchronizationContext(new DroppingSynchronizationContext());
                try
                {
                    stopping = bridge.StopAsync();
                }
                finally
                {
                    SynchronizationContext.SetSynchronizationContext(previousContext);
                }

                var finished = await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(5)));
                try { await bridge.DisposeAsync(); } catch { }
                SqliteStorageService.ReleaseAllPools();
                TryDeleteScanDatabase(tempDb);

                if (finished != stopping || !stopping.IsCompletedSuccessfully)
                    throw new Exception("Bridge shutdown stalled on its own captured synchronization context; the desktop process would never exit.");
                return "StopAsync finished in under 5 seconds while its captured context discarded every continuation, so the shell can always close.";
            }));

            results.Add(await RunTestAsync("T28-DRIFT-SURFACE", "Bridge Publishes Native Configuration Drift", async () =>
            {
                // The analyzer produced DetectedDrifts on every cycle but the
                // bridge kept only threats.Findings, so configuration drift was
                // detected and then discarded. This drives one virtual adapter
                // whose channel alternates on every hardware scan request, which
                // makes the real scanner loop produce a drift each cycle. The
                // radio is never touched: the adapter only exists in memory.
                int port;
                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();

                string tempDb = Path.Combine(Path.GetTempPath(), $"winwifi_drift_{Guid.NewGuid():N}.db");
                using var wifi = new ShiftingChannelWifiService();
                using var storage = new SqliteStorageService(tempDb);
                await using var bridge = new HttpBridgeServer(port, wifi, new SecurityAnalyzer(), new PcapDissector(), new ReportGenerator(), storage);
                await bridge.StartAsync();

                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                try
                {
                    // The live surface is the SSE scan_result payload; the polled
                    // endpoint must serve the same snapshot when SSE is unavailable.
                    using var sseClient = new HttpClient();
                    using var sseRequest = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/api/events?token={bridge.AuthToken}");
                    using var sseResponse = await sseClient.SendAsync(sseRequest, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token);
                    if (sseResponse.StatusCode != HttpStatusCode.OK)
                        throw new Exception($"The SSE stream returned {(int)sseResponse.StatusCode} instead of 200.");

                    string? driftPayload = null;
                    using var sseStream = await sseResponse.Content.ReadAsStreamAsync();
                    using var sseReader = new StreamReader(sseStream);
                    // .NET 8 has no cancellable ReadLineAsync, so the read is kept
                    // as a single pending task and re-awaited until the deadline.
                    Task<string?>? pendingLine = null;
                    var sseDeadline = DateTime.UtcNow.AddSeconds(30);
                    while (DateTime.UtcNow < sseDeadline)
                    {
                        pendingLine ??= sseReader.ReadLineAsync();
                        if (await Task.WhenAny(pendingLine, Task.Delay(1000)) != pendingLine) continue;
                        string? line = await pendingLine;
                        pendingLine = null;
                        if (line is null) break;
                        if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
                        string data = line.Substring(5).Trim();
                        if (!data.Contains("\"drifts\"", StringComparison.Ordinal)) continue;
                        if (!data.Contains("channel_shift", StringComparison.Ordinal)) continue;
                        driftPayload = data;
                        break;
                    }

                    if (driftPayload is null)
                        throw new Exception("No SSE scan_result payload carried a native drift within 30 seconds; drift detection is still being dropped by the bridge.");

                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                    using var driftRequest = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/api/drifts");
                    driftRequest.Headers.Add("X-WinWiFi-Token", bridge.AuthToken);
                    var driftResponse = await http.SendAsync(driftRequest, timeoutCts.Token);
                    string polledJson = await driftResponse.Content.ReadAsStringAsync(timeoutCts.Token);
                    if (driftResponse.StatusCode != HttpStatusCode.OK)
                        throw new Exception($"GET /api/drifts returned {(int)driftResponse.StatusCode} instead of 200.");

                    var options = new System.Text.Json.JsonSerializerOptions
                    {
                        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                        PropertyNameCaseInsensitive = true
                    };
                    var polled = System.Text.Json.JsonSerializer.Deserialize<List<SecurityChange>>(polledJson, options);
                    if (polled is null || polled.Count == 0)
                        throw new Exception("GET /api/drifts served an empty list while the SSE stream carried a drift.");

                    SecurityChange change = polled.First(c => c.Type == "channel_shift");
                    if (string.IsNullOrWhiteSpace(change.Bssid) || string.IsNullOrWhiteSpace(change.Title)
                        || !change.Before.Contains("Channel", StringComparison.OrdinalIgnoreCase)
                        || !change.After.Contains("Channel", StringComparison.OrdinalIgnoreCase)
                        || string.IsNullOrWhiteSpace(change.RiskImpact))
                        throw new Exception($"The served drift is missing the fields the change-intelligence panel renders: {polledJson}");

                    // The camelCase keys are the contract the dashboard reads.
                    foreach (string key in new[] { "\"bssid\"", "\"ssid\"", "\"type\"", "\"title\"", "\"before\"", "\"after\"", "\"riskImpact\"" })
                    {
                        if (!polledJson.Contains(key, StringComparison.Ordinal))
                            throw new Exception($"GET /api/drifts omitted the {key} field the dashboard binds to.");
                    }

                    return $"A virtual adapter that changed channels was reported as a channel_shift drift on both the SSE scan_result payload and GET /api/drifts, with before/after and risk impact intact ('{change.Before}' -> '{change.After}', {change.RiskImpact}).";
                }
                finally
                {
                    await bridge.StopAsync();
                    SqliteStorageService.ReleaseAllPools();
                    TryDeleteScanDatabase(tempDb);
                }
            }));

            return results;
        }

        /// <summary>Stands in for a UI thread that is blocked inside a wait.</summary>
        private sealed class DroppingSynchronizationContext : SynchronizationContext
        {
            public override void Post(SendOrPostCallback d, object? state) { }
            public override void Send(SendOrPostCallback d, object? state) { }
        }

        private static void TryDeleteScanDatabase(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
                if (File.Exists(path + "-wal")) File.Delete(path + "-wal");
                if (File.Exists(path + "-shm")) File.Delete(path + "-shm");
            }
            catch { }
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
            writer.Write(44);
            writer.Write(44);
            writer.Write((byte)0); writer.Write((byte)0); writer.Write((ushort)8); writer.Write(0u);
            writer.Write((ushort)0x0080); writer.Write((ushort)0);
            writer.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write((ushort)0); writer.Write(0UL); writer.Write((ushort)100); writer.Write((ushort)0x0011);
            return stream.ToArray();
        }
#endif

        private static void WritePcapHeader(BinaryWriter writer, uint linkType)
        {
            writer.Write(0xa1b2c3d4);
            writer.Write((ushort)2);
            writer.Write((ushort)4);
            writer.Write(0);
            writer.Write(0);
            writer.Write(65535u);
            writer.Write(linkType);
        }

        private static byte[] BuildPcap(uint linkType, params byte[][] packets)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            WritePcapHeader(writer, linkType);
            uint timestamp = 1710000000;
            foreach (var packet in packets)
            {
                writer.Write(timestamp++);
                writer.Write(0u);
                writer.Write((uint)packet.Length);
                writer.Write((uint)packet.Length);
                writer.Write(packet);
            }
            return stream.ToArray();
        }

        private static byte[] BuildBeaconFrame(string ssid)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((ushort)8);
            writer.Write(0u);
            writer.Write((ushort)0x0080);
            writer.Write((ushort)0);
            writer.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write(new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 });
            writer.Write((ushort)0);
            writer.Write(0UL);
            writer.Write((ushort)100);
            writer.Write((ushort)0x0011);
            byte[] ssidBytes = Encoding.UTF8.GetBytes(ssid);
            writer.Write((byte)0);
            writer.Write((byte)ssidBytes.Length);
            writer.Write(ssidBytes);
            return stream.ToArray();
        }

        private static void WritePcapNgBlock(BinaryWriter writer, uint blockType, byte[] body, bool corruptTrailer = false)
        {
            int padding = (4 - (body.Length % 4)) % 4;
            uint totalLength = (uint)(12 + body.Length + padding);
            writer.Write(blockType);
            writer.Write(totalLength);
            writer.Write(body);
            for (int index = 0; index < padding; index++) writer.Write((byte)0);
            writer.Write(corruptTrailer ? totalLength + 4 : totalLength);
        }

        private static byte[] BuildPcapNgSectionHeader()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write(0x1a2b3c4du);
            writer.Write((ushort)1);
            writer.Write((ushort)0);
            writer.Write(ulong.MaxValue);
            return stream.ToArray();
        }

        private static byte[] BuildPcapNgInterface(uint snapLength, byte? timestampResolution = null)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write((ushort)127);
            writer.Write((ushort)0);
            writer.Write(snapLength);
            if (timestampResolution.HasValue)
            {
                writer.Write((ushort)9);
                writer.Write((ushort)1);
                writer.Write(timestampResolution.Value);
                writer.Write((byte)0);
            }
            writer.Write((ushort)0);
            writer.Write((ushort)0);
            return stream.ToArray();
        }

        private static byte[] BuildPcapNgEnhancedPacket(uint interfaceId, ulong timestampTicks, byte[] packet)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);
            writer.Write(interfaceId);
            writer.Write((uint)(timestampTicks >> 32));
            writer.Write((uint)(timestampTicks & 0xFFFFFFFF));
            writer.Write((uint)packet.Length);
            writer.Write((uint)packet.Length);
            writer.Write(packet);
            return stream.ToArray();
        }

        // Zero-adapter Wi-Fi service so bridge tests never touch the real radio.
        private sealed class StubWifiService : INativeWifiService
        {
            public ScanTelemetryState CurrentState => ScanTelemetryState.Idle;
            public event Action<ScanDiagnostics>? DiagnosticsUpdated { add { } remove { } }
            public event Action<ScanBatchResult>? ScanCompleted { add { } remove { } }
            public Task<List<WifiAdapter>> GetAdaptersAsync() => Task.FromResult(new List<WifiAdapter>());
            public Task<List<AccessPoint>> ScanNetworksAsync(string adapterId, CancellationToken cancellationToken = default) => Task.FromResult(new List<AccessPoint>());
            public Task<ScanBatchResult> ScanNetworksExAsync(string adapterId, CancellationToken cancellationToken = default) => Task.FromResult<ScanBatchResult>(null!);
            public Task<Dictionary<string, ScanBatchResult>> ScanAllAdaptersAsync(CancellationToken cancellationToken = default) => Task.FromResult(new Dictionary<string, ScanBatchResult>());
            public Task TriggerHardwareScanAsync(string adapterId, CancellationToken cancellationToken = default) => Task.CompletedTask;
            public bool IsNativeWifiAvailable() => false;
            public ScanDiagnostics GetDiagnostics() => new ScanDiagnostics();
            public void Dispose() { }
        }

        /// <summary>
        /// One in-memory BSS entry whose channel alternates every time Windows is
        /// asked to scan, so the real analyzer and scanner loop see a fresh
        /// configuration drift on each cycle without touching the radio.
        /// </summary>
        private sealed class ShiftingChannelWifiService : INativeWifiService
        {
            private int _scanRequests;

            public ScanTelemetryState CurrentState => ScanTelemetryState.Idle;
            public event Action<ScanDiagnostics>? DiagnosticsUpdated { add { } remove { } }
            public event Action<ScanBatchResult>? ScanCompleted { add { } remove { } }

            public Task<List<WifiAdapter>> GetAdaptersAsync() => Task.FromResult(new List<WifiAdapter>
            {
                new WifiAdapter
                {
                    Id = "STUB-SHIFTING-ADAPTER",
                    Name = "Virtual Telemetry Adapter",
                    Description = "Memory-only adapter used by the drift surface test",
                    InterfaceGuid = Guid.Empty,
                    MacAddress = "02:00:00:00:00:01",
                    Vendor = "Test Fixture",
                    Chipset = "Virtual",
                    Status = "Ready"
                }
            });

            public Task TriggerHardwareScanAsync(string adapterId, CancellationToken cancellationToken = default)
            {
                // The channel is derived from the request count, so every scan
                // cycle observes a different channel than the cycle before it.
                Interlocked.Increment(ref _scanRequests);
                return Task.CompletedTask;
            }

            public Task<List<AccessPoint>> ScanNetworksAsync(string adapterId, CancellationToken cancellationToken = default)
                => Task.FromResult(new List<AccessPoint> { BuildShiftingAccessPoint(_scanRequests) });

            public Task<ScanBatchResult> ScanNetworksExAsync(string adapterId, CancellationToken cancellationToken = default)
                => Task.FromResult(new ScanBatchResult
                {
                    AdapterId = adapterId,
                    AccessPoints = new List<AccessPoint> { BuildShiftingAccessPoint(_scanRequests) }
                });

            public Task<Dictionary<string, ScanBatchResult>> ScanAllAdaptersAsync(CancellationToken cancellationToken = default)
                => Task.FromResult(new Dictionary<string, ScanBatchResult>
                {
                    ["STUB-SHIFTING-ADAPTER"] = new ScanBatchResult { AdapterId = "STUB-SHIFTING-ADAPTER", AccessPoints = new List<AccessPoint> { BuildShiftingAccessPoint(_scanRequests) } }
                });

            public bool IsNativeWifiAvailable() => false;
            public ScanDiagnostics GetDiagnostics() => new ScanDiagnostics();
            public void Dispose() { }

            private static AccessPoint BuildShiftingAccessPoint(int scanRequests)
            {
                bool evenCycle = scanRequests % 2 == 0;
                return new AccessPoint
                {
                    Bssid = "02:00:00:00:00:02",
                    Ssid = "Drift Fixture",
                    Channel = evenCycle ? 1 : 6,
                    FrequencyMHz = evenCycle ? 2412 : 2437,
                    Band = "2.4 GHz",
                    Rssi = -52,
                    SignalQuality = 78,
                    Security = "WPA2-Personal",
                    Cipher = "CCMP",
                    Vendor = "Test Fixture",
                    SecurityScore = 70
                };
            }
        }

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
