using System;
using System.Collections.Generic;
using System.Linq;
using WinWiFi.Models;

namespace WinWiFi.Services
{
    public class ThreatAnalysisResult
    {
        public List<ThreatFinding> Findings { get; set; } = new();
        public List<SecurityChange> DetectedDrifts { get; set; } = new();
        public int OverallRiskScore { get; set; } = 0; // 0 to 100
        public int CriticalThreatsCount => Findings.Count(f => f.Severity == "CRITICAL");
        public int HighThreatsCount => Findings.Count(f => f.Severity == "HIGH");
        public int MediumThreatsCount => Findings.Count(f => f.Severity == "MEDIUM");
    }

    public class SecurityAnalyzer
    {
        public void EvaluateSecurityPosture(AccessPoint ap)
        {
            ap.SecurityIssues.Clear();
            int score = 100;

            string secUpper = ap.Security.ToUpperInvariant();
            string cipherUpper = ap.Cipher.ToUpperInvariant();

            // 1. WEP Deprecation Check (NIST SP 800-153 §4.2, PCI-DSS 4.0 Req 2.1)
            if (secUpper.Contains("WEP") || cipherUpper.Contains("WEP"))
            {
                score -= 65;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "VULN-WEP-BROKEN",
                    Title = "Deprecated Insecure WEP Encryption",
                    Severity = "CRITICAL",
                    Description = "The network uses 802.11 WEP encryption. Weak 24-bit IV keys can be recovered in under 60 seconds via FMS/KoreK/PTW cryptanalytic attacks.",
                    Remediation = "Migrate hardware immediately to WPA2-Enterprise or WPA3-SAE (AES-CCMP/GCMP-256).",
                    StandardReference = "NIST SP 800-153 §4.2 / PCI-DSS 4.0 Req 2.1"
                });
            }
            // 2. Open / Unencrypted Wi-Fi (NIST SP 800-153 §4.1)
            else if (secUpper.Contains("OPEN") || secUpper.Contains("NONE"))
            {
                score -= 45;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "VULN-OPEN-UNENCRYPTED",
                    Title = "Unencrypted 802.11 Radio Medium",
                    Severity = "HIGH",
                    Description = "Radio layer frames are broadcast in plaintext. Any adjacent station can passively capture session cookies, credentials, and traffic.",
                    Remediation = "Deploy Opportunistic Wireless Encryption (OWE / RFC 8110) or WPA3-SAE.",
                    StandardReference = "NIST SP 800-153 §4.1"
                });
            }

            // 3. WPA 1.0 / TKIP Deprecation (IEEE 802.11i / NIST SP 800-153 §4.2)
            if (cipherUpper.Contains("TKIP") || (secUpper.Contains("WPA-PSK") && !secUpper.Contains("WPA2")))
            {
                score -= 30;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "VULN-WPA-TKIP",
                    Title = "Deprecated WPA1 / TKIP MIC Downgrade",
                    Severity = "HIGH",
                    Description = "TKIP encryption suffers from Michael MIC keystream recovery vulnerabilities (Beck-Tews / Ohigashi-Kuwakado attacks).",
                    Remediation = "Disable TKIP in AP management firmware. Mandate AES-CCMP only.",
                    StandardReference = "NIST SP 800-153 §4.2"
                });
            }

            // 4. WPS 1.0 / 2.0 Unlocked Hazard
            if (ap.IsWpsEnabled && !ap.IsWpsLocked)
            {
                score -= 25;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "VULN-WPS-PIN",
                    Title = "Wi-Fi Protected Setup (WPS) Active and Unlocked",
                    Severity = "HIGH",
                    Description = "WPS External Registrar PIN validation splits the 8-digit PIN into two halves (10,000 + 1,000 combinations), exposing the AP to offline Pixie Dust PRNG recovery.",
                    Remediation = "Disable WPS completely in AP management settings.",
                    StandardReference = "NIST SP 800-153 §4.3 / US-CERT VU#723755"
                });
            }

            // 5. Missing Protected Management Frames (802.11w / PMF)
            if (!ap.PmfRequired && (secUpper.Contains("WPA2") || secUpper.Contains("ENTERPRISE")))
            {
                score -= 10;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "WARN-PMF-DISABLED",
                    Title = "Protected Management Frames (802.11w PMF) Disabled",
                    Severity = "MEDIUM",
                    Description = "Without PMF, deauthentication and disassociation frames are unauthenticated, allowing spoofed packet floods to disconnect legitimate stations.",
                    Remediation = "Configure 802.11w Management Frame Protection to 'Mandatory' or 'Capable'.",
                    StandardReference = "NIST SP 800-153 §4.4 / IEEE 802.11w"
                });
            }

            // 6. Locally Administered (LAA) / Randomized MAC Address on AP
            if (WinWiFi.Services.OuiLookupService.IsLocallyAdministered(ap.Bssid))
            {
                score -= 15;
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "WARN-LAA-BSSID",
                    Title = "Locally Administered / Randomized AP BSSID",
                    Severity = "MEDIUM",
                    Description = "The BSSID uses a locally administered MAC address (bit 1 of first octet is 1). Hardware APs use globally unique vendor OUIs; LAA is common in software APs (hostapd, airbase-ng, mobile hotspots).",
                    Remediation = "Investigate device origin. Verify whether this is an authorized temporary hotspot or an unauthorized rogue device.",
                    StandardReference = "NIST SP 800-153 §5.1"
                });
            }

            ap.SecurityScore = Math.Max(0, Math.Min(100, score));
        }

        public void DetectRogueAccessPoints(List<AccessPoint> accessPoints)
        {
            var analysis = AnalyzeThreatsAndDrift(accessPoints, null);
            foreach (var rogueBssid in analysis.Findings.Where(f => f.Category == "Rogue AP" || f.Category == "Evil Twin").Select(f => f.RelatedBssid))
            {
                var targetAp = accessPoints.FirstOrDefault(a => a.Bssid.Equals(rogueBssid, StringComparison.OrdinalIgnoreCase));
                if (targetAp != null)
                {
                    targetAp.IsRogue = true;
                    targetAp.SecurityScore = Math.Min(targetAp.SecurityScore, 20);
                }
            }
        }

        public ThreatAnalysisResult AnalyzeThreatsAndDrift(
            List<AccessPoint> currentAps, 
            Dictionary<string, AccessPoint>? baselineAps)
        {
            var result = new ThreatAnalysisResult();
            var findingIdCounter = 1;

            // Group current APs by trimmed SSID
            var ssidGroups = currentAps
                .Where(a => !string.IsNullOrWhiteSpace(a.Ssid) && a.Ssid != "[Hidden SSID]")
                .GroupBy(a => a.Ssid.Trim(), StringComparer.OrdinalIgnoreCase);

            foreach (var group in ssidGroups)
            {
                var apList = group.ToList();

                // 1. Multi-factor Evil Twin & Rogue Detection
                for (int i = 0; i < apList.Count; i++)
                {
                    for (int j = i + 1; j < apList.Count; j++)
                    {
                        var ap1 = apList[i];
                        var ap2 = apList[j];

                        // Criterion A: Security Profile Downgrade on Same SSID
                        if (!string.Equals(ap1.Security, ap2.Security, StringComparison.OrdinalIgnoreCase))
                        {
                            var suspiciousAp = (ap1.Security.Contains("Open") || ap1.SecurityScore < ap2.SecurityScore) ? ap1 : ap2;
                            var trustedPeer = suspiciousAp == ap1 ? ap2 : ap1;

                            result.Findings.Add(new ThreatFinding
                            {
                                Id = $"THR-{findingIdCounter++:D4}",
                                Category = "Evil Twin",
                                Title = $"Evil Twin Clone of SSID '{group.Key}'",
                                Severity = "CRITICAL",
                                Confidence = 95,
                                RiskScore = 95,
                                RelatedBssid = suspiciousAp.Bssid,
                                RelatedSsid = group.Key,
                                Evidence = $"BSSID {suspiciousAp.Bssid} broadcasts '{group.Key}' with security '{suspiciousAp.Security}', while peer BSSID {trustedPeer.Bssid} runs '{trustedPeer.Security}'.",
                                Explanation = "Attackers clone authorized SSIDs using lower security (or Open) to intercept client credentials and perform captive-portal credential harvesting.",
                                Remediation = "Locate transmitter via directional antenna or signal survey. Block client connection profiles and alert facilities security.",
                                Status = "New",
                                StandardReference = "NIST SP 800-153 §5.1"
                            });
                        }

                        // Criterion B: Vendor / OUI Mismatch on Infrastructure SSID
                        bool vendor1Known = ap1.Vendor != "Unknown" && !ap1.Vendor.Contains("Randomized");
                        bool vendor2Known = ap2.Vendor != "Unknown" && !ap2.Vendor.Contains("Randomized");
                        if (vendor1Known && vendor2Known && !string.Equals(ap1.Vendor, ap2.Vendor, StringComparison.OrdinalIgnoreCase))
                        {
                            // If one is enterprise infrastructure (Cisco, Aruba, Ubiquiti, Fortinet) and the other is consumer/IoT
                            bool isInfra1 = IsEnterpriseVendor(ap1.Vendor);
                            bool isInfra2 = IsEnterpriseVendor(ap2.Vendor);

                            if (isInfra1 != isInfra2)
                            {
                                var rogue = isInfra1 ? ap2 : ap1;
                                var infra = isInfra1 ? ap1 : ap2;

                                result.Findings.Add(new ThreatFinding
                                {
                                    Id = $"THR-{findingIdCounter++:D4}",
                                    Category = "Rogue AP",
                                    Title = $"Hardware Vendor Mismatch on SSID '{group.Key}'",
                                    Severity = "CRITICAL",
                                    Confidence = 90,
                                    RiskScore = 90,
                                    RelatedBssid = rogue.Bssid,
                                    RelatedSsid = group.Key,
                                    Evidence = $"Authorized infrastructure vendor is '{infra.Vendor}' ({infra.Bssid}), but BSSID {rogue.Bssid} is manufactured by '{rogue.Vendor}'.",
                                    Explanation = "Enterprise wireless deployments use homogenous hardware. An unexpected consumer or IoT vendor broadcasting the same SSID indicates an unauthorized rogue access point.",
                                    Remediation = "Verify physical switch ports for unapproved rogue hardware. Disconnect port immediately.",
                                    Status = "New",
                                    StandardReference = "PCI-DSS 4.0 Req 11.2 / NIST SP 800-153 §5.1"
                                });
                            }
                        }

                        // Criterion C: Signal Disparity / Rogue Proximity Lure (+25 dBm difference)
                        if (Math.Abs(ap1.Rssi - ap2.Rssi) >= 28)
                        {
                            var stronger = ap1.Rssi > ap2.Rssi ? ap1 : ap2;
                            var weaker = stronger == ap1 ? ap2 : ap1;

                            if (stronger.SecurityScore < weaker.SecurityScore || WinWiFi.Services.OuiLookupService.IsLocallyAdministered(stronger.Bssid))
                            {
                                result.Findings.Add(new ThreatFinding
                                {
                                    Id = $"THR-{findingIdCounter++:D4}",
                                    Category = "Evil Twin",
                                    Title = $"High-Power Signal Anomaly on SSID '{group.Key}'",
                                    Severity = "HIGH",
                                    Confidence = 80,
                                    RiskScore = 85,
                                    RelatedBssid = stronger.Bssid,
                                    RelatedSsid = group.Key,
                                    Evidence = $"BSSID {stronger.Bssid} is broadcasting at {stronger.Rssi} dBm ({Math.Abs(stronger.Rssi - weaker.Rssi)} dBm higher than peer {weaker.Bssid} at {weaker.Rssi} dBm).",
                                    Explanation = "Attackers place rogue APs in close physical proximity to force 802.11 client roaming algorithms to associate with the stronger malicious signal.",
                                    Remediation = "Triangulate signal source location. Check for rogue battery-powered devices in conference rooms or public areas.",
                                    Status = "New",
                                    StandardReference = "NIST SP 800-153 §5.1"
                                });
                            }
                        }
                    }
                }
            }

            // 2. Baseline Comparison & Security Drift Monitoring
            if (baselineAps != null && baselineAps.Count > 0)
            {
                foreach (var current in currentAps)
                {
                    if (baselineAps.TryGetValue(current.Bssid, out var baseline))
                    {
                        // Drift 1: Encryption Downgrade
                        if (!string.Equals(current.Security, baseline.Security, StringComparison.OrdinalIgnoreCase))
                        {
                            var drift = new SecurityChange
                            {
                                Id = Guid.NewGuid().ToString(),
                                Bssid = current.Bssid,
                                Ssid = current.Ssid,
                                Type = "security_downgrade",
                                Title = "Security Encryption Downgrade Detected",
                                Before = baseline.Security,
                                After = current.Security,
                                RiskImpact = "CRITICAL"
                            };
                            result.DetectedDrifts.Add(drift);

                            result.Findings.Add(new ThreatFinding
                            {
                                Id = $"THR-{findingIdCounter++:D4}",
                                Category = "Security Downgrade",
                                Title = $"Active Encryption Downgrade on {current.Bssid}",
                                Severity = "CRITICAL",
                                Confidence = 95,
                                RiskScore = 90,
                                RelatedBssid = current.Bssid,
                                RelatedSsid = current.Ssid,
                                Evidence = $"Baseline security was '{baseline.Security}'; current active broadcast is '{current.Security}'.",
                                Explanation = "A previously hardened access point has been reconfigured or spoofed with weaker authentication parameters.",
                                Remediation = "Audit AP configuration via central wireless controller. Roll back unauthorized changes.",
                                Status = "New",
                                StandardReference = "NIST SP 800-153 §4.2"
                            });
                        }

                        // Drift 2: Protected Management Frames (PMF) Stripped
                        if (baseline.PmfRequired && !current.PmfRequired)
                        {
                            var drift = new SecurityChange
                            {
                                Id = Guid.NewGuid().ToString(),
                                Bssid = current.Bssid,
                                Ssid = current.Ssid,
                                Type = "pmf_disabled",
                                Title = "Protected Management Frames (PMF) Removed",
                                Before = "PMF Required (802.11w Mandatory)",
                                After = current.PmfCapable ? "PMF Capable Only" : "PMF Disabled",
                                RiskImpact = "HIGH"
                            };
                            result.DetectedDrifts.Add(drift);

                            result.Findings.Add(new ThreatFinding
                            {
                                Id = $"THR-{findingIdCounter++:D4}",
                                Category = "PMF Stripped",
                                Title = $"PMF Protection Stripped on '{current.Ssid}'",
                                Severity = "HIGH",
                                Confidence = 90,
                                RiskScore = 80,
                                RelatedBssid = current.Bssid,
                                RelatedSsid = current.Ssid,
                                Evidence = "802.11w RSN capability MFPR bit has been cleared from Beacon Information Elements.",
                                Explanation = "Removing PMF enables attackers to disconnect client stations using spoofed deauthentication packets.",
                                Remediation = "Re-enable 802.11w Protected Management Frames in AP WLAN profile.",
                                Status = "New",
                                StandardReference = "NIST SP 800-153 §4.4"
                            });
                        }

                        // Drift 3: WPS Unexpectedly Enabled
                        if (!baseline.IsWpsEnabled && current.IsWpsEnabled)
                        {
                            var drift = new SecurityChange
                            {
                                Id = Guid.NewGuid().ToString(),
                                Bssid = current.Bssid,
                                Ssid = current.Ssid,
                                Type = "wps_enabled",
                                Title = "WPS Service Activated on Secure AP",
                                Before = "WPS Disabled",
                                After = "WPS Enabled",
                                RiskImpact = "HIGH"
                            };
                            result.DetectedDrifts.Add(drift);
                        }

                        // Drift 4: Channel Shift
                        if (baseline.Channel != current.Channel)
                        {
                            var drift = new SecurityChange
                            {
                                Id = Guid.NewGuid().ToString(),
                                Bssid = current.Bssid,
                                Ssid = current.Ssid,
                                Type = "channel_shift",
                                Title = "Operating Channel Shift",
                                Before = $"Channel {baseline.Channel} ({baseline.Band})",
                                After = $"Channel {current.Channel} ({current.Band})",
                                RiskImpact = "LOW"
                            };
                            result.DetectedDrifts.Add(drift);
                        }
                    }
                    else
                    {
                        // Check if current AP is broadcasting a recognized corporate SSID from an unknown BSSID
                        var knownCorpSsids = baselineAps.Values
                            .Where(b => b.Classification == "Corporate" || b.ApprovedStatus == "Approved")
                            .Select(b => b.Ssid)
                            .ToHashSet(StringComparer.OrdinalIgnoreCase);

                        if (knownCorpSsids.Contains(current.Ssid))
                        {
                            result.Findings.Add(new ThreatFinding
                            {
                                Id = $"THR-{findingIdCounter++:D4}",
                                Category = "Unapproved Hardware",
                                Title = $"Unregistered BSSID on Corporate SSID '{current.Ssid}'",
                                Severity = "HIGH",
                                Confidence = 85,
                                RiskScore = 85,
                                RelatedBssid = current.Bssid,
                                RelatedSsid = current.Ssid,
                                Evidence = $"BSSID {current.Bssid} ({current.Vendor}) is broadcasting corporate SSID '{current.Ssid}' but is not in the authorized asset database.",
                                Explanation = "Enterprise networks require strictly inventoried access point MAC addresses. Unregistered transmitters broadcasting corporate SSIDs represent unauthorized expansion or external rogue deployments.",
                                Remediation = "Conduct physical site audit. Register hardware in enterprise inventory if legitimate, or isolate switch port.",
                                Status = "New",
                                StandardReference = "PCI-DSS 4.0 Req 11.2.1"
                            });
                        }
                    }
                }
            }

            // Calculate Overall Posture Risk Score
            int totalRisk = 0;
            foreach (var f in result.Findings)
            {
                totalRisk += f.Severity switch
                {
                    "CRITICAL" => 35,
                    "HIGH" => 20,
                    "MEDIUM" => 10,
                    _ => 5
                };
            }
            result.OverallRiskScore = Math.Min(100, totalRisk);

            return result;
        }

        private static bool IsEnterpriseVendor(string vendor)
        {
            if (string.IsNullOrEmpty(vendor)) return false;
            string v = vendor.ToUpperInvariant();
            return v.Contains("CISCO") || v.Contains("MERAKI") || v.Contains("ARUBA") ||
                   v.Contains("HEWLETT") || v.Contains("UBIQUITI") || v.Contains("FORTINET") ||
                   v.Contains("RUCKUS") || v.Contains("EXTREME") || v.Contains("MIST") ||
                   v.Contains("JUNIPER") || v.Contains("AEROHIVE");
        }
    }
}
