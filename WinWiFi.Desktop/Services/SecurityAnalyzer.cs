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
            ap.RiskFactors.Clear();
            int score = 100;

            string secUpper = ap.Security.ToUpperInvariant();
            string cipherUpper = ap.Cipher.ToUpperInvariant();
            // "OWE (Enhanced Open)" is encrypted (RFC 8110) and must not be
            // classified as unencrypted just because the label contains "Open".
            bool isOwe = secUpper.Contains("OWE") || secUpper.Contains("ENHANCED OPEN");

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
            else if (!isOwe && (secUpper.Contains("OPEN") || secUpper.Contains("NONE")))
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
            if (ap.PmfInformationAvailable && !ap.PmfRequired && (secUpper.Contains("WPA2") || secUpper.Contains("ENTERPRISE")))
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
                ap.SecurityIssues.Add(new SecurityIssue
                {
                    Id = "WARN-LAA-BSSID",
                    Title = "Locally Administered / Randomized AP BSSID",
                    Severity = "INFO",
                    Description = "The BSSID uses a locally administered MAC address. This is common for mobile hotspots and privacy-preserving devices and is not a vulnerability by itself.",
                    Remediation = "Confirm ownership if this network is expected to be part of the authorized scope.",
                    StandardReference = "NIST SP 800-153 §5.1"
                });
            }

            ap.SecurityScore = Math.Max(0, Math.Min(100, score));
            ap.RiskScore = 100 - ap.SecurityScore;
            foreach (var issue in ap.SecurityIssues)
            {
                int points = issue.Id switch
                {
                    "VULN-WEP-BROKEN" => 65,
                    "VULN-OPEN-UNENCRYPTED" => 45,
                    "VULN-WPA-TKIP" => 30,
                    "VULN-WPS-PIN" => 25,
                    "WARN-PMF-DISABLED" => 10,
                    _ => 0
                };
                ap.RiskFactors.Add(new RiskFactor { Name = issue.Title, Points = points, Evidence = issue.Description });
            }
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

            // Group current APs by trimmed SSID
            var ssidGroups = currentAps
                .Where(a => !string.IsNullOrWhiteSpace(a.Ssid) && a.Ssid != "[Hidden SSID]")
                .GroupBy(a => a.Ssid.Trim(), StringComparer.OrdinalIgnoreCase);

            foreach (var group in ssidGroups)
            {
                var apList = group.ToList();

                // 1. Multi-signal Evil Twin & Rogue Detection.
                // A single difference (security string, vendor, or signal) is
                // normal in mixed-AP and WPA2/WPA3 transition deployments.
                // Require at least two independent signals before alerting.
                var candidates = new Dictionary<string, RogueCandidate>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < apList.Count; i++)
                {
                    for (int j = i + 1; j < apList.Count; j++)
                    {
                        ConsiderRoguePair(apList[i], apList[j], baselineAps, candidates);
                        ConsiderRoguePair(apList[j], apList[i], baselineAps, candidates);
                    }
                }

                foreach (var candidate in candidates.Values.Where(c => c.Signals.Count >= 2))
                {
                    var suspect = candidate.Suspect;
                    var peer = candidate.Peer;
                    bool downgrade = candidate.Signals.Contains("security_downgrade");
                    bool ouiMismatch = candidate.Signals.Contains("oui_mismatch");
                    bool unapproved = candidate.Signals.Contains("unapproved_bssid");

                    string category = downgrade ? "Evil Twin" : "Rogue AP";
                    string severity = (candidate.Signals.Count >= 3 || (downgrade && (ouiMismatch || unapproved)))
                        ? "CRITICAL"
                        : "HIGH";
                    int confidence = Math.Min(95, 40 + candidate.Signals.Count * 15 + (downgrade ? 5 : 0));

                    result.Findings.Add(new ThreatFinding
                    {
                        Id = MakeFindingId(category, suspect.Bssid),
                        Category = category,
                        Title = downgrade
                            ? $"Evil Twin Clone of SSID '{group.Key}'"
                            : $"Rogue AP Broadcasting SSID '{group.Key}'",
                        Severity = severity,
                        Confidence = confidence,
                        RiskScore = confidence,
                        RelatedBssid = suspect.Bssid,
                        RelatedSsid = group.Key,
                        Evidence = string.Join("; ", candidate.Signals.Select(signal => signal switch
                        {
                            "security_downgrade" => $"security downgrade '{suspect.Security}' vs peer '{peer.Security}' ({peer.Bssid})",
                            "oui_mismatch" => $"OUI anomaly '{suspect.Vendor}' ({suspect.Bssid}) vs '{peer.Vendor}' ({peer.Bssid})",
                            "unapproved_bssid" => $"BSSID {suspect.Bssid} is absent from the approved asset registry for '{group.Key}'",
                            "signal_anomaly" => $"signal anomaly {suspect.Rssi} dBm vs {peer.Rssi} dBm (+{Math.Abs(suspect.Rssi - peer.Rssi)} dB)",
                            _ => signal
                        })),
                        Explanation = downgrade
                            ? "Multiple independent indicators suggest this transmitter clones an authorized SSID with weaker security to intercept client traffic."
                            : "Multiple independent indicators suggest an unauthorized access point is broadcasting a known SSID.",
                        Remediation = "Verify the transmitter against the approved asset registry, locate it physically, and remove it if unauthorized.",
                        Status = "New",
                        StandardReference = "NIST SP 800-153 §5.1"
                    });
                }
            }

            // 2. Baseline Comparison & Security Drift Monitoring
            if (baselineAps != null && baselineAps.Count > 0)
            {
                foreach (var current in currentAps)
                {
                    if (baselineAps.TryGetValue(current.Bssid, out var baseline))
                    {
                        // Drift 1: Encryption Downgrade. A WPA2/WPA3 pair is a
                        // normal transition deployment, not a downgrade.
                        if (!string.Equals(current.Security, baseline.Security, StringComparison.OrdinalIgnoreCase)
                            && !IsTransitionCompatible(current.Security, baseline.Security))
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
                                Id = MakeFindingId("Security Downgrade", current.Bssid),
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
                                Id = MakeFindingId("PMF Stripped", current.Bssid),
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
                                Id = MakeFindingId("Unapproved Hardware", current.Bssid),
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

        private const int SignalAnomalyThresholdDb = 25;

        private sealed class RogueCandidate
        {
            public AccessPoint Suspect { get; init; } = null!;
            public AccessPoint Peer { get; init; } = null!;
            public HashSet<string> Signals { get; } = new(StringComparer.OrdinalIgnoreCase);
        }

        private static void ConsiderRoguePair(
            AccessPoint suspect,
            AccessPoint peer,
            Dictionary<string, AccessPoint>? baselineAps,
            Dictionary<string, RogueCandidate> candidates)
        {
            if (!IsPlausibleSuspect(suspect, peer, baselineAps)) return;

            var signals = CollectSignals(suspect, peer, baselineAps);
            if (signals.Count < 2) return;

            if (candidates.TryGetValue(suspect.Bssid, out var existing) && existing.Signals.Count >= signals.Count)
                return;

            var candidate = new RogueCandidate { Suspect = suspect, Peer = peer };
            foreach (var signal in signals) candidate.Signals.Add(signal);
            candidates[suspect.Bssid] = candidate;
        }

        private static bool IsPlausibleSuspect(
            AccessPoint suspect,
            AccessPoint peer,
            Dictionary<string, AccessPoint>? baselineAps)
        {
            if (string.IsNullOrWhiteSpace(suspect.Bssid) ||
                string.Equals(suspect.Bssid, peer.Bssid, StringComparison.OrdinalIgnoreCase))
                return false;

            int suspectTier = SecurityTier(suspect.Security);
            int peerTier = SecurityTier(peer.Security);
            if (!IsTransitionCompatible(suspect.Security, peer.Security) &&
                suspectTier >= 0 && peerTier >= 0 && suspectTier < peerTier)
                return true;

            if (IsUnapprovedBssid(suspect, baselineAps) && !IsUnapprovedBssid(peer, baselineAps))
                return true;

            bool suspectLaa = OuiLookupService.IsLocallyAdministered(suspect.Bssid);
            bool peerLaa = OuiLookupService.IsLocallyAdministered(peer.Bssid);
            if (suspectLaa && !peerLaa) return true;

            return suspect.Rssi - peer.Rssi >= SignalAnomalyThresholdDb;
        }

        private static HashSet<string> CollectSignals(
            AccessPoint suspect,
            AccessPoint peer,
            Dictionary<string, AccessPoint>? baselineAps)
        {
            var signals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int suspectTier = SecurityTier(suspect.Security);
            int peerTier = SecurityTier(peer.Security);

            if (!IsTransitionCompatible(suspect.Security, peer.Security) &&
                suspectTier >= 0 && peerTier >= 0 && suspectTier < peerTier)
            {
                signals.Add("security_downgrade");
            }

            if (IsOuiAnomaly(suspect, peer)) signals.Add("oui_mismatch");
            if (IsUnapprovedBssid(suspect, baselineAps)) signals.Add("unapproved_bssid");
            if (suspect.Rssi - peer.Rssi >= SignalAnomalyThresholdDb) signals.Add("signal_anomaly");

            return signals;
        }

        private static bool IsOuiAnomaly(AccessPoint suspect, AccessPoint peer)
        {
            bool suspectLaa = OuiLookupService.IsLocallyAdministered(suspect.Bssid);
            bool peerLaa = OuiLookupService.IsLocallyAdministered(peer.Bssid);
            if (suspectLaa != peerLaa) return true;

            if (!IsKnownVendor(suspect.Vendor) || !IsKnownVendor(peer.Vendor)) return false;
            return !string.Equals(suspect.Vendor, peer.Vendor, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsKnownVendor(string? vendor) =>
            !string.IsNullOrWhiteSpace(vendor) &&
            !vendor.Equals("Unknown", StringComparison.OrdinalIgnoreCase) &&
            !vendor.Contains("Randomized", StringComparison.OrdinalIgnoreCase);

        private static bool IsUnapprovedBssid(AccessPoint ap, Dictionary<string, AccessPoint>? baselineAps)
        {
            if (baselineAps == null || baselineAps.Count == 0) return false;

            bool ssidHasApprovedHardware = baselineAps.Values.Any(b =>
                string.Equals(b.Ssid, ap.Ssid, StringComparison.OrdinalIgnoreCase) && IsApprovedAsset(b));
            if (!ssidHasApprovedHardware) return false;

            return !baselineAps.TryGetValue(ap.Bssid, out var known) || !IsApprovedAsset(known);
        }

        private static bool IsApprovedAsset(AccessPoint ap) =>
            string.Equals(ap.ApprovedStatus, "Approved", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(ap.Classification, "Corporate", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(ap.Classification, "Trusted", StringComparison.OrdinalIgnoreCase);

        // WPA2 and WPA3 are routinely advertised by different APs in the same
        // transition or mixed-AP deployment. That alone is not a downgrade.
        private static bool IsTransitionCompatible(string first, string second)
        {
            string a = (first ?? string.Empty).ToUpperInvariant();
            string b = (second ?? string.Empty).ToUpperInvariant();
            bool aWpa3 = a.Contains("WPA3");
            bool bWpa3 = b.Contains("WPA3");
            bool aWpa2 = a.Contains("WPA2");
            bool bWpa2 = b.Contains("WPA2");
            return (aWpa3 && bWpa2) || (aWpa2 && bWpa3);
        }

        private static int SecurityTier(string? security)
        {
            string value = (security ?? string.Empty).ToUpperInvariant();
            if (value.Contains("OWE") || value.Contains("ENHANCED OPEN")) return 3;
            if (value.Contains("WPA3")) return 4;
            if (value.Contains("WPA2")) return 3;
            if (value.Contains("WEP")) return 1;
            if (value.Contains("WPA")) return 2;
            if (value.Contains("OPEN") || value.Contains("NONE")) return 0;
            return -1;
        }

        private static string MakeFindingId(string category, string bssid)
        {
            string categorySlug = Slug(category);
            string targetSlug = Slug(bssid);
            return $"THR-{categorySlug}-{(targetSlug.Length > 0 ? targetSlug : "SESSION")}";
        }

        private static string Slug(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            var chars = value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(24).ToArray();
            return new string(chars);
        }
    }
}
