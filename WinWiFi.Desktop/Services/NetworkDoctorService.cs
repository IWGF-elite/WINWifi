using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Models;

namespace WinWiFi.Services;

public static class NetworkDoctorService
{
    public static async Task<NetworkDoctorCheck> CheckAsync(
        string adapterId,
        NetworkConnectionStatus connection,
        LocalNetworkInfo network,
        AccessPoint? connectedAp,
        IReadOnlyCollection<AccessPoint> authorizedNeighbors,
        NetworkFingerprint? baseline,
        bool replaceFingerprint,
        CancellationToken cancellationToken = default)
    {
        var result = new NetworkDoctorCheck
        {
            AdapterId = adapterId,
            Ssid = connection.Ssid,
            Bssid = connection.Bssid,
            GatewayIp = network.GatewayIp,
            DnsServers = network.DnsServers,
            Security = connectedAp?.Security ?? "Unknown",
            Cipher = connectedAp?.Cipher ?? "Unknown",
            SignalDbm = connectedAp?.Rssi,
            Signal = connectedAp is null ? "N/A" : $"{connectedAp.Rssi} dBm ({connectedAp.SignalQuality}%)",
            Channel = connectedAp?.Channel,
            Band = connectedAp?.Band ?? "Unknown",
            Status = "Complete"
        };

        if (!string.Equals(connection.State, "Connected", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(connection.Bssid)
            || string.IsNullOrWhiteSpace(connection.Ssid))
        {
            result.Status = "Unavailable";
            result.Reason = string.IsNullOrWhiteSpace(connection.Reason) ? "Connect to a Wi-Fi network before checking it." : connection.Reason;
            return result;
        }
        if (network.Status != "Available")
        {
            result.Status = "Partial";
            result.Reason = network.Reason;
        }

        result.SafeChecks.Add(new NetworkDoctorFinding
        {
            Name = "Current Wi-Fi connection",
            Status = "PASS",
            Evidence = $"Windows reports connected to {connection.Ssid} at {connection.Bssid}."
        });

        var apPattern = authorizedNeighbors
            .Where(ap => string.Equals(ap.Ssid, connection.Ssid, StringComparison.Ordinal))
            .Select(ap => NormalizeMac(ap.Bssid))
            .Where(mac => mac.Length > 0)
            .Append(NormalizeMac(connection.Bssid))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(mac => mac, StringComparer.OrdinalIgnoreCase)
            .ToList();

        result.AuthorizedNeighborCount = authorizedNeighbors.Count(ap =>
            string.Equals(ap.Band, result.Band, StringComparison.OrdinalIgnoreCase)
            && ap.IsActiveInCurrentScan);
        var sameBand = authorizedNeighbors
            .Where(ap => string.Equals(ap.Band, result.Band, StringComparison.OrdinalIgnoreCase)
                && ap.Channel > 0 && ap.FrequencyMHz > 0 && ap.IsActiveInCurrentScan)
            .Append(connectedAp)
            .Where(ap => ap is not null && ap.Channel > 0 && ap.FrequencyMHz > 0)
            .Cast<AccessPoint>()
            .GroupBy(ap => NormalizeMac(ap.Bssid), StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
        result.ObservedAuthorizedChannels = sameBand.Select(ap => ap.Channel).Distinct().OrderBy(channel => channel).ToList();
        result.RecommendedObservedChannel = SelectBestObservedChannel(sameBand, result.Bssid, result.Channel ?? 0);

        if (!IPAddress.TryParse(network.GatewayIp, out var gateway) || gateway.Equals(IPAddress.Any) || gateway.IsIPv6Multicast)
        {
            result.SafeChecks.Add(new NetworkDoctorFinding { Name = "Default gateway", Status = "WARN", Evidence = "Windows did not provide a usable gateway address for this adapter." });
        }
        else
        {
            bool sameSubnet = IsInSubnet(gateway, network.LocalIp, network.PrefixLength);
            result.SafeChecks.Add(new NetworkDoctorFinding
            {
                Name = "Gateway route",
                Status = sameSubnet ? "PASS" : "WARN",
                Evidence = sameSubnet ? $"Gateway {gateway} is in the adapter's local subnet." : $"Gateway {gateway} is outside the adapter's reported local subnet; verify the route configuration."
            });
            await MeasureGatewayAsync(gateway, result, cancellationToken).ConfigureAwait(false);
            var arp = LocalNetworkService.ReadArpTableSnapshot();
            if (arp.TryGetValue(gateway.ToString(), out string? gatewayMac))
                result.GatewayMac = FormatMac(gatewayMac);
            bool gatewayMacValid = IsValidUnicastMac(result.GatewayMac);
            bool gatewayMacChanged = baseline is not null && !string.IsNullOrWhiteSpace(baseline.GatewayMac)
                && gatewayMacValid && !string.Equals(NormalizeMac(baseline.GatewayMac), NormalizeMac(result.GatewayMac), StringComparison.OrdinalIgnoreCase);
            result.SafeChecks.Add(new NetworkDoctorFinding
            {
                Name = "Gateway ARP mapping",
                Status = !gatewayMacValid ? "INFO" : gatewayMacChanged ? "ALERT" : "PASS",
                Evidence = !gatewayMacValid
                    ? $"Windows ARP cache has no valid unicast hardware-address mapping for gateway {gateway}."
                    : gatewayMacChanged
                        ? $"Gateway {gateway} now resolves to {result.GatewayMac}; the saved mapping was {baseline!.GatewayMac}. Router replacement or network spoofing can cause this change; confirm with the network owner."
                        : $"Windows ARP cache maps gateway {gateway} to {result.GatewayMac}."
            });
        }

        bool dnsValid = result.DnsServers.Count > 0 && result.DnsServers.All(value => IPAddress.TryParse(value, out var ip)
            && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any) && !ip.IsIPv6Multicast);
        result.SafeChecks.Add(new NetworkDoctorFinding
        {
            Name = "DNS configuration",
            Status = result.DnsServers.Count == 0 ? "WARN" : dnsValid ? "PASS" : "WARN",
            Evidence = result.DnsServers.Count == 0 ? "Windows reports no DNS server for this adapter."
                : dnsValid ? $"Windows reports {string.Join(", ", result.DnsServers)}."
                : $"Windows reports an invalid or unusable DNS address: {string.Join(", ", result.DnsServers)}."
        });
        await MeasureDnsAsync(result, cancellationToken).ConfigureAwait(false);

        AddSecurityCheck(result);
        CompareSavedFingerprint(result, baseline, apPattern);
        if (baseline is null && !replaceFingerprint && result.FingerprintVerdict != "unavailable")
        {
            result.FingerprintVerdict = "first-seen";
            result.SafeChecks.Add(new NetworkDoctorFinding
            {
                Name = "Network fingerprint",
                Status = "INFO",
                Evidence = "This is the first recorded check for this SSID. Basic connection, route, DNS, and security checks are available; there is no earlier fingerprint to compare."
            });
        }
        else if (result.FingerprintVerdict == "matches")
        {
            result.SafeChecks.Add(new NetworkDoctorFinding { Name = "Network fingerprint", Status = "PASS", Evidence = "Gateway, DNS, security, and authorized access-point pattern match the saved fingerprint." });
        }
        else if (result.FingerprintVerdict == "changed")
        {
            result.SafeChecks.Add(new NetworkDoctorFinding
            {
                Name = "Network fingerprint",
                Status = "ALERT",
                Evidence = "Saved network details changed: " + string.Join("; ", result.FingerprintDifferences) + ". A change can be legitimate; verify it before trusting this connection."
            });
        }

        AddAutopsyFindings(result, sameBand);
        BuildConclusion(result);
        return result;
    }

    public static List<string> CompareFingerprint(NetworkDoctorCheck current, NetworkFingerprint? saved, IReadOnlyCollection<string> currentApPattern)
    {
        var differences = new List<string>();
        if (saved is null) return differences;
        Compare("BSSID", NormalizeMac(saved.Bssid), NormalizeMac(current.Bssid), differences);
        Compare("gateway IP", saved.GatewayIp, current.GatewayIp, differences);
        Compare("gateway MAC", NormalizeMac(saved.GatewayMac), NormalizeMac(current.GatewayMac), differences);
        Compare("security", saved.Security, current.Security, differences);
        Compare("cipher", saved.Cipher, current.Cipher, differences);
        Compare("DNS servers", NormalizeList(saved.DnsServers), NormalizeList(current.DnsServers), differences);
        Compare("authorized access-point pattern", NormalizeMacList(saved.AuthorizedApPattern), NormalizeMacList(currentApPattern), differences);
        return differences;
    }

    public static void MarkFingerprintReplaced(NetworkDoctorCheck check)
    {
        check.FingerprintVerdict = "matches";
        check.FingerprintDifferences.Clear();
        var fingerprintFinding = check.SafeChecks.FirstOrDefault(finding => finding.Name == "Network fingerprint");
        if (fingerprintFinding is not null)
        {
            fingerprintFinding.Status = "PASS";
            fingerprintFinding.Evidence = "The saved fingerprint was replaced with the currently connected network details at the operator's request.";
        }
        BuildConclusion(check);
    }

    public static int? SelectBestObservedChannel(IReadOnlyCollection<AccessPoint> accessPoints, string connectedBssid, int currentChannel)
    {
        var candidates = accessPoints
            .Where(ap => ap.Channel > 0 && ap.FrequencyMHz > 0 && ap.IsActiveInCurrentScan)
            .GroupBy(ap => ap.Channel)
            .Select(group => group.First())
            .ToList();
        if (candidates.Count < 2) return null;
        var current = accessPoints.FirstOrDefault(ap => string.Equals(NormalizeMac(ap.Bssid), NormalizeMac(connectedBssid), StringComparison.OrdinalIgnoreCase));
        if (current is null) return null;
        int currentScore = ChannelOverlapScore(current, accessPoints);
        var best = candidates
            .Select(candidate => new { candidate.Channel, Score = ChannelOverlapScore(candidate, accessPoints) })
            .OrderBy(candidate => candidate.Score)
            .ThenBy(candidate => candidate.Channel)
            .First();
        return best.Score < currentScore ? best.Channel : null;
    }

    private static int ChannelOverlapScore(AccessPoint candidate, IReadOnlyCollection<AccessPoint> accessPoints)
    {
        int halfWidth = Math.Max(10, candidate.ChannelWidth) / 2;
        return accessPoints
            .Where(ap => ap.IsActiveInCurrentScan && ap.FrequencyMHz > 0
                && !string.Equals(NormalizeMac(candidate.Bssid), NormalizeMac(ap.Bssid), StringComparison.OrdinalIgnoreCase))
            .Sum(ap => Math.Abs(candidate.FrequencyMHz - ap.FrequencyMHz) < halfWidth + Math.Max(10, ap.ChannelWidth) / 2
                ? Math.Max(1, (int)(ap.SignalQuality / 20)) : 0);
    }

    private static async Task MeasureGatewayAsync(IPAddress gateway, NetworkDoctorCheck result, CancellationToken cancellationToken)
    {
        var times = new List<long>(5);
        int lost = 0;
        for (int i = 0; i < 5; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(gateway, 450).WaitAsync(TimeSpan.FromMilliseconds(600), cancellationToken).ConfigureAwait(false);
                if (reply.Status == IPStatus.Success) times.Add(reply.RoundtripTime);
                else lost++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch { lost++; }
        }
        result.GatewayPacketLossPercent = lost * 20;
        if (times.Count > 0)
        {
            times.Sort();
            result.GatewayMedianMs = times[times.Count / 2];
        }
        result.SafeChecks.Add(new NetworkDoctorFinding
        {
            Name = "Gateway response",
            Status = times.Count == 0 ? "WARN" : lost > 0 || result.GatewayMedianMs > 100 ? "WARN" : "PASS",
            Evidence = times.Count == 0
                ? $"No ICMP echo replies from {gateway}; Windows or the router may block ping."
                : $"{times.Count}/5 replies; median {result.GatewayMedianMs:0} ms; {result.GatewayPacketLossPercent}% packet loss."
        });
    }

    private static async Task MeasureDnsAsync(NetworkDoctorCheck result, CancellationToken cancellationToken)
    {
        if (result.DnsServers.Count == 0) return;
        var started = DateTime.UtcNow;
        try
        {
            var addresses = await Dns.GetHostAddressesAsync("example.com", cancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(3), cancellationToken).ConfigureAwait(false);
            result.DnsLookupMs = (DateTime.UtcNow - started).TotalMilliseconds;
            result.SafeChecks.Add(new NetworkDoctorFinding
            {
                Name = "DNS lookup",
                Status = addresses.Length == 0 ? "WARN" : result.DnsLookupMs > 1000 ? "WARN" : "PASS",
                Evidence = addresses.Length == 0 ? "The system resolver returned no addresses for example.com."
                    : $"System resolver returned {addresses.Length} address(es) in {result.DnsLookupMs:0} ms. Windows may cache DNS responses, so this timing can be lower than a fresh upstream query."
            });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            result.SafeChecks.Add(new NetworkDoctorFinding { Name = "DNS lookup", Status = "WARN", Evidence = $"System resolver lookup failed or exceeded 3 seconds ({ex.GetType().Name})." });
        }
    }

    private static void AddSecurityCheck(NetworkDoctorCheck result)
    {
        string normalized = result.Security.ToUpperInvariant();
        string status = normalized.Contains("OPEN") || normalized.Contains("WEP") ? "ALERT"
            : normalized.Contains("WPA2") || normalized.Contains("WPA3") ? "PASS" : "INFO";
        result.SafeChecks.Add(new NetworkDoctorFinding
        {
            Name = "Wi-Fi security",
            Status = status,
            Evidence = result.Security == "Unknown" ? "Windows did not expose the connected access point's security details in the current scan."
                : $"Connected access point reports {result.Security} with {result.Cipher}."
        });
    }

    private static void CompareSavedFingerprint(NetworkDoctorCheck result, NetworkFingerprint? saved, IReadOnlyCollection<string> currentApPattern)
    {
        if (result.Security == "Unknown" || string.IsNullOrWhiteSpace(result.GatewayIp))
        {
            result.FingerprintVerdict = "unavailable";
            return;
        }
        if (saved is null)
        {
            result.FingerprintVerdict = "first-seen";
            return;
        }
        result.FingerprintDifferences = CompareFingerprint(result, saved, currentApPattern);
        result.FingerprintVerdict = result.FingerprintDifferences.Count == 0 ? "matches" : "changed";
    }

    private static void AddAutopsyFindings(NetworkDoctorCheck result, IReadOnlyCollection<AccessPoint> sameBand)
    {
        if (result.SignalDbm.HasValue)
        {
            string signal = result.SignalDbm >= -60 ? "strong" : result.SignalDbm >= -70 ? "fair" : "weak";
            result.SafeChecks.Add(new NetworkDoctorFinding { Name = "Signal", Status = result.SignalDbm >= -70 ? "PASS" : "WARN", Evidence = $"{signal} signal at {result.SignalDbm} dBm ({result.Signal})." });
        }
        else result.SafeChecks.Add(new NetworkDoctorFinding { Name = "Signal", Status = "INFO", Evidence = "The current scan has no signal reading for the connected BSSID." });

        result.SafeChecks.Add(new NetworkDoctorFinding
        {
            Name = "Channel overlap",
            Status = sameBand.Count < 2 ? "INFO" : result.RecommendedObservedChannel.HasValue ? "WARN" : "PASS",
            Evidence = sameBand.Count < 2
                ? "Not enough currently observed, approved access points on this band to compare channel overlap."
                : result.RecommendedObservedChannel is int channel
                    ? $"An approved access point is using channel {result.Channel}; channel {channel} had the lowest measured overlap among currently observed approved channels. This is an observation, not a regional channel plan."
                    : $"Compared the connected access point with {sameBand.Count - 1} currently observed, approved access point(s); no lower-overlap observed channel was found."
        });
    }

    private static void BuildConclusion(NetworkDoctorCheck result)
    {
        var warnings = result.SafeChecks.Count(check => check.Status is "WARN" or "ALERT");
        if (result.Status == "Unavailable")
        {
            result.Conclusion = result.Reason;
            result.Recommendation = "Connect to a Wi-Fi network, select its adapter, and run Check Network again.";
            return;
        }
        if (warnings > 0)
        {
            var first = result.SafeChecks.First(check => check.Status is "WARN" or "ALERT");
            result.Conclusion = $"Review needed: {first.Name.ToLowerInvariant()} needs attention.";
            result.Recommendation = first.Name switch
            {
                "Wi-Fi security" => "Use the network owner's router settings to enable WPA2-AES or WPA3.",
                "Gateway response" => "Check the router and Wi-Fi signal; some routers block ping, so compare with a wired or router-side check.",
                "DNS configuration" or "DNS lookup" => "Check the adapter's DNS configuration and confirm the configured resolver is reachable.",
                "Network fingerprint" => "Verify the listed changes with the network owner before trusting this connection.",
                "Channel overlap" => "If you manage this router, review its channel plan using current regional rules.",
                _ => "Check the displayed evidence and confirm the network configuration with its owner."
            };
            return;
        }
        result.Conclusion = "No issue was found in the checks Windows could perform for this connection.";
        result.Recommendation = "Keep the router firmware and Wi-Fi security settings current; run Check Network again if the connection changes.";
    }

    private static bool IsInSubnet(IPAddress gateway, string localIp, int prefixLength)
    {
        if (prefixLength is < 0 or > 32 || !IPAddress.TryParse(localIp, out var local) || local.AddressFamily != gateway.AddressFamily) return false;
        var gatewayBytes = gateway.GetAddressBytes();
        var localBytes = local.GetAddressBytes();
        int remaining = prefixLength;
        for (int index = 0; index < gatewayBytes.Length; index++)
        {
            int bits = Math.Clamp(remaining, 0, 8);
            byte mask = bits == 0 ? (byte)0 : (byte)(0xFF << (8 - bits));
            if ((gatewayBytes[index] & mask) != (localBytes[index] & mask)) return false;
            remaining -= bits;
        }
        return true;
    }

    private static string NormalizeMac(string? value) => string.IsNullOrWhiteSpace(value)
        ? string.Empty
        : string.Concat(value.Where(Uri.IsHexDigit)).ToUpperInvariant();
    private static string NormalizeMacList(IEnumerable<string>? values) => string.Join("|", (values ?? Array.Empty<string>())
        .Select(NormalizeMac).Where(value => value.Length > 0).Distinct().OrderBy(value => value, StringComparer.Ordinal));
    private static string FormatMac(string value)
    {
        string compact = NormalizeMac(value);
        return compact.Length == 12 ? string.Join(":", Enumerable.Range(0, 6).Select(index => compact.Substring(index * 2, 2))) : value;
    }
    private static bool IsValidUnicastMac(string value)
    {
        string compact = NormalizeMac(value);
        return compact.Length == 12 && compact != "000000000000"
            && byte.TryParse(compact[..2], System.Globalization.NumberStyles.HexNumber, null, out byte first)
            && (first & 0x01) == 0;
    }
    private static string NormalizeList(IEnumerable<string>? values) => string.Join("|", (values ?? Array.Empty<string>())
        .Select(value => value.Trim().ToUpperInvariant()).Where(value => value.Length > 0).Distinct().OrderBy(value => value, StringComparer.Ordinal));
    private static void Compare(string label, string expected, string actual, List<string> differences)
    {
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)) differences.Add($"{label} changed from {Display(expected)} to {Display(actual)}");
    }
    private static string Display(string value) => string.IsNullOrWhiteSpace(value) ? "not recorded" : value;
}
