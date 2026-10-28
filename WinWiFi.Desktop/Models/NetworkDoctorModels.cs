using System;
using System.Collections.Generic;

namespace WinWiFi.Models;

public sealed class NetworkFingerprint
{
    public string ProjectId { get; set; } = string.Empty;
    public string Ssid { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public string GatewayIp { get; set; } = string.Empty;
    public string GatewayMac { get; set; } = string.Empty;
    public List<string> DnsServers { get; set; } = new();
    public string Security { get; set; } = string.Empty;
    public string Cipher { get; set; } = string.Empty;
    public List<string> AuthorizedApPattern { get; set; } = new();
    public string FirstSeenAt { get; set; } = string.Empty;
    public string LastSeenAt { get; set; } = string.Empty;
}

public sealed class NetworkDoctorCheck
{
    public string Status { get; set; } = "Unavailable";
    public string Reason { get; set; } = string.Empty;
    public string CheckedAt { get; set; } = DateTimeOffset.UtcNow.ToString("O");
    public string AdapterId { get; set; } = string.Empty;
    public string Ssid { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public string Signal { get; set; } = "N/A";
    public int? SignalDbm { get; set; }
    public int? Channel { get; set; }
    public string Band { get; set; } = "Unknown";
    public string Security { get; set; } = "Unknown";
    public string Cipher { get; set; } = "Unknown";
    public string GatewayIp { get; set; } = string.Empty;
    public string GatewayMac { get; set; } = string.Empty;
    public List<string> DnsServers { get; set; } = new();
    public double? GatewayMedianMs { get; set; }
    public int? GatewayPacketLossPercent { get; set; }
    public double? DnsLookupMs { get; set; }
    public int AuthorizedNeighborCount { get; set; }
    public List<int> ObservedAuthorizedChannels { get; set; } = new();
    public int? RecommendedObservedChannel { get; set; }
    public string FingerprintVerdict { get; set; } = "unavailable";
    public List<string> FingerprintDifferences { get; set; } = new();
    public List<NetworkDoctorFinding> SafeChecks { get; set; } = new();
    public string Conclusion { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
}

public sealed class NetworkDoctorFinding
{
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = "INFO";
    public string Evidence { get; set; } = string.Empty;
}

public sealed class NetworkDoctorRequest
{
    public string AdapterId { get; set; } = string.Empty;
    public bool ReplaceFingerprint { get; set; }
}
