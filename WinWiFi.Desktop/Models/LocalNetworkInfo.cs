using System.Collections.Generic;

namespace WinWiFi.Models;

public sealed class LocalNetworkInfo
{
    public string AdapterId { get; set; } = string.Empty;
    public string InterfaceName { get; set; } = string.Empty;
    public string NetworkId { get; set; } = string.Empty;
    public string LocalIp { get; set; } = string.Empty;
    public int PrefixLength { get; set; }
    public string GatewayIp { get; set; } = string.Empty;
    public List<string> DnsServers { get; set; } = new();
    public List<string> DhcpServers { get; set; } = new();
    public string Status { get; set; } = "Unavailable";
    public string Reason { get; set; } = string.Empty;
    public string ScannedAt { get; set; } = string.Empty;
    public string PortScanMode { get; set; } = "Common ports";
    public int PortsScanned { get; set; }
    public bool Cancelled { get; set; }
    public List<LanDeviceRecord> Devices { get; set; } = new();
}

public sealed class LanDeviceRecord
{
    public string NetworkId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Vendor { get; set; } = "Unknown";
    public string Hostname { get; set; } = string.Empty;
    public string DeviceType { get; set; } = "Unknown";
    public List<string> Evidence { get; set; } = new();
    public List<LanOpenPort> OpenPorts { get; set; } = new();
    public bool IsOnline { get; set; }
    public bool IsNew { get; set; }
    public bool IsKnown { get; set; }
    public bool IsRandomizedMac { get; set; }
    public int? PingTtl { get; set; }
    public string OsGuess { get; set; } = "Unknown";
    public string FirstSeen { get; set; } = string.Empty;
    public string LastSeen { get; set; } = string.Empty;
}

public sealed class LanOpenPort
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string Service { get; set; } = "Unknown";
    public bool RiskFlag { get; set; }
    public string RiskReason { get; set; } = string.Empty;
    public string Banner { get; set; } = string.Empty;
}
