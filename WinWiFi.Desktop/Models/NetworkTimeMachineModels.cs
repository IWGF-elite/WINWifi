using System.Collections.Generic;

namespace WinWiFi.Models;

public sealed class NetworkTimelineEvent
{
    public string Id { get; set; } = string.Empty;
    public string ProjectId { get; set; } = string.Empty;
    public string OccurredAt { get; set; } = string.Empty;
    public string EntityType { get; set; } = string.Empty;
    public string EntityKey { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string BeforeStateJson { get; set; } = "{}";
    public string AfterStateJson { get; set; } = "{}";
}

public sealed class NetworkTimelineBounds
{
    public bool HasData { get; set; }
    public string? EarliestAt { get; set; }
    public string? LatestAt { get; set; }
    public int ChangeCount { get; set; }
    public int LegacyObservationCount { get; set; }
    public string Message { get; set; } = string.Empty;
}

public sealed class NetworkTimelineState
{
    public bool HasData { get; set; }
    public string AsOf { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public List<NetworkTimelineEntityState> AccessPoints { get; set; } = new();
    public List<NetworkTimelineEntityState> Devices { get; set; } = new();
    public List<NetworkTimelineEvent> Changes { get; set; } = new();
}

public sealed class NetworkTimelineEntityState
{
    public string EntityType { get; set; } = string.Empty;
    public string EntityKey { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public string Ssid { get; set; } = string.Empty;
    public int? Channel { get; set; }
    public string Band { get; set; } = string.Empty;
    public int? FrequencyMhz { get; set; }
    public int? Rssi { get; set; }
    public uint? SignalQuality { get; set; }
    public string Security { get; set; } = string.Empty;
    public string Cipher { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public int? ChannelWidth { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string DeviceType { get; set; } = string.Empty;
    public bool IsOnline { get; set; }
    public bool IsPresent { get; set; }
    public string FirstSeenAt { get; set; } = string.Empty;
    public string LastSeenAt { get; set; } = string.Empty;
}
