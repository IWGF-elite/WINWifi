namespace WinWiFi.Models;

public sealed class WalkSignalReading
{
    public string Id { get; set; } = string.Empty;
    public string ProjectId { get; set; } = string.Empty;
    public string Bssid { get; set; } = string.Empty;
    public string Ssid { get; set; } = string.Empty;
    public string LocationName { get; set; } = string.Empty;
    public int RssiDbm { get; set; }
    public uint SignalQuality { get; set; }
    public string CapturedAt { get; set; } = string.Empty;
}

public sealed class WalkSignalReadingRequest
{
    public string Bssid { get; set; } = string.Empty;
    public string Ssid { get; set; } = string.Empty;
    public string LocationName { get; set; } = string.Empty;
    public int RssiDbm { get; set; }
    public uint SignalQuality { get; set; }
}
