namespace WinWiFi.Models;

public sealed class LocalNetworkActivity
{
    public string Status { get; set; } = "Unavailable";
    public string Reason { get; set; } = string.Empty;
    public string ObservedAt { get; set; } = string.Empty;
    public string TrafficBytesStatus { get; set; } = "Windows does not expose per-process byte totals through this view.";
    public List<LocalConnectionRecord> Connections { get; set; } = new();
}

public sealed class LocalConnectionRecord
{
    public string Protocol { get; set; } = string.Empty;
    public string LocalAddress { get; set; } = string.Empty;
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = "Unknown";
}
