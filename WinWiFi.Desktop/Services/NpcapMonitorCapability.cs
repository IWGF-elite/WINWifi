using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WinWiFi.Services;

/// <summary>
/// Performs a non-invasive Npcap monitor-mode capability probe. The probe opens no
/// capture and never injects frames: pcap_can_set_rfmon only asks the driver whether
/// the selected adapter can enter passive monitor mode.
/// </summary>
public static class NpcapMonitorCapability
{
    private const int PcapErrorBufferSize = 256;

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapIf
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pcap_findalldevs(out IntPtr allDevices, StringBuilder errorBuffer);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_freealldevs(IntPtr allDevices);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr pcap_create(string source, StringBuilder errorBuffer);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int pcap_can_set_rfmon(IntPtr handle);

    [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_close(IntPtr handle);

    public sealed class ProbeResult
    {
        public bool NpcapInstalled { get; init; }
        public bool AdapterExposed { get; init; }
        public bool MonitorModeSupported { get; init; }
        public string DeviceName { get; init; } = string.Empty;
        public string Reason { get; init; } = string.Empty;
    }

    public static ProbeResult ProbeAdapter(string adapterDescription)
    {
        if (!OperatingSystem.IsWindows())
            return new ProbeResult { Reason = "Npcap monitor-mode probing is available only on Windows." };

        try
        {
            if (!NativeLibrary.TryLoad("wpcap.dll", out var library))
                return new ProbeResult { Reason = "Npcap is not installed. Install Npcap with 802.11/raw Wi-Fi support to enable passive monitor-mode capture." };
            NativeLibrary.Free(library);

            var error = new StringBuilder(PcapErrorBufferSize);
            if (pcap_findalldevs(out var devices, error) != 0 || devices == IntPtr.Zero)
                return new ProbeResult { NpcapInstalled = true, Reason = $"Npcap is installed but could not enumerate capture adapters: {error}" };

            try
            {
                var target = Normalize(adapterDescription);
                for (var current = devices; current != IntPtr.Zero;)
                {
                    var device = Marshal.PtrToStructure<PcapIf>(current);
                    var name = Marshal.PtrToStringAnsi(device.Name) ?? string.Empty;
                    var description = Marshal.PtrToStringAnsi(device.Description) ?? string.Empty;
                    if (MatchesAdapter(target, Normalize(description), Normalize(name)))
                    {
                        error.Clear();
                        var handle = pcap_create(name, error);
                        if (handle == IntPtr.Zero)
                            return new ProbeResult { NpcapInstalled = true, AdapterExposed = true, DeviceName = name, Reason = $"Npcap exposed this adapter but refused a passive capture handle: {error}" };
                        try
                        {
                            var supported = pcap_can_set_rfmon(handle) == 1;
                            return new ProbeResult
                            {
                                NpcapInstalled = true,
                                AdapterExposed = true,
                                MonitorModeSupported = supported,
                                DeviceName = name,
                                Reason = supported
                                    ? "Npcap confirmed this adapter accepts passive monitor mode. Capture remains scope-gated and never injects traffic."
                                    : "Npcap can see this adapter, but its driver does not expose 802.11 monitor mode. Use an adapter/driver with raw 802.11 monitor support."
                            };
                        }
                        finally { pcap_close(handle); }
                    }
                    current = device.Next;
                }
                return new ProbeResult { NpcapInstalled = true, Reason = "Npcap is installed, but it does not expose the active Wi-Fi adapter as a capture device." };
            }
            finally { pcap_freealldevs(devices); }
        }
        catch (DllNotFoundException)
        {
            return new ProbeResult { Reason = "Npcap is not installed. Install Npcap with 802.11/raw Wi-Fi support to enable passive monitor-mode capture." };
        }
        catch (Exception ex)
        {
            return new ProbeResult { NpcapInstalled = true, Reason = $"Npcap capability probe failed: {ex.Message}" };
        }
    }

    private static bool MatchesAdapter(string target, string description, string deviceName) =>
        !string.IsNullOrEmpty(target) &&
        (description.Contains(target, StringComparison.OrdinalIgnoreCase) || target.Contains(description, StringComparison.OrdinalIgnoreCase) || deviceName.Contains(target, StringComparison.OrdinalIgnoreCase));

    private static string Normalize(string value) => new string(value.Where(char.IsLetterOrDigit).ToArray());
}
