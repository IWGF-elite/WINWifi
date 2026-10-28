using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Models;

namespace WinWiFi.Services;

public static class LocalNetworkService
{
    private static readonly (int Port, string Name, bool Risk, string Reason)[] ProbePorts =
    {
        (21, "FTP", true, "FTP may expose credentials without encryption."),
        (22, "SSH", false, ""), (23, "Telnet", true, "Telnet is an unencrypted remote-login service."),
        (53, "DNS", false, ""), (80, "HTTP", false, ""), (443, "HTTPS", false, ""),
        (445, "SMB", false, ""), (554, "RTSP", true, "RTSP may expose a camera or media stream."),
        (3389, "RDP", false, ""), (8080, "HTTP alternate", false, ""),
        (8443, "HTTPS alternate", false, ""), (9100, "JetDirect", false, "")
    };

    public static async Task<LocalNetworkInfo> ScanAsync(string? adapterId, CancellationToken cancellationToken = default)
    {
        var result = GetNetworkInfo(adapterId);
        if (result.Status != "Available") return result;

        var hosts = EnumerateHosts(result.LocalIp, result.PrefixLength).ToArray();
        if (hosts.Length > 4096)
        {
            result.Status = "Unavailable";
            result.Reason = "The selected subnet exceeds the safe 4,096-address discovery limit.";
            return result;
        }

        using var gate = new SemaphoreSlim(48);
        var replies = await Task.WhenAll(hosts.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 350).WaitAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                return reply.Status == IPStatus.Success ? reply : null;
            }
            catch { return null; }
            finally { gate.Release(); }
        })).ConfigureAwait(false);

        var online = replies
            .Where(reply => reply is not null && IsDiscoverableHost(reply.Address.ToString(), result.LocalIp, result.PrefixLength))
            .ToDictionary(reply => reply!.Address.ToString(), reply => reply!, StringComparer.OrdinalIgnoreCase);
        await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        var neighbors = ReadArpTable()
            .Where(pair => IsDiscoverableHost(pair.Key, result.LocalIp, result.PrefixLength)
                && !IsNonUnicastMac(pair.Value))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        var addresses = online.Keys.Concat(neighbors.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        string now = DateTimeOffset.UtcNow.ToString("O");
        using var portGate = new SemaphoreSlim(48);
        foreach (string ip in addresses)
        {
            neighbors.TryGetValue(ip, out string? mac);
            bool isOnline = online.ContainsKey(ip) || ip == result.GatewayIp;
            var device = new LanDeviceRecord
            {
                NetworkId = result.NetworkId,
                IpAddress = ip,
                MacAddress = mac ?? string.Empty,
                Vendor = mac is null ? "Unknown" : OuiLookupService.ResolveVendor(mac),
                IsRandomizedMac = mac is not null && OuiLookupService.IsLocallyAdministered(mac),
                IsOnline = isOnline,
                IsNew = true,
                PingTtl = online.TryGetValue(ip, out var pingReply) ? pingReply.Options?.Ttl : null,
                OsGuess = online.TryGetValue(ip, out pingReply)
                    ? (pingReply.Options?.Ttl is int ttl && ttl <= 64 ? "Low-confidence Unix-like TTL pattern"
                        : pingReply.Options?.Ttl is int ttl2 && ttl2 <= 128 ? "Low-confidence Windows-like TTL pattern"
                        : pingReply.Options?.Ttl is int ? "Low-confidence network-device TTL pattern" : "Unknown")
                    : "Unknown",
                FirstSeen = now,
                LastSeen = isOnline ? now : string.Empty,
                DeviceType = ip == result.GatewayIp ? "Gateway" : "Unknown"
            };
            device.Evidence.Add(online.ContainsKey(ip) ? "IPv4 ping response" : "Windows ARP cache entry; not confirmed online by ping");
            if (mac is not null) device.Evidence.Add("MAC address from Windows ARP cache");
            if (device.IsRandomizedMac) device.Evidence.Add("Locally administered MAC bit is set; this can indicate randomization");
            if (ip == result.GatewayIp) device.Evidence.Add("Default gateway for selected adapter");
            device.Hostname = await ResolveHostnameAsync(ip, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(device.Hostname)) device.Evidence.Add("Reverse DNS name");
            if (isOnline) device.OpenPorts = await ProbePortsAsync(ip, portGate, cancellationToken).ConfigureAwait(false);
            if (device.OpenPorts.Any(p => p.Port == 554))
            {
                if (device.DeviceType != "Gateway") device.DeviceType = "RTSP media endpoint";
                device.Evidence.Add("TCP port 554 responded");
            }
            else if (device.OpenPorts.Any(p => p.Port is 80 or 443 or 8080 or 8443))
            {
                if (device.DeviceType != "Gateway") device.DeviceType = "Web endpoint";
                device.Evidence.Add("HTTP/S TCP port responded");
            }
            else if (device.OpenPorts.Any(p => p.Port == 9100))
            {
                if (device.DeviceType != "Gateway") device.DeviceType = "Printer endpoint";
                device.Evidence.Add("TCP port 9100 responded");
            }
            result.Devices.Add(device);
        }

        result.Devices = result.Devices.OrderBy(d => ToUInt(IPAddress.Parse(d.IpAddress))).ToList();
        result.ScannedAt = now;
        return result;
    }

    public static LocalNetworkInfo GetNetworkInfo(string? adapterId)
    {
        if (string.IsNullOrWhiteSpace(adapterId))
            return new LocalNetworkInfo { Reason = "Select an active Wi-Fi adapter first." };

        var iface = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            n.OperationalStatus == OperationalStatus.Up
            && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
            && string.Equals(n.Id.Trim('{', '}'), adapterId.Trim().Trim('{', '}'), StringComparison.OrdinalIgnoreCase));
        if (iface is null)
            return new LocalNetworkInfo { AdapterId = adapterId, Reason = "Windows has no active IP interface for the selected Wi-Fi adapter." };

        var properties = iface.GetIPProperties();
        var address = properties.UnicastAddresses.FirstOrDefault(a =>
            a.Address.AddressFamily == AddressFamily.InterNetwork && a.IPv4Mask is not null);
        if (address is null)
            return new LocalNetworkInfo { AdapterId = adapterId, InterfaceName = iface.Name, Reason = "The selected adapter has no IPv4 address." };

        int prefix = address.IPv4Mask!.GetAddressBytes().Sum(b => System.Numerics.BitOperations.PopCount((uint)b));
        var networkBytes = address.Address.GetAddressBytes();
        var maskBytes = address.IPv4Mask.GetAddressBytes();
        for (int i = 0; i < networkBytes.Length; i++) networkBytes[i] &= maskBytes[i];

        return new LocalNetworkInfo
        {
            AdapterId = adapterId,
            InterfaceName = iface.Name,
            NetworkId = $"{new IPAddress(networkBytes)}/{prefix}",
            LocalIp = address.Address.ToString(),
            PrefixLength = prefix,
            GatewayIp = properties.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(g => g.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? string.Empty,
            DnsServers = properties.DnsAddresses.Select(d => d.ToString()).ToList(),
            Status = "Available"
        };
    }

    private static IEnumerable<IPAddress> EnumerateHosts(string address, int prefix)
    {
        if (prefix < 16 || prefix > 30) yield break;
        uint local = ToUInt(IPAddress.Parse(address));
        uint network = local & (uint.MaxValue << (32 - prefix));
        uint count = (1u << (32 - prefix)) - 2;
        for (uint offset = 1; offset <= count; offset++)
        {
            uint value = network + offset;
            if (value != local) yield return FromUInt(value);
        }
    }

    private static uint ToUInt(IPAddress ip) => BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray());
    private static IPAddress FromUInt(uint ip) => new(BitConverter.GetBytes(ip).Reverse().ToArray());
    public static bool IsDiscoverableHost(string candidate, string local, int prefix)
    {
        if (prefix < 1 || prefix > 30
            || !IPAddress.TryParse(candidate, out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork)
            return false;

        uint mask = uint.MaxValue << (32 - prefix);
        uint value = ToUInt(ip);
        uint network = ToUInt(IPAddress.Parse(local)) & mask;
        uint broadcast = network | ~mask;
        return value != network && value != broadcast && value != ToUInt(IPAddress.Parse(local))
            && (value & mask) == network;
    }

    private static bool IsNonUnicastMac(string mac)
    {
        string[] octets = mac.Split(':', '-');
        return octets.Length != 6
            || octets.All(part => part.Equals("FF", StringComparison.OrdinalIgnoreCase))
            || !byte.TryParse(octets[0], System.Globalization.NumberStyles.HexNumber, null, out byte first)
            || (first & 0x01) != 0;
    }

    private static Dictionary<string, string> ReadArpTable()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var process = Process.Start(new ProcessStartInfo("arp.exe", "-a")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
            });
            if (process is null) return result;
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(2000);
            foreach (Match match in Regex.Matches(output, @"(?m)^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(?:dynamic|static)\s*$"))
                result[match.Groups[1].Value] = match.Groups[2].Value.Replace('-', ':').ToUpperInvariant();
        }
        catch { }
        return result;
    }

    private static async Task<string> ResolveHostnameAsync(string ip, CancellationToken cancellationToken)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            return entry.HostName == ip ? string.Empty : entry.HostName;
        }
        catch { return string.Empty; }
    }

    private static async Task<List<LanOpenPort>> ProbePortsAsync(string ip, SemaphoreSlim gate, CancellationToken cancellationToken)
    {
        var open = new List<LanOpenPort>();
        var tasks = ProbePorts.Select(async item =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(ip, item.Port)
                    .WaitAsync(TimeSpan.FromMilliseconds(450), cancellationToken).ConfigureAwait(false);
                string banner = await ReadServiceBannerAsync(client, item.Port, ip, cancellationToken).ConfigureAwait(false);
                bool adminPage = banner.Contains("admin", StringComparison.OrdinalIgnoreCase)
                    || banner.Contains("management", StringComparison.OrdinalIgnoreCase)
                    || banner.Contains("login", StringComparison.OrdinalIgnoreCase);
                lock (open)
                    open.Add(new LanOpenPort
                    {
                        Port = item.Port,
                        Service = item.Name,
                        Banner = banner,
                        RiskFlag = item.Risk || adminPage,
                        RiskReason = item.Risk ? item.Reason : adminPage ? "The HTTP response indicates a possible administrative sign-in page; verify access controls." : string.Empty
                    });
            }
            catch { }
            finally { gate.Release(); }
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        return open.OrderBy(p => p.Port).ToList();
    }

    private static async Task<string> ReadServiceBannerAsync(TcpClient client, int port, string host, CancellationToken cancellationToken)
    {
        try
        {
            var stream = client.GetStream();
            if (port is 80 or 8080)
            {
                byte[] request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            }
            byte[] buffer = new byte[1024];
            int count = await stream.ReadAsync(buffer, cancellationToken).AsTask()
                .WaitAsync(TimeSpan.FromMilliseconds(350), cancellationToken).ConfigureAwait(false);
            return count <= 0 ? string.Empty : System.Text.Encoding.ASCII.GetString(buffer, 0, count)
                .Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).Take(4).Aggregate((a, b) => a + " | " + b);
        }
        catch { return string.Empty; }
    }
}
