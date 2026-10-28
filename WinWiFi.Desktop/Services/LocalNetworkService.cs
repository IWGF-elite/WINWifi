using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using WinWiFi.Models;

namespace WinWiFi.Services;

public static class LocalNetworkService
{
    private sealed record SsdpDiscovery(string SearchTarget, string Server, string Location, string UniqueServiceName, string Hostname);

    private static readonly (int Port, string Name, bool Risk, string Reason)[] ProbePorts =
    {
        (21, "FTP", true, "FTP may expose credentials without encryption."),
        (22, "SSH", false, ""), (23, "Telnet", true, "Telnet is an unencrypted remote-login service."),
        (25, "SMTP", false, ""), (53, "DNS", false, ""), (80, "HTTP", false, ""),
        (110, "POP3", false, ""), (139, "NetBIOS session", false, ""), (143, "IMAP", false, ""),
        (443, "HTTPS", false, ""), (445, "SMB", false, ""), (554, "RTSP", true, "RTSP may expose a camera or media stream."),
        (631, "IPP", false, ""), (993, "IMAPS", false, ""), (995, "POP3S", false, ""),
        (1433, "Microsoft SQL Server", false, ""), (1883, "MQTT", false, ""), (3306, "MySQL", false, ""),
        (3389, "RDP", false, ""), (5000, "HTTP alternate", false, ""), (5357, "WSD", false, ""),
        (5900, "VNC", false, ""), (8008, "HTTP alternate", false, ""), (8080, "HTTP alternate", false, ""),
        (8443, "HTTPS alternate", false, ""), (8888, "HTTP alternate", false, ""),
        (9000, "HTTP alternate", false, ""), (9100, "JetDirect", false, "")
    };

    public static async Task<LocalNetworkInfo> ScanAsync(string? adapterId, CancellationToken cancellationToken = default, bool fullPortScan = false, int probesPerSecond = 100)
    {
        probesPerSecond = Math.Clamp(probesPerSecond, 1, 250);
        var result = GetNetworkInfo(adapterId);
        if (result.Status != "Available") return result;
        result.PortScanMode = fullPortScan ? $"Full TCP range (rate-limited to {probesPerSecond}/s)" : "Common ports";

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
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch { return null; }
            finally { gate.Release(); }
        })).ConfigureAwait(false);

        var online = replies
            .Where(reply => reply is not null && IsDiscoverableHost(reply.Address.ToString(), result.LocalIp, result.PrefixLength))
            .ToDictionary(reply => reply!.Address.ToString(), reply => reply!, StringComparer.OrdinalIgnoreCase);
        await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        var neighbors = ReadArpTableSnapshot()
            .Where(pair => IsDiscoverableHost(pair.Key, result.LocalIp, result.PrefixLength)
                && !IsNonUnicastMac(pair.Value))
            .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase);
        var ssdp = await DiscoverSsdpAsync(result.LocalIp, result.PrefixLength, cancellationToken).ConfigureAwait(false);
        var addresses = online.Keys.Concat(neighbors.Keys).Concat(ssdp.Keys).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var mdnsNames = await ResolveMdnsNamesAsync(
            online.Keys.Concat(ssdp.Keys).Distinct(StringComparer.OrdinalIgnoreCase), result.LocalIp, cancellationToken).ConfigureAwait(false);
        string now = DateTimeOffset.UtcNow.ToString("O");
        using var portGate = new SemaphoreSlim(48);
        var fullRangePacer = new ProbePacer(probesPerSecond);
        foreach (string ip in addresses)
        {
            neighbors.TryGetValue(ip, out string? mac);
            bool isOnline = online.ContainsKey(ip) || ssdp.ContainsKey(ip) || ip == result.GatewayIp;
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
                DeviceType = ip == result.GatewayIp ? "Gateway" : ssdp.TryGetValue(ip, out var ssdpInfo) ? GetSsdpDeviceType(ssdpInfo.SearchTarget) : "Unknown"
            };
            if (online.ContainsKey(ip)) device.Evidence.Add("IPv4 ping response");
            else if (ssdp.ContainsKey(ip)) device.Evidence.Add("SSDP multicast discovery response");
            else device.Evidence.Add("Windows ARP cache entry; not confirmed online by ping");
            if (mac is not null) device.Evidence.Add("MAC address from Windows ARP cache");
            if (device.IsRandomizedMac) device.Evidence.Add("Locally administered MAC bit is set; this can indicate randomization");
            if (ip == result.GatewayIp) device.Evidence.Add("Default gateway for selected adapter");
            if (ssdp.TryGetValue(ip, out ssdpInfo))
            {
                if (!string.IsNullOrWhiteSpace(ssdpInfo.SearchTarget)) device.Evidence.Add("SSDP target: " + ssdpInfo.SearchTarget);
                if (!string.IsNullOrWhiteSpace(ssdpInfo.Server)) device.Evidence.Add("SSDP server: " + ssdpInfo.Server);
                if (!string.IsNullOrWhiteSpace(ssdpInfo.Location)) device.Evidence.Add("UPnP description location: " + ssdpInfo.Location);
            }
            device.Hostname = await ResolveHostnameAsync(ip, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(device.Hostname)) device.Evidence.Add("Reverse DNS name");
            if (string.IsNullOrWhiteSpace(device.Hostname) && mdnsNames.TryGetValue(ip, out string? mdnsName))
            {
                device.Hostname = mdnsName;
                device.Evidence.Add("mDNS reverse PTR response");
            }
            if (string.IsNullOrWhiteSpace(device.Hostname))
            {
                var netBios = await ResolveNetBiosNameAsync(ip, cancellationToken).ConfigureAwait(false);
                device.Hostname = netBios.Name;
                device.Evidence.Add(netBios.Evidence);
            }
            if (string.IsNullOrWhiteSpace(device.Hostname) && ssdp.TryGetValue(ip, out ssdpInfo) && !string.IsNullOrWhiteSpace(ssdpInfo.Hostname))
            {
                device.Hostname = ssdpInfo.Hostname;
                device.Evidence.Add("Host name from SSDP description URL");
            }
            if (isOnline)
            {
                var probeResult = await ProbePortsAsync(ip, portGate, cancellationToken, fullPortScan, probesPerSecond, fullRangePacer).ConfigureAwait(false);
                device.OpenPorts = probeResult.OpenPorts;
                result.PortsScanned += probeResult.PortsScanned;
            }
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
            DhcpServers = OperatingSystem.IsWindows()
                ? properties.DhcpServerAddresses.Select(d => d.ToString()).ToList()
                : new List<string>(),
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

    public static Dictionary<string, string> ReadArpTableSnapshot()
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

    private static async Task<Dictionary<string, SsdpDiscovery>> DiscoverSsdpAsync(string localIp, int prefix, CancellationToken cancellationToken)
    {
        var discovered = new Dictionary<string, SsdpDiscovery>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.Bind(new IPEndPoint(IPAddress.Parse(localIp), 0));
            client.Ttl = 2;
            const string search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
            byte[] request = Encoding.ASCII.GetBytes(search);
            await client.SendAsync(request, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900), cancellationToken).ConfigureAwait(false);
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(1600);
            while (DateTime.UtcNow < deadline)
            {
                cancellationToken.ThrowIfCancellationRequested();
                TimeSpan remaining = deadline - DateTime.UtcNow;
                UdpReceiveResult packet;
                try { packet = await client.ReceiveAsync(cancellationToken).AsTask().WaitAsync(remaining, cancellationToken).ConfigureAwait(false); }
                catch (TimeoutException) { break; }

                string address = packet.RemoteEndPoint.Address.ToString();
                if (!IsDiscoverableHost(address, localIp, prefix)) continue;
                var headers = ParseHeaders(Encoding.UTF8.GetString(packet.Buffer));
                string target = Header(headers, "ST");
                string server = Header(headers, "SERVER");
                string location = Header(headers, "LOCATION");
                string usn = Header(headers, "USN");
                string hostname = string.Empty;
                if (Uri.TryCreate(location, UriKind.Absolute, out var uri) && !IPAddress.TryParse(uri.Host, out _))
                    hostname = uri.Host;
                if (target.Length > 0 || server.Length > 0 || location.Length > 0 || usn.Length > 0)
                    discovered[address] = new SsdpDiscovery(target, server, location, usn, hostname);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* SSDP is optional; keep the scan result honest and continue with available discovery sources. */ }
        return discovered;
    }

    private static Dictionary<string, string> ParseHeaders(string response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in response.Split('\n'))
        {
            int separator = line.IndexOf(':');
            if (separator <= 0) continue;
            string name = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();
            if (name.Length > 0 && value.Length > 0) headers[name] = value;
        }
        return headers;
    }

    private static string Header(Dictionary<string, string> headers, string name) =>
        headers.TryGetValue(name, out string? value) ? value : string.Empty;

    private static string GetSsdpDeviceType(string searchTarget)
    {
        if (searchTarget.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase)) return "UPnP gateway";
        if (searchTarget.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase)) return "Media renderer";
        if (searchTarget.Contains("MediaServer", StringComparison.OrdinalIgnoreCase)) return "Media server";
        if (searchTarget.Contains("Printer", StringComparison.OrdinalIgnoreCase)) return "Printer";
        if (searchTarget.Contains("Basic:", StringComparison.OrdinalIgnoreCase)) return "UPnP device";
        return "Unknown";
    }

    private static async Task<Dictionary<string, string>> ResolveMdnsNamesAsync(IEnumerable<string> addresses, string localIp, CancellationToken cancellationToken)
    {
        using var gate = new SemaphoreSlim(24);
        var results = await Task.WhenAll(addresses.Select(async ip =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return (Ip: ip, Name: await QueryMdnsReverseNameAsync(ip, localIp, cancellationToken).ConfigureAwait(false)); }
            finally { gate.Release(); }
        })).ConfigureAwait(false);
        return results.Where(item => !string.IsNullOrWhiteSpace(item.Name))
            .ToDictionary(item => item.Ip, item => item.Name, StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<string> QueryMdnsReverseNameAsync(string ip, string localIp, CancellationToken cancellationToken)
    {
        try
        {
            byte[] query = BuildMdnsReversePtrQuery(ip);
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.Bind(new IPEndPoint(IPAddress.Parse(localIp), 0));
            await client.SendAsync(query, new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353), cancellationToken).ConfigureAwait(false);
            var response = await client.ReceiveAsync(cancellationToken).AsTask()
                .WaitAsync(TimeSpan.FromMilliseconds(700), cancellationToken).ConfigureAwait(false);
            return ParseMdnsPtrResponse(response.Buffer);
        }
        catch (TimeoutException) { return string.Empty; }
        catch (OperationCanceledException) { throw; }
        catch { return string.Empty; }
    }

    private static byte[] BuildMdnsReversePtrQuery(string ip)
    {
        var address = IPAddress.Parse(ip).GetAddressBytes();
        var labels = new[] { address[3].ToString(), address[2].ToString(), address[1].ToString(), address[0].ToString(), "in-addr", "arpa" };
        var packet = new List<byte> { 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (string label in labels)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(label);
            packet.Add((byte)bytes.Length);
            packet.AddRange(bytes);
        }
        packet.Add(0);
        packet.Add(0); packet.Add(12); // PTR
        packet.Add(0x80); packet.Add(1); // IN class with the unicast-response request bit
        return packet.ToArray();
    }

    private static string ParseMdnsPtrResponse(byte[] packet)
    {
        if (packet.Length < 12) return string.Empty;
        int questions = ReadUInt16(packet, 4);
        int records = ReadUInt16(packet, 6) + ReadUInt16(packet, 8) + ReadUInt16(packet, 10);
        int offset = 12;
        for (int i = 0; i < questions; i++)
        {
            _ = ReadDnsName(packet, ref offset);
            offset += 4;
            if (offset > packet.Length) return string.Empty;
        }
        for (int i = 0; i < records; i++)
        {
            _ = ReadDnsName(packet, ref offset);
            if (offset + 10 > packet.Length) return string.Empty;
            int type = ReadUInt16(packet, offset);
            int dataLength = ReadUInt16(packet, offset + 8);
            int dataOffset = offset + 10;
            if (dataOffset + dataLength > packet.Length) return string.Empty;
            if (type == 12)
            {
                int targetOffset = dataOffset;
                string target = ReadDnsName(packet, ref targetOffset);
                if (target.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) return target.TrimEnd('.');
            }
            offset = dataOffset + dataLength;
        }
        return string.Empty;
    }

    private static int ReadUInt16(byte[] bytes, int offset) => (bytes[offset] << 8) | bytes[offset + 1];

    private static string ReadDnsName(byte[] packet, ref int offset)
    {
        var labels = new List<string>();
        int cursor = offset;
        int resumeOffset = -1;
        int hops = 0;
        while (cursor < packet.Length && hops++ < 128)
        {
            int length = packet[cursor++];
            if (length == 0)
            {
                if (resumeOffset < 0) resumeOffset = cursor;
                break;
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length) return string.Empty;
                int pointer = ((length & 0x3F) << 8) | packet[cursor++];
                if (resumeOffset < 0) resumeOffset = cursor;
                if (pointer >= packet.Length) return string.Empty;
                cursor = pointer;
                continue;
            }
            if ((length & 0xC0) != 0 || cursor + length > packet.Length) return string.Empty;
            labels.Add(Encoding.UTF8.GetString(packet, cursor, length));
            cursor += length;
        }
        offset = resumeOffset >= 0 ? resumeOffset : cursor;
        return string.Join('.', labels);
    }

    private sealed record NetBiosResult(string Name, string Evidence);

    private static async Task<NetBiosResult> ResolveNetBiosNameAsync(string ip, CancellationToken cancellationToken)
    {
        try
        {
            var start = new ProcessStartInfo("nbtstat.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-A");
            start.ArgumentList.Add(ip);
            using var process = Process.Start(start);
            if (process is null) return new(string.Empty, "NetBIOS query unavailable: Windows did not start nbtstat.exe.");
            Task<string> outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            try { await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromMilliseconds(900), cancellationToken).ConfigureAwait(false); }
            catch (TimeoutException) { process.Kill(entireProcessTree: true); return new(string.Empty, "NetBIOS query to UDP 137 timed out with no response."); }
            string output = await outputTask.ConfigureAwait(false);
            Match match = Regex.Match(output, @"(?im)^\s*([^\s<]+)\s+<00>\s+UNIQUE\b");
            if (match.Success) return new(match.Groups[1].Value, "NetBIOS name returned by Windows nbtstat query.");
            string detail = output.Split('\r', '\n').Select(line => line.Trim()).FirstOrDefault(line =>
                line.Contains("host not found", StringComparison.OrdinalIgnoreCase)
                || line.Contains("no response", StringComparison.OrdinalIgnoreCase)
                || line.Contains("timed out", StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
            return new(string.Empty, detail.Length > 0
                ? $"NetBIOS query returned no name: {detail}"
                : "NetBIOS query to UDP 137 returned no name response.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return new(string.Empty, $"NetBIOS query unavailable: {ex.Message}"); }
    }

    private sealed record PortProbeResult(List<LanOpenPort> OpenPorts, int PortsScanned);

    private sealed class ProbePacer
    {
        private readonly long _interval;
        private readonly object _sync = new();
        private long _next;

        public ProbePacer(int perSecond) => _interval = Math.Max(1, Stopwatch.Frequency / perSecond);

        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            long target;
            long now = Stopwatch.GetTimestamp();
            lock (_sync)
            {
                target = Math.Max(now, _next);
                _next = target + _interval;
            }
            if (target > now)
                await Task.Delay(TimeSpan.FromSeconds((target - now) / (double)Stopwatch.Frequency), cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<PortProbeResult> ProbePortsAsync(string ip, SemaphoreSlim gate, CancellationToken cancellationToken, bool fullPortScan, int probesPerSecond, ProbePacer fullRangePacer)
    {
        var open = new List<LanOpenPort>();
        if (!fullPortScan)
        {
            var tasks = ProbePorts.Select(async item =>
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try { await ProbeSinglePortAsync(ip, item.Port, item.Name, item.Risk, item.Reason, open, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch { }
                finally { gate.Release(); }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
            return new(open.OrderBy(p => p.Port).ToList(), ProbePorts.Length);
        }

        var pacer = new ProbePacer(probesPerSecond);
        int nextPort = 0;
        int scanned = 0;
        int workerCount = Math.Min(32, probesPerSecond);
        var fullTasks = Enumerable.Range(0, workerCount).Select(async _ =>
        {
            while (true)
            {
                int port = Interlocked.Increment(ref nextPort);
                if (port > 65535) return;
                await fullRangePacer.WaitAsync(cancellationToken).ConfigureAwait(false);
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    string name = ProbePorts.FirstOrDefault(item => item.Port == port).Name ?? "Unknown TCP service";
                    var known = ProbePorts.FirstOrDefault(item => item.Port == port);
                    await ProbeSinglePortAsync(ip, port, name, known.Risk, known.Reason, open, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch { }
                finally
                {
                    Interlocked.Increment(ref scanned);
                    gate.Release();
                }
            }
        });
        await Task.WhenAll(fullTasks).ConfigureAwait(false);
        return new(open.OrderBy(p => p.Port).ToList(), scanned);
    }

    private static async Task ProbeSinglePortAsync(string ip, int port, string service, bool risky, string riskReason, List<LanOpenPort> open, CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(ip, port).WaitAsync(TimeSpan.FromMilliseconds(500), cancellationToken).ConfigureAwait(false);
        string banner = await ReadServiceBannerAsync(client, port, ip, cancellationToken).ConfigureAwait(false);
        bool adminPage = IsAdministrativePage(banner);
        lock (open)
            open.Add(new LanOpenPort
            {
                Port = port,
                Service = service,
                Banner = banner,
                RiskFlag = risky || adminPage,
                RiskReason = risky ? riskReason : adminPage ? "The HTTP response indicates a possible administrative sign-in page; verify access controls." : string.Empty
            });
    }

    private static async Task<string> ReadServiceBannerAsync(TcpClient client, int port, string host, CancellationToken cancellationToken)
    {
        if (port is 443 or 8443)
            return await ReadTlsBannerAsync(client, host, cancellationToken).ConfigureAwait(false);

        try
        {
            var stream = client.GetStream();
            if (IsHttpPort(port))
            {
                byte[] request = System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            }
            else if (port == 554)
            {
                byte[] request = Encoding.ASCII.GetBytes("OPTIONS rtsp://" + host + "/ RTSP/1.0\r\nCSeq: 1\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            }

            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromMilliseconds(1200));
            byte[] buffer = new byte[1024];
            using var response = new System.IO.MemoryStream();
            while (response.Length < 4096)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, 4096 - (int)response.Length)), deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                response.Write(buffer, 0, count);
                string current = Encoding.Latin1.GetString(response.GetBuffer(), 0, (int)response.Length);
                int headerEnd = current.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (headerEnd >= 0 && current.Length - headerEnd > 256) break;
            }
            string text = Encoding.Latin1.GetString(response.GetBuffer(), 0, (int)response.Length);
            return string.Join(" | ", text.Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).Take(8));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return string.Empty; }
        catch { return string.Empty; }
    }

    private static bool IsHttpPort(int port) => port is 80 or 5000 or 8008 or 8080 or 8888 or 9000;

    private static bool IsAdministrativePage(string banner) =>
        banner.Contains("admin", StringComparison.OrdinalIgnoreCase)
        || banner.Contains("management", StringComparison.OrdinalIgnoreCase)
        || banner.Contains("login", StringComparison.OrdinalIgnoreCase)
        || banner.Contains("sign in", StringComparison.OrdinalIgnoreCase)
        || banner.Contains("password", StringComparison.OrdinalIgnoreCase)
        || banner.Contains("<form", StringComparison.OrdinalIgnoreCase);

    private static async Task<string> ReadTlsBannerAsync(TcpClient client, string host, CancellationToken cancellationToken)
    {
        try
        {
            SslPolicyErrors validationErrors = SslPolicyErrors.None;
            using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: true,
                (_, _, _, errors) => { validationErrors = errors; return true; });
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromMilliseconds(1800));
            await tls.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, deadline.Token).ConfigureAwait(false);
            X509Certificate? certificate = tls.RemoteCertificate;
            string certText = certificate is null ? "certificate unavailable"
                : "certificate name " + (certificate is X509Certificate2 certificate2
                    ? certificate2.GetNameInfo(X509NameType.SimpleName, forIssuer: false)
                    : certificate.Subject);
            string validation = validationErrors == SslPolicyErrors.None ? "certificate validation passed" : "certificate validation warnings: " + validationErrors;
            return $"TLS {tls.SslProtocol}; {certText}; {validation}";
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return "TLS handshake timed out"; }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested) { return "TLS handshake failed: " + ex.GetType().Name; }
    }
}
