using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using WinWiFi.Models;

namespace WinWiFi.Services;

public static class LocalNetworkActivityService
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ErrorNoData = 232;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp4RowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp4RowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddress;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningProcessId;
    }

    private delegate uint TableQuery(IntPtr table, ref uint size);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, bool sort, int addressFamily, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size, bool sort, int addressFamily, int tableClass, uint reserved);

    public static Task<LocalNetworkActivity> GetAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(new LocalNetworkActivity { Reason = "Active connection ownership is available only on Windows." });

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = new LocalNetworkActivity { Status = "Available", ObservedAt = DateTimeOffset.UtcNow.ToString("O") };
            var processNames = new Dictionary<int, string>();

            foreach (var row in ReadTable<MibTcp4RowOwnerPid>(QueryTcp4))
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Connections.Add(new LocalConnectionRecord
                {
                    Protocol = "TCP",
                    LocalAddress = AddressFromNative(row.LocalAddress),
                    LocalPort = PortFromNative(row.LocalPort),
                    RemoteAddress = AddressFromNative(row.RemoteAddress),
                    RemotePort = PortFromNative(row.RemotePort),
                    State = TcpStateName(row.State),
                    ProcessId = (int)row.OwningProcessId,
                    ProcessName = ResolveProcessName((int)row.OwningProcessId, processNames)
                });
            }

            foreach (var row in ReadTable<MibTcp6RowOwnerPid>(QueryTcp6))
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Connections.Add(new LocalConnectionRecord
                {
                    Protocol = "TCP",
                    LocalAddress = AddressFromNative(row.LocalAddress, row.LocalScopeId),
                    LocalPort = PortFromNative(row.LocalPort),
                    RemoteAddress = AddressFromNative(row.RemoteAddress, row.RemoteScopeId),
                    RemotePort = PortFromNative(row.RemotePort),
                    State = TcpStateName(row.State),
                    ProcessId = (int)row.OwningProcessId,
                    ProcessName = ResolveProcessName((int)row.OwningProcessId, processNames)
                });
            }

            foreach (var row in ReadTable<MibUdp4RowOwnerPid>(QueryUdp4))
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Connections.Add(new LocalConnectionRecord
                {
                    Protocol = "UDP",
                    LocalAddress = AddressFromNative(row.LocalAddress),
                    LocalPort = PortFromNative(row.LocalPort),
                    State = "Bound",
                    ProcessId = (int)row.OwningProcessId,
                    ProcessName = ResolveProcessName((int)row.OwningProcessId, processNames)
                });
            }

            foreach (var row in ReadTable<MibUdp6RowOwnerPid>(QueryUdp6))
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Connections.Add(new LocalConnectionRecord
                {
                    Protocol = "UDP",
                    LocalAddress = AddressFromNative(row.LocalAddress, row.LocalScopeId),
                    LocalPort = PortFromNative(row.LocalPort),
                    State = "Bound",
                    ProcessId = (int)row.OwningProcessId,
                    ProcessName = ResolveProcessName((int)row.OwningProcessId, processNames)
                });
            }

            result.Connections = result.Connections
                .OrderBy(connection => connection.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                .ThenBy(connection => connection.RemotePort)
                .ThenBy(connection => connection.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return Task.FromResult(result);
        }
        catch (OperationCanceledException)
        {
            return Task.FromResult(new LocalNetworkActivity { Reason = "Windows connection data request was cancelled." });
        }
        catch (Exception ex)
        {
            return Task.FromResult(new LocalNetworkActivity { Reason = "Windows connection ownership query failed: " + ex.Message });
        }
    }

    private static uint QueryTcp4(IntPtr table, ref uint size) =>
        GetExtendedTcpTable(table, ref size, true, AfInet, TcpTableOwnerPidAll, 0);

    private static uint QueryTcp6(IntPtr table, ref uint size) =>
        GetExtendedTcpTable(table, ref size, true, AfInet6, TcpTableOwnerPidAll, 0);

    private static uint QueryUdp4(IntPtr table, ref uint size) =>
        GetExtendedUdpTable(table, ref size, true, AfInet, UdpTableOwnerPid, 0);

    private static uint QueryUdp6(IntPtr table, ref uint size) =>
        GetExtendedUdpTable(table, ref size, true, AfInet6, UdpTableOwnerPid, 0);

    private static List<T> ReadTable<T>(TableQuery query) where T : struct
    {
        uint size = 0;
        uint status = query(IntPtr.Zero, ref size);
        if (status == ErrorNoData) return new List<T>();
        if (status != ErrorInsufficientBuffer && status != 0)
            throw new Win32Exception((int)status, "Windows could not read the local connection table.");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (size < sizeof(uint)) size = sizeof(uint);
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
            try
            {
                status = query(buffer, ref size);
                if (status == ErrorNoData) return new List<T>();
                if (status == ErrorInsufficientBuffer) continue;
                if (status != 0)
                    throw new Win32Exception((int)status, "Windows could not read the local connection table.");

                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<T>();
                int maxRows = (checked((int)size) - sizeof(uint)) / rowSize;
                if (count < 0 || count > maxRows)
                    throw new InvalidDataException("Windows returned an invalid connection-table size.");

                var rows = new List<T>(count);
                IntPtr rowAddress = IntPtr.Add(buffer, sizeof(uint));
                for (int index = 0; index < count; index++)
                {
                    rows.Add(Marshal.PtrToStructure<T>(rowAddress));
                    rowAddress = IntPtr.Add(rowAddress, rowSize);
                }
                return rows;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        throw new InvalidOperationException("Windows connection table changed repeatedly while it was being read.");
    }

    private static string AddressFromNative(uint address) => new IPAddress(BitConverter.GetBytes(address)).ToString();

    private static string AddressFromNative(byte[]? address, uint scopeId)
    {
        if (address is null || address.Length != 16) return string.Empty;
        var parsed = new IPAddress(address, scopeId);
        return parsed.ToString();
    }

    private static int PortFromNative(uint port) =>
        unchecked((ushort)IPAddress.NetworkToHostOrder((short)port));

    private static string ResolveProcessName(int processId, IDictionary<int, string> cache)
    {
        if (cache.TryGetValue(processId, out string? name)) return name;
        try { name = Process.GetProcessById(processId).ProcessName; }
        catch { name = "Unknown"; }
        cache[processId] = name;
        return name;
    }

    private static string TcpStateName(uint state) => state switch
    {
        1 => "Closed", 2 => "Listen", 3 => "SynSent", 4 => "SynReceived",
        5 => "Established", 6 => "FinWait1", 7 => "FinWait2", 8 => "CloseWait",
        9 => "Closing", 10 => "LastAck", 11 => "TimeWait", 12 => "DeleteTcb",
        _ => $"Unknown ({state})"
    };
}
