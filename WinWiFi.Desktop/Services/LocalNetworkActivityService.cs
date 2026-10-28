using System.Diagnostics;
using System.Text.Json;
using WinWiFi.Models;

namespace WinWiFi.Services;

public static class LocalNetworkActivityService
{
    private const string Query = "$ErrorActionPreference='Stop'; $tcp=Get-NetTCPConnection | Select-Object @{n='Protocol';e={'TCP'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess; $udp=Get-NetUDPEndpoint | Select-Object @{n='Protocol';e={'UDP'}},LocalAddress,LocalPort,@{n='RemoteAddress';e={''}},@{n='RemotePort';e={0}},@{n='State';e={'Bound'}},OwningProcess; @($tcp)+@($udp) | ConvertTo-Json -Compress";

    public static async Task<LocalNetworkActivity> GetAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return new() { Reason = "Active connection ownership is available only on Windows." };

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("powershell.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", Query }
                }
            };
            process.Start();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(6));
            string json = await process.StandardOutput.ReadToEndAsync(timeout.Token).ConfigureAwait(false);
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                string error = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                return new() { Reason = string.IsNullOrWhiteSpace(error) ? "Windows did not return connection ownership data." : error.Trim() };
            }

            var result = new LocalNetworkActivity { Status = "Available", ObservedAt = DateTimeOffset.UtcNow.ToString("O") };
            using JsonDocument document = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "[]" : json);
            IEnumerable<JsonElement> rows = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToArray()
                : document.RootElement.ValueKind == JsonValueKind.Object ? new[] { document.RootElement } : Array.Empty<JsonElement>();
            foreach (JsonElement row in rows)
            {
                int pid = GetInt(row, "OwningProcess");
                string processName = "Unknown";
                try { processName = Process.GetProcessById(pid).ProcessName; } catch { }
                result.Connections.Add(new LocalConnectionRecord
                {
                    Protocol = GetString(row, "Protocol"),
                    LocalAddress = GetString(row, "LocalAddress"),
                    LocalPort = GetInt(row, "LocalPort"),
                    RemoteAddress = GetString(row, "RemoteAddress"),
                    RemotePort = GetInt(row, "RemotePort"),
                    State = NormalizeState(GetString(row, "Protocol"), GetString(row, "State")),
                    ProcessId = pid,
                    ProcessName = processName
                });
            }
            result.Connections = result.Connections
                .OrderBy(c => c.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                .ThenBy(c => c.RemotePort)
                .ThenBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return result;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new() { Reason = "Windows connection query exceeded the 6-second response limit." };
        }
        catch (Exception ex)
        {
            return new() { Reason = "Windows connection ownership query failed: " + ex.Message };
        }
    }

    private static string GetString(JsonElement row, string name) =>
        row.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : string.Empty;

    private static int GetInt(JsonElement row, string name) =>
        row.TryGetProperty(name, out var value) && value.TryGetInt32(out int result) ? result : 0;

    private static string NormalizeState(string protocol, string state)
    {
        if (!protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase)
            || !int.TryParse(state, out int code)) return state;
        return code switch
        {
            1 => "Closed", 2 => "Listen", 3 => "SynSent", 4 => "SynReceived",
            5 => "Established", 6 => "FinWait1", 7 => "FinWait2", 8 => "CloseWait",
            9 => "Closing", 10 => "LastAck", 11 => "TimeWait", 12 => "DeleteTcb",
            _ => $"Unknown ({code})"
        };
    }
}
