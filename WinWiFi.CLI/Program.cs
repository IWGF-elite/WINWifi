using System.Text.Json;
using WinWiFi.Data;
using WinWiFi.Services;
using WinWiFi.Tests;

namespace WinWiFi;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        string command = args.FirstOrDefault()?.ToLowerInvariant() ?? "--help";
        switch (command)
        {
            case "--help":
            case "-h":
                PrintHelp();
                return 0;

            case "--test":
                return await RunSelfTestsAsync();

            case "--adapters":
                return await ListAdaptersAsync();

            case "--scan":
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("An adapter ID is required. Run --adapters first.");
                    return 2;
                }
                return await ScanAsync(args[1]);

            case "--bridge":
                return await RunBridgeAsync(ParsePort(args));

            default:
                Console.Error.WriteLine($"Unknown option: {args[0]}");
                PrintHelp();
                return 2;
        }
    }

    private static async Task<int> RunSelfTestsAsync()
    {
        var results = await new NativeSelfTests().RunAllTestsAsync();
        foreach (var result in results)
        {
            Console.WriteLine($"[{(result.Passed ? "PASS" : "FAIL")}] {result.TestId}: {result.Name} ({result.DurationMs} ms)");
            if (!result.Passed && !string.IsNullOrWhiteSpace(result.Details))
                Console.WriteLine($"       {result.Details}");
        }

        Console.WriteLine($"\n{results.Count(r => r.Passed)}/{results.Count} native checks passed.");
        return results.All(r => r.Passed) ? 0 : 1;
    }

    private static async Task<int> ListAdaptersAsync()
    {
        var analyzer = new SecurityAnalyzer();
        using var wifi = new NativeWifiService(analyzer);
        var adapters = await wifi.GetAdaptersAsync();
        Console.WriteLine(JsonSerializer.Serialize(adapters, new JsonSerializerOptions { WriteIndented = true }));
        return adapters.Count > 0 ? 0 : 1;
    }

    private static async Task<int> ScanAsync(string adapterId)
    {
        var analyzer = new SecurityAnalyzer();
        using var wifi = new NativeWifiService(analyzer);
        var networks = await wifi.ScanNetworksAsync(adapterId);
        Console.WriteLine(JsonSerializer.Serialize(networks, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"\nObserved {networks.Count} access point(s) from the Windows WLAN cache.");
        return 0;
    }

    private static async Task<int> RunBridgeAsync(int port)
    {
        var analyzer = new SecurityAnalyzer();
        using var wifi = new NativeWifiService(analyzer);
        var pcap = new PcapDissector();
        var reports = new ReportGenerator();
        using var storage = new SqliteStorageService();
        using var scanner = new WifiBackgroundScanner(wifi, analyzer, storage);
        await using var bridge = new HttpBridgeServer(port, wifi, analyzer, pcap, reports, storage, scanner);

        await bridge.StartAsync();
        Console.WriteLine($"WinWiFi bridge listening on http://127.0.0.1:{port}/. Press Ctrl+C to stop.");
        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stop.Cancel();
        };

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
        }
        catch (OperationCanceledException) { }
        return 0;
    }

    private static int ParsePort(string[] args)
    {
        int index = Array.FindIndex(args, arg => arg.Equals("--port", StringComparison.OrdinalIgnoreCase));
        if (index < 0) return 38989;
        if (index + 1 >= args.Length || !int.TryParse(args[index + 1], out int port) || port is < 1 or > 65535)
            throw new ArgumentException("--port must be followed by a number between 1 and 65535.");
        return port;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("WinWiFi native Windows tools");
        Console.WriteLine("  --help              Show this help");
        Console.WriteLine("  --test              Run native parser, WLAN, and SQLite self-checks");
        Console.WriteLine("  --adapters          List Windows WLAN adapters");
        Console.WriteLine("  --scan <adapterId>  Read access points from the Windows WLAN cache");
        Console.WriteLine("  --bridge [--port N] Run the localhost bridge for the dashboard");
    }
}
