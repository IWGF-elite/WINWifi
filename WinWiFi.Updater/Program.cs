using System.Diagnostics;
using System.Security.Cryptography;

namespace WinWiFi.Updater;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 4 || !int.TryParse(args[2], out int parentPid) || !IsSha256(args[1])) return 2;

        string updateRoot = Path.GetFullPath(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinWiFi", "Updates"));
        string installerPath;
        string appPath;
        try
        {
            installerPath = Path.GetFullPath(args[0]);
            appPath = Path.GetFullPath(args[3]);
        }
        catch { return 2; }

        string updatePrefix = updateRoot + Path.DirectorySeparatorChar;
        if (!installerPath.StartsWith(updatePrefix, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(installerPath).StartsWith("WinWiFi-Setup", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(appPath), "WinWiFi.exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(installerPath) || !File.Exists(appPath)) return 2;

        try
        {
            if (!string.Equals(ComputeSha256(installerPath), args[1], StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The staged update checksum no longer matches.");

            if (parentPid != Environment.ProcessId)
            {
                try
                {
                    using var parent = Process.GetProcessById(parentPid);
                    if (!parent.WaitForExit(120_000)) throw new TimeoutException("WinWiFi did not close in time; the update was skipped.");
                }
                catch (ArgumentException) { /* The application already exited. */ }
            }

            using var installer = Process.Start(new ProcessStartInfo(installerPath,
                "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS")
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(installerPath)!
            });
            installer?.WaitForExit();
            if (installer is null || installer.ExitCode != 0)
                throw new InvalidOperationException($"The installer ended with code {installer?.ExitCode.ToString() ?? "no process"}.");

            try { File.Delete(Path.Combine(updateRoot, "apply-next-launch.json")); } catch { }
            WriteLog("The in-place update completed successfully.");
        }
        catch (Exception ex)
        {
            WriteLog($"The update could not be applied: {ex.Message}");
            try { File.Delete(Path.Combine(updateRoot, "apply-next-launch.json")); } catch { }
        }

        try
        {
            Process.Start(new ProcessStartInfo(appPath)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(appPath)!
            });
        }
        catch (Exception ex) { WriteLog($"WinWiFi could not be restarted: {ex.Message}"); }
        return 0;
    }

    private static bool IsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void WriteLog(string message)
    {
        try
        {
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinWiFi");
            Directory.CreateDirectory(directory);
            File.AppendAllText(Path.Combine(directory, "updater.log"), $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
        }
        catch { }
    }
}
