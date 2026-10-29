using System.Diagnostics;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;

namespace WinWiFi.Services;

/// <summary>Checks published GitHub Releases and stages a verified in-place installer update.</summary>
public sealed class AppUpdateService : IDisposable
{
    private const string ReleaseApiUrl = "https://api.github.com/repos/IWGF-elite/WINWifi/releases/latest";
    private const string InstallerAssetName = "WinWiFi-Setup.exe";
    private const string ChecksumAssetName = "WinWiFi-Setup.exe.sha256";
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(12);
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Uri _releaseApi;
    private readonly Func<string, string, int, bool> _applyHelperLauncher;
    private readonly string _updatesDirectory;
    private readonly string _currentVersion;
    private readonly SemaphoreSlim _checkLock = new(1, 1);
    private readonly CancellationTokenSource _shutdown = new();
    private readonly object _stateLock = new();
    private UpdateSnapshot _snapshot;
    private string? _stagedInstallerPath;
    private string? _stagedSha256;
    private Task? _periodicTask;
    private int _disposed;

    public AppUpdateService(HttpClient? httpClient = null, Uri? releaseApi = null, string? updatesDirectory = null, string? currentVersion = null,
        Func<string, string, int, bool>? applyHelperLauncher = null)
    {
        _http = httpClient ?? new HttpClient();
        _ownsHttp = httpClient is null;
        _releaseApi = releaseApi ?? new Uri(ReleaseApiUrl);
        _applyHelperLauncher = applyHelperLauncher ?? LaunchApplyHelper;
        _updatesDirectory = Path.GetFullPath(updatesDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinWiFi", "Updates"));
        _currentVersion = NormalizeVersion(currentVersion ?? Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "0.0.0");
        _snapshot = new UpdateSnapshot("idle", _currentVersion, null, 0, false, null, null);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("WinWiFi-Security-Auditor/3.x");
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        LoadStagedUpdate();
    }

    public UpdateSnapshot GetStatus()
    {
        lock (_stateLock) return _snapshot;
    }

    public void Start()
    {
        if (_periodicTask is not null) return;
        _periodicTask = RunPeriodicChecksAsync(_shutdown.Token);
        if (GetStatus().State != "ready") _ = CheckNowAsync(_shutdown.Token);
    }

    public async Task<UpdateSnapshot> CheckNowAsync(CancellationToken cancellationToken = default)
    {
        if (!await _checkLock.WaitAsync(0, cancellationToken)) return GetStatus();
        try
        {
            SetStatus("checking", null, 0, false, null, null);
            using var response = await _http.GetAsync(_releaseApi, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                SetStatus("current", null, 0, false, null, DateTimeOffset.UtcNow);
                return GetStatus();
            }
            response.EnsureSuccessStatusCode();

            using var releaseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var release = await JsonDocument.ParseAsync(releaseStream, cancellationToken: cancellationToken);
            var root = release.RootElement;
            if (root.TryGetProperty("draft", out var draft) && draft.GetBoolean() ||
                root.TryGetProperty("prerelease", out var prerelease) && prerelease.GetBoolean())
            {
                SetStatus("current", null, 0, false, null, DateTimeOffset.UtcNow);
                return GetStatus();
            }

            string tag = root.TryGetProperty("tag_name", out var tagElement) ? tagElement.GetString() ?? "" : "";
            string latestVersion = NormalizeVersion(tag);
            if (!Version.TryParse(latestVersion, out var latest) || !Version.TryParse(_currentVersion, out var current))
                throw new InvalidDataException("The latest release has an invalid version tag.");
            if (latest <= current)
            {
                ClearStagedUpdate();
                SetStatus("current", latestVersion, 0, false, null, DateTimeOffset.UtcNow);
                return GetStatus();
            }

            var assets = root.GetProperty("assets").EnumerateArray().ToDictionary(
                asset => asset.GetProperty("name").GetString() ?? "",
                asset => asset.GetProperty("browser_download_url").GetString() ?? "",
                StringComparer.Ordinal);
            if (!assets.TryGetValue(InstallerAssetName, out string? installerUrl) ||
                !assets.TryGetValue(ChecksumAssetName, out string? checksumUrl) ||
                !Uri.TryCreate(installerUrl, UriKind.Absolute, out var installerUri) ||
                !Uri.TryCreate(checksumUrl, UriKind.Absolute, out var checksumUri) ||
                installerUri.Scheme != Uri.UriSchemeHttps || checksumUri.Scheme != Uri.UriSchemeHttps)
                throw new InvalidDataException("The latest release is missing the Windows installer or its SHA-256 file.");

            string expectedHash = ParseSha256Manifest(await _http.GetStringAsync(checksumUri, cancellationToken));
            string versionDirectory = Path.Combine(_updatesDirectory, latestVersion);
            Directory.CreateDirectory(versionDirectory);
            string finalPath = Path.Combine(versionDirectory, InstallerAssetName);
            string temporaryPath = finalPath + ".download";
            if (!await ExistingFileMatchesAsync(finalPath, expectedHash, cancellationToken))
            {
                SetStatus("downloading", latestVersion, 0, false, null, GetStatus().LastCheckedAt);
                using var installerResponse = await _http.GetAsync(installerUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                installerResponse.EnsureSuccessStatusCode();
                long? total = installerResponse.Content.Headers.ContentLength;
                await using (var source = await installerResponse.Content.ReadAsStreamAsync(cancellationToken))
                await using (var destination = new FileStream(temporaryPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
                {
                    byte[] buffer = new byte[81920];
                    long received = 0;
                    int read;
                    while ((read = await source.ReadAsync(buffer, cancellationToken)) > 0)
                    {
                        await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                        received += read;
                        int progress = total is > 0 ? (int)Math.Clamp(received * 100 / total.Value, 0, 99) : 0;
                        SetStatus("downloading", latestVersion, progress, false, null, GetStatus().LastCheckedAt);
                    }
                    await destination.FlushAsync(cancellationToken);
                }

                if (!await ExistingFileMatchesAsync(temporaryPath, expectedHash, cancellationToken))
                    throw new InvalidDataException("The downloaded installer did not match its published SHA-256 checksum.");
                File.Move(temporaryPath, finalPath, overwrite: true);
            }

            _stagedInstallerPath = finalPath;
            _stagedSha256 = expectedHash;
            PersistStagedUpdate(latestVersion, finalPath, expectedHash);
            SetStatus("ready", latestVersion, 100, true, null, DateTimeOffset.UtcNow);
            return GetStatus();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            SetStatus("idle", null, 0, false, null, GetStatus().LastCheckedAt);
            throw;
        }
        catch (Exception ex)
        {
            string latest = GetStatus().LatestVersion ?? "";
            SetStatus("error", latest, 0, false, ex.Message, DateTimeOffset.UtcNow);
            return GetStatus();
        }
        finally
        {
            _checkLock.Release();
        }
    }

    public bool DeferUntilNextLaunch()
    {
        if (!TryGetVerifiedStagedUpdate(out var path, out var hash) || string.IsNullOrEmpty(GetStatus().LatestVersion)) return false;
        try
        {
            Directory.CreateDirectory(_updatesDirectory);
            File.WriteAllText(DeferredMarkerPath, JsonSerializer.Serialize(new StagedUpdate(GetStatus().LatestVersion!, path, hash)));
            return true;
        }
        catch (Exception ex)
        {
            SetStatus("error", GetStatus().LatestVersion, 0, false, ex.Message, DateTimeOffset.UtcNow);
            return false;
        }
    }

    public bool StartApplyHelper(int parentProcessId)
    {
        if (!TryGetVerifiedStagedUpdate(out var path, out var hash)) return false;
        return _applyHelperLauncher(path, hash, parentProcessId);
    }

    private async Task RunPeriodicChecksAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(CheckInterval, cancellationToken);
                if (GetStatus().State != "ready") await CheckNowAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private bool TryGetVerifiedStagedUpdate(out string path, out string sha256)
    {
        path = _stagedInstallerPath ?? "";
        sha256 = _stagedSha256 ?? "";
        return IsCachePath(path) && RegexIsSha256(sha256) && File.Exists(path) &&
               string.Equals(ComputeSha256(path), sha256, StringComparison.OrdinalIgnoreCase);
    }

    private void LoadStagedUpdate()
    {
        try
        {
            if (!File.Exists(StagedMetadataPath)) return;
            var staged = JsonSerializer.Deserialize<StagedUpdate>(File.ReadAllText(StagedMetadataPath), JsonOptions);
            if (staged is null || string.IsNullOrWhiteSpace(staged.Version) || !IsCachePath(staged.InstallerPath) || !RegexIsSha256(staged.Sha256) ||
                !File.Exists(staged.InstallerPath) || !string.Equals(ComputeSha256(staged.InstallerPath), staged.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                ClearStagedUpdate();
                return;
            }
            if (Version.TryParse(NormalizeVersion(staged.Version), out var stagedVersion) &&
                Version.TryParse(_currentVersion, out var currentVersion) && stagedVersion <= currentVersion)
            {
                ClearStagedUpdate();
                return;
            }
            _stagedInstallerPath = staged.InstallerPath;
            _stagedSha256 = staged.Sha256;
            SetStatus("ready", staged.Version, 100, true, null, null);
        }
        catch { ClearStagedUpdate(); }
    }

    private void PersistStagedUpdate(string version, string path, string hash)
    {
        Directory.CreateDirectory(_updatesDirectory);
        File.WriteAllText(StagedMetadataPath, JsonSerializer.Serialize(new StagedUpdate(version, path, hash)));
    }

    private void ClearStagedUpdate()
    {
        _stagedInstallerPath = null;
        _stagedSha256 = null;
        try { if (File.Exists(StagedMetadataPath)) File.Delete(StagedMetadataPath); } catch { }
        try { if (File.Exists(DeferredMarkerPath)) File.Delete(DeferredMarkerPath); } catch { }
    }

    private bool IsCachePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full = Path.GetFullPath(path);
        string prefix = Path.GetFullPath(_updatesDirectory) + Path.DirectorySeparatorChar;
        return full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) &&
               Path.GetFileName(full).StartsWith("WinWiFi-Setup", StringComparison.OrdinalIgnoreCase);
    }

    private string StagedMetadataPath => Path.Combine(_updatesDirectory, "ready.json");
    private string DeferredMarkerPath => Path.Combine(_updatesDirectory, "apply-next-launch.json");

    internal static string NormalizeVersion(string value) => value.Trim().TrimStart('v', 'V');

    internal static string ParseSha256Manifest(string text)
    {
        var match = System.Text.RegularExpressions.Regex.Match(text, @"(?i)\b([0-9a-f]{64})\b");
        if (!match.Success) throw new InvalidDataException("The release SHA-256 file is malformed.");
        return match.Groups[1].Value.ToLowerInvariant();
    }

    internal static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static bool RegexIsSha256(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);

    private static async Task<bool> ExistingFileMatchesAsync(string path, string expectedHash, CancellationToken token) =>
        File.Exists(path) && string.Equals(await Task.Run(() => ComputeSha256(path), token), expectedHash, StringComparison.OrdinalIgnoreCase);

    private void SetStatus(string state, string? latest, int progress, bool ready, string? error, DateTimeOffset? checkedAt)
    {
        lock (_stateLock) _snapshot = new UpdateSnapshot(state, _currentVersion, latest, progress, ready, error, checkedAt);
    }

    private static bool LaunchApplyHelper(string installerPath, string sha256, int parentProcessId)
    {
        string? appExecutable = Environment.ProcessPath;
        string runnerSource = Path.Combine(AppContext.BaseDirectory, "WinWiFi.UpdateRunner.exe");
        if (string.IsNullOrWhiteSpace(appExecutable) || !File.Exists(appExecutable) || !File.Exists(runnerSource)) return false;
        try
        {
            string runnerPath = Path.Combine(Path.GetDirectoryName(installerPath)!, "WinWiFi.UpdateRunner.exe");
            File.Copy(runnerSource, runnerPath, overwrite: true);
            var start = new ProcessStartInfo(runnerPath)
            {
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Path.GetDirectoryName(runnerPath)!
            };
            start.ArgumentList.Add(installerPath);
            start.ArgumentList.Add(sha256);
            start.ArgumentList.Add(parentProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.ArgumentList.Add(appExecutable);
            return Process.Start(start) is not null;
        }
        catch { return false; }
    }

    /// <summary>Called from Program.Main before WPF starts; silently applies a user-deferred package.</summary>
    public static bool TryStartDeferredApply(string executablePath, int parentProcessId)
    {
        string root = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinWiFi", "Updates"));
        string marker = Path.Combine(root, "apply-next-launch.json");
        try
        {
            if (!File.Exists(marker)) return false;
            var update = JsonSerializer.Deserialize<StagedUpdate>(File.ReadAllText(marker), JsonOptions);
            if (update is null) { File.Delete(marker); return false; }
            string path = Path.GetFullPath(update.InstallerPath);
            string prefix = root + Path.DirectorySeparatorChar;
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(path).StartsWith("WinWiFi-Setup", StringComparison.OrdinalIgnoreCase) ||
                !RegexIsSha256(update.Sha256) || !File.Exists(path) || !string.Equals(ComputeSha256(path), update.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(marker);
                return false;
            }
            string? originalExecutable = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(executablePath) && File.Exists(executablePath)) originalExecutable = executablePath;
            if (string.IsNullOrWhiteSpace(originalExecutable)) return false;
            string runnerSource = Path.Combine(AppContext.BaseDirectory, "WinWiFi.UpdateRunner.exe");
            if (!File.Exists(runnerSource)) return false;
            string runnerPath = Path.Combine(Path.GetDirectoryName(path)!, "WinWiFi.UpdateRunner.exe");
            File.Copy(runnerSource, runnerPath, overwrite: true);
            var start = new ProcessStartInfo(runnerPath)
            {
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Path.GetDirectoryName(runnerPath)!
            };
            start.ArgumentList.Add(path);
            start.ArgumentList.Add(update.Sha256);
            start.ArgumentList.Add(parentProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            start.ArgumentList.Add(originalExecutable);
            return Process.Start(start) is not null;
        }
        catch
        {
            try { File.Delete(marker); } catch { }
            return false;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _shutdown.Cancel();
        _shutdown.Dispose();
        if (_ownsHttp) _http.Dispose();
    }

    private sealed record StagedUpdate(string Version, string InstallerPath, string Sha256);
}

public sealed record UpdateSnapshot(string State, string CurrentVersion, string? LatestVersion, int ProgressPercent,
    bool IsUpdateReady, string? Error, DateTimeOffset? LastCheckedAt);
