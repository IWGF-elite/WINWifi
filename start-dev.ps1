# WinWiFi one-command dev start.
# Launches the native bridge (WinWiFi.CLI --bridge) and the Vite dev server,
# waits until the bridge health endpoint answers, then opens the dashboard in
# the default browser with the per-launch bridge token.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\start-dev.ps1
param(
    [int]$BridgePort = 38989,
    [int]$DevPort = 5173
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

# Put the bridge and the dev server into a Windows job object marked
# KILL_ON_JOB_CLOSE. Ctrl+C, closing the PowerShell window, or the script
# crashing then cannot leave a daemon sitting on port 38989 -- which is exactly
# the stale-bridge state that makes the next desktop or dev launch collide.
$devJob = $null
try {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public sealed class KillOnCloseJob : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public long Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private const uint KillOnClose = 0x2000;
    private const int ExtendedLimitInformation = 9;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint size);

    [DllImport("kernel32.dll")]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private readonly IntPtr _job;

    private KillOnCloseJob(IntPtr job) { _job = job; }

    public static KillOnCloseJob Create()
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var limits = new ExtendedLimits();
        limits.BasicLimitInformation.LimitFlags = KillOnClose;
        if (!SetInformationJobObject(job, ExtendedLimitInformation, ref limits, (uint)MarshalSize()))
        {
            CloseHandle(job);
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return new KillOnCloseJob(job);
    }

    private static int MarshalSize() { return Marshal.SizeOf(typeof(ExtendedLimits)); }

    public void Add(Process process)
    {
        if (_job != IntPtr.Zero && process != null) AssignProcessToJobObject(_job, process.Handle);
    }

    public void Dispose()
    {
        if (_job != IntPtr.Zero) CloseHandle(_job);
    }
}
'@ -ErrorAction Stop
    $devJob = [KillOnCloseJob]::Create()
} catch {
    Write-Host "Could not create the process job object: $($_.Exception.Message) -- Ctrl+C still cleans up." -ForegroundColor Yellow
    $devJob = $null
}

$bridgeProcess = $null
$devProcess = $null
try {
    Write-Host "== WinWiFi dev starter ==" -ForegroundColor Cyan
    Write-Host "Repo: $repoRoot"

    # 1) Native bridge in its own window so its log stays visible.
    Write-Host "Starting native bridge on 127.0.0.1:$BridgePort ..." -ForegroundColor Cyan
    $bridgeProcess = Start-Process -FilePath 'dotnet' `
        -ArgumentList @('run','--project','WinWiFi.CLI','--',"--bridge",'--port',"$BridgePort") `
        -WorkingDirectory $repoRoot -PassThru
    if ($null -eq $bridgeProcess) { throw 'Could not start the bridge process.' }
    if ($devJob) { $devJob.Add($bridgeProcess) }

    # 2) Wait for the bridge health endpoint. The per-launch token is written to
    #    %LOCALAPPDATA%\WinWiFi\bridge.token by the bridge itself at startup.
    $tokenFile = Join-Path $env:LOCALAPPDATA 'WinWiFi\bridge.token'
    $healthUrl = "http://127.0.0.1:$BridgePort/api/health"
    Write-Host "Waiting for bridge health check at $healthUrl ..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(120)
    $bridgeToken = $null
    $consecutive401 = 0
    while ((Get-Date) -lt $deadline) {
        if ($bridgeProcess.HasExited) { throw "The bridge process exited early (exit code $($bridgeProcess.ExitCode)). Another program may already be using port $BridgePort." }
        if (Test-Path $tokenFile) {
            $candidate = (Get-Content $tokenFile -Raw).Trim()
            if ($candidate.Length -gt 0) {
                try {
                    $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl `
                        -Headers @{ 'X-WinWiFi-Token' = $candidate } -TimeoutSec 2
                    if ($response.StatusCode -eq 200) {
                        $bridgeToken = $candidate
                        break
                    }
                } catch {
                    # Windows PowerShell 5.1 raises System.Net.WebException here while
                    # PowerShell 7 raises its own HTTP exception type, so read the
                    # status code from the response object instead of typing the catch.
                    $status = 0
                    if ($_.Exception.Response) {
                        try { $status = [int]$_.Exception.Response.StatusCode } catch { $status = 0 }
                    }
                    if ($status -eq 401) {
                        # 401 means this token does not match the listener on the port.
                        # If that persists, a different WinWiFi bridge owns the port.
                        $consecutive401++
                        if ($consecutive401 -ge 20) {
                            throw "Another WinWiFi bridge is already using port $BridgePort with a different token. Close its window (or press Ctrl+C in its terminal) and run start-dev.ps1 again."
                        }
                    }
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    if ($null -eq $bridgeToken) { throw "The bridge did not become healthy on port $BridgePort within 120 seconds." }
    Write-Host "Bridge is healthy (token accepted)." -ForegroundColor Green

    # 3) Vite dev server with the bridge token baked in as an env fallback, so a
    #    plain browser tab at 127.0.0.1:$DevPort authenticates without pasting
    #    anything. The URL below also carries ?token= as a second path.
    #    The npm dev script binds 127.0.0.1 only, so probe that address: on this
    #    PC "localhost" resolves to ::1 first and the request would never land.
    Write-Host "Starting Vite dev server on http://127.0.0.1:$DevPort ..." -ForegroundColor Cyan
    $env:VITE_WINWIFI_BRIDGE_TOKEN = $bridgeToken
    $devProcess = Start-Process -FilePath 'npm.cmd' `
        -ArgumentList @('run','dev','--','--port',"$DevPort",'--strictPort') `
        -WorkingDirectory $repoRoot -PassThru
    if ($devJob) { $devJob.Add($devProcess) }

    $viteUrl = "http://127.0.0.1:$DevPort"
    $deadline = (Get-Date).AddSeconds(60)
    $viteReady = $false
    while ((Get-Date) -lt $deadline) {
        if ($devProcess.HasExited) { throw "The Vite dev server exited early (port $DevPort may already be in use)." }
        try {
            $null = Invoke-WebRequest -UseBasicParsing -Uri $viteUrl -TimeoutSec 8
            $viteReady = $true
            break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $viteReady) { throw "The Vite dev server did not answer on $viteUrl within 60 seconds." }
    Write-Host "Dev server is up." -ForegroundColor Green

    # 4) Open the dashboard with the per-launch token.
    Start-Process "$viteUrl/?token=$bridgeToken"
    Write-Host ""
    Write-Host "Dashboard: $viteUrl (token supplied automatically)" -ForegroundColor Green
    Write-Host "Bridge:    http://127.0.0.1:$BridgePort (loopback only)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press Ctrl+C to stop both services." -ForegroundColor Yellow

    while (-not $bridgeProcess.HasExited -and -not $devProcess.HasExited) {
        Start-Sleep -Seconds 1
    }
    Write-Host "A service exited. Shutting down the other one ..." -ForegroundColor Yellow
}
finally {
    foreach ($proc in @($devProcess, $bridgeProcess)) {
        if ($null -ne $proc -and -not $proc.HasExited) {
            # 'dotnet run' and 'npm run dev' are launchers: stopping only the
            # launcher leaves the bridge or Vite holding its port for the next run.
            try { & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null } catch { }
        }
    }
    Remove-Item Env:VITE_WINWIFI_BRIDGE_TOKEN -ErrorAction SilentlyContinue
    if ($devJob) { $devJob.Dispose(); $devJob = $null }
    Write-Host "Dev starter finished." -ForegroundColor Cyan
}
