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

    # 2) Wait for the bridge health endpoint. The per-launch token is written to
    #    %LOCALAPPDATA%\WinWiFi\bridge.token by the bridge itself at startup.
    $tokenFile = Join-Path $env:LOCALAPPDATA 'WinWiFi\bridge.token'
    $healthUrl = "http://127.0.0.1:$BridgePort/api/health"
    Write-Host "Waiting for bridge health check at $healthUrl ..." -ForegroundColor Cyan
    $deadline = (Get-Date).AddSeconds(120)
    $bridgeToken = $null
    while ((Get-Date) -lt $deadline) {
        if ($bridgeProcess.HasExited) { throw "The bridge process exited early (exit code $($bridgeProcess.ExitCode)). Check the dotnet build output above." }
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
                } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
                    # 401 means the token file is stale from a previous launch;
                    # keep polling until this launch overwrites it.
                } catch {
                    Start-Sleep -Milliseconds 500
                }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    if ($null -eq $bridgeToken) { throw "The bridge did not become healthy on port $BridgePort within 120 seconds." }
    Write-Host "Bridge is healthy (token accepted)." -ForegroundColor Green

    # 3) Vite dev server with the bridge token baked in as an env fallback, so a
    #    plain browser tab at localhost:$DevPort authenticates without pasting
    #    anything. The URL below also carries ?token= as a second path.
    Write-Host "Starting Vite dev server on http://localhost:$DevPort ..." -ForegroundColor Cyan
    $env:VITE_WINWIFI_BRIDGE_TOKEN = $bridgeToken
    $devProcess = Start-Process -FilePath 'npm.cmd' `
        -ArgumentList @('run','dev','--','--port',"$DevPort",'--strictPort') `
        -WorkingDirectory $repoRoot -PassThru

    $viteUrl = "http://localhost:$DevPort"
    $deadline = (Get-Date).AddSeconds(60)
    $viteReady = $false
    while ((Get-Date) -lt $deadline) {
        if ($devProcess.HasExited) { throw "The Vite dev server exited early (port $DevPort may already be in use)." }
        try {
            $null = Invoke-WebRequest -UseBasicParsing -Uri $viteUrl -TimeoutSec 2
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
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
    Remove-Item Env:VITE_WINWIFI_BRIDGE_TOKEN -ErrorAction SilentlyContinue
    Write-Host "Dev starter finished." -ForegroundColor Cyan
}
