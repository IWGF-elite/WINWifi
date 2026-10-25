$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $projectRoot "WinWiFi.Desktop\WinWiFi.Desktop.csproj"
$publishPath = Join-Path $projectRoot "publish\win-x64"

Push-Location $projectRoot
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    npm run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
}

dotnet publish $projectPath `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output $publishPath

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$dashboardPath = Join-Path $publishPath "dashboard"
New-Item -ItemType Directory -Force -Path $dashboardPath | Out-Null
Copy-Item -Path (Join-Path $projectRoot "dist\*") -Destination $dashboardPath -Recurse -Force

$webViewInstaller = Join-Path $publishPath "Install-WebView2Runtime.exe"
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $webViewInstaller
$signature = Get-AuthenticodeSignature -FilePath $webViewInstaller
if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
    Remove-Item -LiteralPath $webViewInstaller -Force
    throw "Downloaded WebView2 bootstrapper did not have a valid Microsoft signature."
}

Write-Host "WinWiFi is ready at $publishPath\WinWiFi.exe"
Write-Host "Keep the dashboard folder beside WinWiFi.exe when moving the app."
Write-Host "If WebView2 Runtime is missing, launch Install-WebView2Runtime.exe from this folder."
