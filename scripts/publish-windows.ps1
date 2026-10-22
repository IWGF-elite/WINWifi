$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $projectRoot "WinWiFi.Desktop\WinWiFi.Desktop.csproj"
$publishPath = Join-Path $projectRoot "publish\win-x64"

dotnet publish $projectPath `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    --output $publishPath

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "WinWiFi is ready at $publishPath\WinWiFi.exe"
