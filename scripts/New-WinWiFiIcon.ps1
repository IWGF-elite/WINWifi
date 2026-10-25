Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'WinWiFi.Desktop\Assets\WinWiFiShield.png'
$icoOutput = Join-Path $root 'WinWiFi.Desktop\Assets\WinWiFi.ico'
$webOutput = Join-Path $root 'public\winwifi-shield.png'
$sourceBitmap = [System.Drawing.Bitmap]::new($source)

# Remove only fully transparent margin from the supplied mark.
$left = $sourceBitmap.Width; $top = $sourceBitmap.Height; $right = -1; $bottom = -1
for ($y = 0; $y -lt $sourceBitmap.Height; $y++) {
  for ($x = 0; $x -lt $sourceBitmap.Width; $x++) {
    if ($sourceBitmap.GetPixel($x, $y).A -gt 8) {
      $left = [Math]::Min($left, $x); $top = [Math]::Min($top, $y)
      $right = [Math]::Max($right, $x); $bottom = [Math]::Max($bottom, $y)
    }
  }
}
if ($right -lt 0) { throw 'The supplied logo contains no visible pixels.' }
$crop = [System.Drawing.Rectangle]::FromLTRB($left, $top, $right + 1, $bottom + 1)
$cropped = $sourceBitmap.Clone($crop, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$iconSize = 256
$canvas = [System.Drawing.Bitmap]::new($iconSize, $iconSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($canvas)
$graphics.Clear([System.Drawing.Color]::Transparent)
$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$padding = 10
$scale = [Math]::Min(($iconSize - 2 * $padding) / $cropped.Width, ($iconSize - 2 * $padding) / $cropped.Height)
$width = [int]($cropped.Width * $scale); $height = [int]($cropped.Height * $scale)
$graphics.DrawImage($cropped, [int](($canvas.Width - $width) / 2), [int](($canvas.Height - $height) / 2), $width, $height)

New-Item -ItemType Directory -Force -Path (Split-Path $webOutput) | Out-Null
$canvas.Save($webOutput, [System.Drawing.Imaging.ImageFormat]::Png)
$iconHandle = $canvas.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($iconHandle)
$stream = [System.IO.File]::Open($icoOutput, [System.IO.FileMode]::Create)
$icon.Save($stream)
$stream.Dispose()
[System.Runtime.InteropServices.Marshal]::Release($iconHandle) | Out-Null
$graphics.Dispose(); $canvas.Dispose(); $cropped.Dispose(); $sourceBitmap.Dispose()
Write-Output "Generated $icoOutput and $webOutput from the supplied WinWiFi shield."
