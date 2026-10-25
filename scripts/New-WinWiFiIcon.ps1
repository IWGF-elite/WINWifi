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
function New-LogoBitmap([int]$size) {
  $canvas = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $graphics = [System.Drawing.Graphics]::FromImage($canvas)
  $graphics.Clear([System.Drawing.Color]::Transparent)
  $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
  $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $padding = [Math]::Max(1, [int]($size * 0.04))
  $scale = [Math]::Min(($size - 2 * $padding) / $cropped.Width, ($size - 2 * $padding) / $cropped.Height)
  $width = [int]($cropped.Width * $scale); $height = [int]($cropped.Height * $scale)
  $graphics.DrawImage($cropped, [int](($size - $width) / 2), [int](($size - $height) / 2), $width, $height)
  $graphics.Dispose()
  return $canvas
}

New-Item -ItemType Directory -Force -Path (Split-Path $webOutput) | Out-Null
$webBitmap = New-LogoBitmap 512
$webBitmap.Save($webOutput, [System.Drawing.Imaging.ImageFormat]::Png)
$webBitmap.Dispose()

# Write a standards-compliant multi-frame ICO. The shell chooses the sharpest
# matching frame instead of shrinking one 256px image into a distorted taskbar icon.
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$frames = @()
foreach ($size in $sizes) {
  $frame = New-LogoBitmap $size
  $memory = [System.IO.MemoryStream]::new()
  $frame.Save($memory, [System.Drawing.Imaging.ImageFormat]::Png)
  $frames += ,$memory.ToArray()
  $memory.Dispose()
  $frame.Dispose()
}
$writer = [System.IO.BinaryWriter]::new([System.IO.File]::Open($icoOutput, [System.IO.FileMode]::Create))
$writer.Write([UInt16]0); $writer.Write([UInt16]1); $writer.Write([UInt16]$frames.Count)
$offset = 6 + (16 * $frames.Count)
for ($i = 0; $i -lt $frames.Count; $i++) {
  $dimension = $sizes[$i]
  $widthByte = [byte]$dimension; $heightByte = [byte]$dimension
  if ($dimension -eq 256) { $widthByte = [byte]0; $heightByte = [byte]0 }
  $writer.Write($widthByte); $writer.Write($heightByte); $writer.Write([byte]0); $writer.Write([byte]0)
  $writer.Write([UInt16]1); $writer.Write([UInt16]32); $writer.Write([UInt32]$frames[$i].Length); $writer.Write([UInt32]$offset)
  $offset += $frames[$i].Length
}
foreach ($frame in $frames) { $writer.Write($frame) }
$writer.Dispose(); $cropped.Dispose(); $sourceBitmap.Dispose()
Write-Output "Generated $icoOutput and $webOutput from the supplied WinWiFi shield."
