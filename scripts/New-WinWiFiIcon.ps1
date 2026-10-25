Add-Type -AssemblyName System.Drawing

$size = 256
$bitmap = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)

$bounds = [System.Drawing.RectangleF]::new(4, 4, 248, 248)
$corner = 58
$path = [System.Drawing.Drawing2D.GraphicsPath]::new()
$path.AddArc($bounds.X, $bounds.Y, $corner, $corner, 180, 90)
$path.AddArc($bounds.Right - $corner, $bounds.Y, $corner, $corner, 270, 90)
$path.AddArc($bounds.Right - $corner, $bounds.Bottom - $corner, $corner, $corner, 0, 90)
$path.AddArc($bounds.X, $bounds.Bottom - $corner, $corner, $corner, 90, 90)
$path.CloseFigure()

$blue = [System.Drawing.Drawing2D.LinearGradientBrush]::new($bounds, [System.Drawing.Color]::FromArgb(41, 198, 255), [System.Drawing.Color]::FromArgb(37, 99, 235), 45)
$graphics.FillPath($blue, $path)

$shield = [System.Drawing.Drawing2D.GraphicsPath]::new()
$shield.AddLines([System.Drawing.PointF[]]@(
  [System.Drawing.PointF]::new(128, 39), [System.Drawing.PointF]::new(197, 64), [System.Drawing.PointF]::new(197, 116),
  [System.Drawing.PointF]::new(190, 166), [System.Drawing.PointF]::new(165, 203), [System.Drawing.PointF]::new(128, 221),
  [System.Drawing.PointF]::new(91, 203), [System.Drawing.PointF]::new(66, 166), [System.Drawing.PointF]::new(59, 116),
  [System.Drawing.PointF]::new(59, 64), [System.Drawing.PointF]::new(128, 39)
))
$shield.CloseFigure()
$graphics.FillPath([System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(235, 7, 21, 37)), $shield)

$whitePen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(248, 250, 252), 14)
$whitePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$whitePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$graphics.DrawArc($whitePen, 65, 67, 126, 126, 218, 104)
$graphics.DrawArc($whitePen, 88, 90, 80, 80, 218, 104)
$graphics.DrawLine($whitePen, 121, 148, 135, 148)
$graphics.FillEllipse([System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(64, 245, 197)), 115, 165, 26, 26)

$output = Join-Path $PSScriptRoot '..\WinWiFi.Desktop\Assets\WinWiFi.ico'
$iconHandle = $bitmap.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($iconHandle)
$stream = [System.IO.File]::Open($output, [System.IO.FileMode]::Create)
$icon.Save($stream)
$stream.Dispose()
[System.Runtime.InteropServices.Marshal]::Release($iconHandle) | Out-Null
$whitePen.Dispose(); $blue.Dispose(); $shield.Dispose(); $path.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
Write-Output "Generated $output"
