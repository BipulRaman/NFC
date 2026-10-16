# Renders the SVG icon sources in this folder into the PNG/ICO files both apps use.
# Requires resvg: `cargo install resvg`. Run from anywhere: `pwsh assets/render-icons.ps1`.
$ErrorActionPreference = 'Stop'
$assets = $PSScriptRoot
$root = Split-Path $assets -Parent
$tmp = Join-Path ([IO.Path]::GetTempPath()) "nfc-studio-icons"
New-Item -ItemType Directory -Force $tmp | Out-Null

function Render([string]$svg, [int]$size, [string]$out) {
    New-Item -ItemType Directory -Force (Split-Path $out -Parent) | Out-Null
    & resvg --width $size --height $size (Join-Path $assets $svg) $out
    if ($LASTEXITCODE -ne 0) { throw "resvg failed for $svg at $size px" }
}

# Desktop: window icon and a multi-size Windows .ico (PNG-compressed entries).
$desktop = Join-Path $root 'app/desktop/assets'
Render 'icon.svg' 256 (Join-Path $desktop 'icon-256.png')
$sizes = 16, 24, 32, 48, 64, 128, 256
$images = foreach ($s in $sizes) {
    $png = Join-Path $tmp "ico-$s.png"
    Render 'icon.svg' $s $png
    , [IO.File]::ReadAllBytes($png)
}
$ico = New-Object IO.MemoryStream
$w = New-Object IO.BinaryWriter $ico
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$images[$i].Length); $w.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $w.Write($img) }
$w.Flush()
[IO.File]::WriteAllBytes((Join-Path $desktop 'icon.ico'), $ico.ToArray())

# Android: legacy launcher icons plus adaptive-icon foreground and themed (monochrome) layers.
$res = Join-Path $root 'app/android/app/src/main/res'
$densities = [ordered]@{ mdpi = 1.0; hdpi = 1.5; xhdpi = 2.0; xxhdpi = 3.0; xxxhdpi = 4.0 }
foreach ($d in $densities.Keys) {
    $f = $densities[$d]
    $dir = Join-Path $res "mipmap-$d"
    Render 'icon.svg' ([int](48 * $f)) (Join-Path $dir 'ic_launcher.png')
    Render 'icon-foreground.svg' ([int](108 * $f)) (Join-Path $dir 'ic_launcher_foreground.png')
    Render 'icon-monochrome.svg' ([int](108 * $f)) (Join-Path $dir 'ic_launcher_monochrome.png')
}

Remove-Item $tmp -Recurse -Force
Write-Host "Icons rendered."
