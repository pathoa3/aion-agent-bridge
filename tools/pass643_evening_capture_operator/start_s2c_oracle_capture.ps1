param(
    [string]$OutDir = "C:\AionTools\aion_decoder_agent\inbox\captures",
    [string]$BaseName = "s2c_oracle_world_entry",
    [string]$Interface = ""
)

$ErrorActionPreference = "Stop"
$filter = "tcp port 7785 or tcp port 10242 or tcp port 2106"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$finalPath = Join-Path $OutDir ($BaseName + ".pcapng")
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = Join-Path $OutDir ($BaseName + "_" + $stamp + ".pcapng")
$pidFile = Join-Path $OutDir ($BaseName + ".capture_pid.txt")
$pathFile = Join-Path $OutDir ($BaseName + ".capture_path.txt")

$candidates = @(
    "C:\Program Files\Wireshark\dumpcap.exe",
    "C:\Program Files\Wireshark\tshark.exe"
)
$cmd = $null
foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { $cmd = $c; break }
}
if (-not $cmd) {
    $found = Get-Command dumpcap.exe,tshark.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $cmd = $found.Source }
}
if (-not $cmd) { throw "Neither dumpcap.exe nor tshark.exe was found. Install Wireshark or add it to PATH." }

if ([string]::IsNullOrWhiteSpace($Interface)) {
    Write-Host "Available capture interfaces:"
    & $cmd -D
    $Interface = Read-Host "Enter interface number/name to capture on"
    if ([string]::IsNullOrWhiteSpace($Interface)) { throw "No interface selected." }
}

$args = @("-i", $Interface, "-f", $filter, "-w", $backupPath)
Write-Host "Starting capture with: $cmd $($args -join ' ')"
Write-Host "Final expected path will be: $finalPath"
Write-Host "Timestamped capture path: $backupPath"
$p = Start-Process -FilePath $cmd -ArgumentList $args -PassThru -WindowStyle Hidden
Set-Content -LiteralPath $pidFile -Value $p.Id -Encoding ASCII
Set-Content -LiteralPath $pathFile -Value $backupPath -Encoding UTF8
Write-Host "Capture started pid=$($p.Id)."
Write-Host "Now login/enter world, receive visible S2C markers, and log each marker with log_s2c_marker.ps1."
Write-Host "Stop with: powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\stop_s2c_oracle_capture.ps1"
