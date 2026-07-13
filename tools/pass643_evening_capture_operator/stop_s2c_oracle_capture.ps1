param(
    [string]$OutDir = "C:\AionTools\aion_decoder_agent\inbox\captures",
    [string]$BaseName = "s2c_oracle_world_entry"
)

$ErrorActionPreference = "Continue"
$finalPath = Join-Path $OutDir ($BaseName + ".pcapng")
$pidFile = Join-Path $OutDir ($BaseName + ".capture_pid.txt")
$pathFile = Join-Path $OutDir ($BaseName + ".capture_path.txt")
$backupPath = if (Test-Path -LiteralPath $pathFile) { (Get-Content -LiteralPath $pathFile -Raw).Trim() } else { "" }

if (Test-Path -LiteralPath $pidFile) {
    $pidText = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    $proc = Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue
    if ($proc -and ($proc.ProcessName -in @("dumpcap", "tshark"))) {
        Write-Host "Stopping capture process $($proc.ProcessName) pid=$($proc.Id)"
        Stop-Process -Id $proc.Id -Force
        Start-Sleep -Seconds 2
    } else {
        Write-Host "Recorded capture pid is no longer running or is not dumpcap/tshark. Not killing anything else."
    }
} else {
    Write-Host "No capture pid file found. Not stopping unrelated processes."
}

if ($backupPath -and (Test-Path -LiteralPath $backupPath)) {
    Copy-Item -LiteralPath $backupPath -Destination $finalPath -Force
    Write-Host "Copied timestamped capture to expected path: $finalPath"
} else {
    Write-Host "Timestamped capture path not found yet: $backupPath"
}

Write-Host "Next command:"
Write-Host "powershell -ExecutionPolicy Bypass -File tools\pass643_evening_capture_operator\run_after_capture_full.ps1"
