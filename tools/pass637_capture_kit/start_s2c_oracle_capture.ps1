param(
  [string]$OutPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng"
)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $OutPath
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$dumpcap = Get-Command dumpcap.exe -ErrorAction SilentlyContinue
$tshark = Get-Command tshark.exe -ErrorAction SilentlyContinue
if ($dumpcap) {
  Write-Host "Starting dumpcap capture to $OutPath"
  Start-Process -FilePath $dumpcap.Source -ArgumentList @("-i", "1", "-f", "tcp port 7785", "-w", $OutPath) -WindowStyle Hidden
} elseif ($tshark) {
  Write-Host "Starting tshark capture to $OutPath"
  Start-Process -FilePath $tshark.Source -ArgumentList @("-i", "1", "-f", "tcp port 7785", "-w", $OutPath) -WindowStyle Hidden
} else {
  throw "Neither dumpcap.exe nor tshark.exe was found on PATH. Start Wireshark manually and save to $OutPath."
}
Write-Host "Capture started. Use stop_s2c_oracle_capture.ps1 after all markers are visible."
