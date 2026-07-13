$ErrorActionPreference = "Stop"
$names = @("dumpcap", "tshark")
$stopped = 0
foreach ($name in $names) {
  Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "Stopping $($_.ProcessName) pid=$($_.Id)"
    Stop-Process -Id $_.Id -Force
    $stopped += 1
  }
}
if ($stopped -eq 0) {
  Write-Host "No dumpcap/tshark process found. If Wireshark GUI is running, stop and save manually."
}
