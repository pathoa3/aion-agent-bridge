# Pass653 clean capture v2 start kit. Does not start automatically unless user runs it.
$ErrorActionPreference = "Stop"
$capDir = "C:\AionTools\aion_decoder_agent\inbox\captures"
$log = Join-Path $capDir "s2c_oracle_known_plaintext_log.txt"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (Test-Path $log) {
  $archive = Join-Path $capDir "s2c_oracle_known_plaintext_log_mixed_$stamp.txt"
  Move-Item -LiteralPath $log -Destination $archive
}
"timestamp_local,direction,visible_text,notes" | Set-Content -LiteralPath $log -Encoding ASCII
Write-Host "Known plaintext log reset. Capture filter to use:"
Write-Host "host 51.83.147.97 and (tcp port 2106 or tcp port 11000 or tcp port 10242 or tcp portrange 7770-7799)"
Write-Host "Start packet capture manually with this filter, then run clean_capture_v2_marker_commands.ps1 for marker text."
