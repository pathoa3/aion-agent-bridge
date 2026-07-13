param(
    [string]$LogPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt"
)

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$lines = @(
    "timestamp_local,frame_hint,direction,visible_text,notes",
    "# Use log_s2c_marker.ps1 at the actual visible moment. Do not treat these comment lines as real timestamps.",
    "# S2C_ORACLE_001_A1B2",
    "# S2C_ORACLE_002_C3D4",
    "# S2C_ORACLE_003_0123456789",
    "# S2C_ORACLE_004_REPEAT",
    "# S2C_ORACLE_004_REPEAT"
)
Set-Content -LiteralPath $LogPath -Value $lines -Encoding UTF8
Write-Host "Created marker log template: $LogPath"
Write-Host "Prefer live logging with log_s2c_marker.ps1 immediately after each marker is visible on the target client."
