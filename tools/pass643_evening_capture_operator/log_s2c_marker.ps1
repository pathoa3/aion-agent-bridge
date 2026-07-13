param(
    [Parameter(Mandatory=$true)] [string]$Text,
    [string]$Direction = "S2C",
    [string]$Notes = "visible on target client",
    [string]$LogPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt"
)

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $dir | Out-Null
if (!(Test-Path -LiteralPath $LogPath)) {
    Set-Content -LiteralPath $LogPath -Value "timestamp_local,frame_hint,direction,visible_text,notes" -Encoding UTF8
}
if ($Direction -eq "S2C" -and $Text.Length -lt 16) {
    Write-Warning "S2C marker text is shorter than 16 characters; longer repeated markers are stronger oracle material."
}
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
function CsvEscape([string]$s) { '"' + ($s -replace '"', '""') + '"' }
$row = @(
    (CsvEscape $timestamp),
    "",
    (CsvEscape $Direction),
    (CsvEscape $Text),
    (CsvEscape $Notes)
) -join ","
Add-Content -LiteralPath $LogPath -Value $row -Encoding UTF8
Write-Host "Logged marker at $timestamp : $Text"
Write-Host "Log path: $LogPath"
