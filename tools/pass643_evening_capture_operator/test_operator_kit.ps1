$ErrorActionPreference = "Continue"
$Repo = "C:\AionTools\aion-agent-bridge"
$ToolDir = Join-Path $Repo "tools\pass643_evening_capture_operator"
$Artifacts = Join-Path $Repo "artifacts"
$OutDir = "C:\AionTools\aion_decoder_agent\inbox\captures"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$scripts = @(
    "start_s2c_oracle_capture.ps1",
    "stop_s2c_oracle_capture.ps1",
    "log_s2c_marker.ps1",
    "create_marker_log_template.ps1",
    "run_after_capture_full.ps1",
    "test_operator_kit.ps1",
    "README.md"
)
$rows = @()
foreach ($s in $scripts) {
    $p = Join-Path $ToolDir $s
    $rows += [pscustomobject]@{ check="script_exists"; target=$s; ok=(Test-Path -LiteralPath $p); detail=$p }
}
$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$pathTool = Get-Command dumpcap.exe,tshark.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$rows += [pscustomobject]@{ check="wireshark_tool_available"; target="dumpcap_or_tshark"; ok=((Test-Path -LiteralPath $dumpcap) -or (Test-Path -LiteralPath $tshark) -or [bool]$pathTool); detail="common_paths_or_PATH" }
$rows += [pscustomobject]@{ check="output_dir_ready"; target=$OutDir; ok=(Test-Path -LiteralPath $OutDir); detail="created_if_missing" }
Set-Location $Repo
$forbidden = git diff --cached --name-only | Where-Object { $_ -match '\.(pcap|pcapng|dll|bin|exe|zip|7z|rar|key|pem|pyc)$' -or $_ -match '(^|/)(captures|binaries|private|secrets|__pycache__)(/|$)' -or $_ -match 'payload|ciphertext|raw_packet|packet_hex|packet_hash' }
$rows += [pscustomobject]@{ check="no_forbidden_files_staged"; target="git_index"; ok=(-not $forbidden); detail=(($forbidden -join ';')) }
$out = Join-Path $Artifacts "pass643_operator_dry_run_status.csv"
$rows | Export-Csv -LiteralPath $out -NoTypeInformation -Encoding UTF8
$rows | Format-Table -AutoSize
Write-Host "Dry-run status written to $out"
