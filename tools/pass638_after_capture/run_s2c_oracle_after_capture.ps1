param(
    [string]$PcapPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng",
    [string]$KnownLogPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt",
    [string]$OutDir = "C:\AionTools\aion_decoder_agent\outbox\pass638_s2c_oracle_after_capture",
    [switch]$DryRun,
    [string]$KnownText = "",
    [int]$CandidateFrame = 0,
    [ValidateSet("C2S", "S2C")] [string]$Direction = "S2C",
    [switch]$DeriveCheckpointOnly
)

$ErrorActionPreference = "Stop"
$Repo = "C:\AionTools\aion-agent-bridge"
$Artifacts = Join-Path $Repo "artifacts"
$ToolDir = Join-Path $Repo "tools\pass638_after_capture"
$CaptureValidator = Join-Path $Repo "tools\pass637_capture_kit\validate_capture_presence.py"
$LogValidator = Join-Path $ToolDir "validate_known_plaintext_log.py"
$WindowExtractor = Join-Path $ToolDir "extract_s2c_window_metadata.py"
$CribTool = Join-Path $Repo "tools\pass636_antigravity_s2c_oracle\s2c_crib_drag_oracle.py"
$DecodeTool = Join-Path $Repo "tools\pass636_antigravity_s2c_oracle\s2c_decode_from_oracle.py"
$KeyrollTool = Join-Path $Repo "tools\pass636_antigravity_s2c_oracle\s2c_keyroll_validate.py"
$CheckpointTool = Join-Path $Repo "tools\pass642_c2s_checkpoint_from_hello_hi\derive_c2s_key_from_known_text.py"

Set-Location $Repo

if ($DeriveCheckpointOnly) {
    if ([string]::IsNullOrWhiteSpace($KnownText)) { throw "-KnownText is required with -DeriveCheckpointOnly" }
    if ($CandidateFrame -le 0) { throw "-CandidateFrame is required with -DeriveCheckpointOnly" }
    if (!(Test-Path -LiteralPath $CheckpointTool)) { throw "Checkpoint tool not found: $CheckpointTool" }
    $captureDir = Split-Path -Parent $PcapPath
    Write-Host "Running checkpoint-only known-text derivation. Safe metadata only."
    python $CheckpointTool --capture-dir $captureDir --known-text $KnownText --candidate-frame $CandidateFrame --direction $Direction --derive-checkpoint-only
    exit $LASTEXITCODE
}

New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$steps = @(
    [pscustomobject]@{ step="check_pcap"; path=$PcapPath; exists=(Test-Path -LiteralPath $PcapPath); would_run="input_check"; creates_raw_output=$false },
    [pscustomobject]@{ step="check_known_log"; path=$KnownLogPath; exists=(Test-Path -LiteralPath $KnownLogPath); would_run="input_check"; creates_raw_output=$false },
    [pscustomobject]@{ step="capture_validator"; path=$CaptureValidator; exists=(Test-Path -LiteralPath $CaptureValidator); would_run="python tools/pass637_capture_kit/validate_capture_presence.py"; creates_raw_output=$false },
    [pscustomobject]@{ step="known_log_validator"; path=$LogValidator; exists=(Test-Path -LiteralPath $LogValidator); would_run="python tools/pass638_after_capture/validate_known_plaintext_log.py"; creates_raw_output=$false },
    [pscustomobject]@{ step="s2c_window_extractor"; path=$WindowExtractor; exists=(Test-Path -LiteralPath $WindowExtractor); would_run="python tools/pass638_after_capture/extract_s2c_window_metadata.py <pcap> <known_log> artifacts/pass638_s2c_window_inventory.csv"; creates_raw_output=$false },
    [pscustomobject]@{ step="s2c_crib_oracle"; path=$CribTool; exists=(Test-Path -LiteralPath $CribTool); would_run="python tools/pass636_antigravity_s2c_oracle/s2c_crib_drag_oracle.py <pcap> artifacts/pass638_s2c_crib_candidates.csv"; creates_raw_output=$false },
    [pscustomobject]@{ step="s2c_decode_candidates"; path=$DecodeTool; exists=(Test-Path -LiteralPath $DecodeTool); would_run="python tools/pass636_antigravity_s2c_oracle/s2c_decode_from_oracle.py <pcap> artifacts/pass638_s2c_crib_candidates.csv"; creates_raw_output=$false },
    [pscustomobject]@{ step="keyroll_validation"; path=$KeyrollTool; exists=(Test-Path -LiteralPath $KeyrollTool); would_run="run only if candidate validates; current tool is hard-coded to Pass636 capture"; creates_raw_output=$false }
)

$dryCsv = Join-Path $Artifacts "pass638_dry_run_status.csv"
$steps | Export-Csv -LiteralPath $dryCsv -NoTypeInformation -Encoding UTF8

if ($DryRun) {
    Write-Host "Pass638 dry run. No packet payloads processed."
    $steps | Format-Table -AutoSize
    Write-Host "Dry-run status: $dryCsv"
    exit 0
}

if (!(Test-Path -LiteralPath $PcapPath)) { throw "PCAP not found: $PcapPath" }
if (!(Test-Path -LiteralPath $KnownLogPath)) { throw "Known plaintext log not found: $KnownLogPath" }
foreach ($tool in @($CaptureValidator, $LogValidator, $WindowExtractor, $CribTool, $DecodeTool)) {
    if (!(Test-Path -LiteralPath $tool)) { throw "Required tool not found: $tool" }
}

$env:PYTHONPATH = "$Repo\tools\pass636_antigravity_s2c_oracle;$Repo"

Write-Host "Running safe capture presence validator..."
python $CaptureValidator --repo-root $Repo

Write-Host "Running known plaintext log validator..."
python $LogValidator $KnownLogPath --out-csv (Join-Path $Artifacts "pass638_known_plaintext_log_status.csv")

Write-Host "Running S2C window metadata extractor..."
python $WindowExtractor $PcapPath $KnownLogPath --out-csv (Join-Path $Artifacts "pass638_s2c_window_inventory.csv")

Write-Host "Running S2C crib/oracle metadata scan..."
$cribCsv = Join-Path $Artifacts "pass638_s2c_crib_candidates.csv"
python $CribTool $PcapPath $cribCsv

Write-Host "Running candidate decode metadata validation..."
python $DecodeTool $PcapPath $cribCsv

$validation = Join-Path $Artifacts "pass636_antigravity_s2c_validation.csv"
$hasValidated = $false
if (Test-Path -LiteralPath $validation) {
    $hasValidated = Select-String -LiteralPath $validation -Pattern ',true,' -Quiet
}

if ($hasValidated) {
    Write-Host "A validating candidate marker was detected; run bounded keyroll validation manually after reviewing safe metadata."
} else {
    Write-Host "No validating candidate marker detected; skipping hard-coded Pass636 keyroll tool."
}


