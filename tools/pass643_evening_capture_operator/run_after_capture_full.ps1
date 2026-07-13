param(
    [string]$PcapPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_world_entry.pcapng",
    [string]$KnownLogPath = "C:\AionTools\aion_decoder_agent\inbox\captures\s2c_oracle_known_plaintext_log.txt",
    [string]$OutDir = "C:\AionTools\aion_decoder_agent\outbox\pass643_after_capture"
)

$ErrorActionPreference = "Stop"
$Repo = "C:\AionTools\aion-agent-bridge"
Set-Location $Repo
$runner = Join-Path $Repo "tools\pass638_after_capture\run_s2c_oracle_after_capture.ps1"
$checkpoint = Join-Path $Repo "tools\agent_helpers\agent_safe_checkpoint.ps1"
if (!(Test-Path -LiteralPath $runner)) { throw "Pass638 runner not found: $runner" }
if (!(Test-Path -LiteralPath $PcapPath)) { throw "PCAP not found: $PcapPath" }
if (!(Test-Path -LiteralPath $KnownLogPath)) { throw "Known plaintext log not found: $KnownLogPath" }

Write-Host "Running Pass638 post-capture validator/oracle pipeline..."
powershell -ExecutionPolicy Bypass -File $runner -PcapPath $PcapPath -KnownLogPath $KnownLogPath -OutDir $OutDir
$runExit = $LASTEXITCODE
if ($runExit -ne 0) { throw "Post-capture runner failed with exit code $runExit" }

Write-Host "Checkpointing safe metadata outputs only..."
powershell -ExecutionPolicy Bypass -File $checkpoint -Message "Analyze one-click S2C oracle capture"
exit $LASTEXITCODE
