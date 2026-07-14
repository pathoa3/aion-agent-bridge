param(
    [string]$Message = "Agent checkpoint",
    [string[]]$Paths = @(
        "tools/agent_helpers/agent_safe_checkpoint.ps1",
        "docs/AGENT_WORK_CONTRACT.md",
        "tools/agent_helpers/run_work_queue_until_empty.ps1",
        "tools/agent_helpers/work_queue_schema.json",
        "tools/pass638_after_capture/validate_known_plaintext_log.py",
        "tools/pass638_after_capture/report_dynamic_flow_context.py",
        "tools/pass638_after_capture/run_s2c_oracle_after_capture.ps1",
        "tools/pass645_10242_oracle_analysis",
        "tools/pass646_10242_structured_model",
        "tools/pass647_dynamic_world_port",
        "tools/pass648_dynamic_world_s2c_oracle",
        "tools/pass649_current_length_ladder",
        "tools/pass650_marker_window_structure",
        "tools/pass651_extended_s2c_structure",
        "tools/pass652_10242_event_model",
        "tools/pass653_*",
        "tools/pass653_10242_labeler_hardening",
        "tools/pass654b_*",
        "tools/pass654b_offline_capture_validation",
        "tools/pass655_*",
        "tools/pass655_world_framing_marathon",
        "tools/pass656_*",
        "tools/pass656_sequence_correct_body_transform",
        "tools/pass657_*",
        "tools/pass657_corrective_holdout_validation",
        "artifacts/pass638_dynamic_flow_context.csv",
        "artifacts/pass638_known_plaintext_log_status.csv",
        "artifacts/pass645_10242_*",
        "artifacts/pass646_10242_*",
        "artifacts/pass646_next_capture_plan_10242_vs_7785.md",
        "artifacts/pass647_*",
        "artifacts/pass648_*",
        "artifacts/pass649_*",
        "artifacts/pass650_*",
        "artifacts/pass651_*",
        "artifacts/pass652_*",
        "artifacts/pass653_*",
        "artifacts/pass654b_*",
        "artifacts/pass655_*",
        "artifacts/pass656_*",
        "artifacts/pass657_*",
        "inbox/codex_report.md"
    )
)

$ErrorActionPreference = "Continue"

Set-Location "C:\AionTools\aion-agent-bridge"

function Add-PathIfPresent {
    param([string]$PathSpec)
    if ($PathSpec -match '[*?]') {
        $matches = Get-ChildItem -Path $PathSpec -File -ErrorAction SilentlyContinue
        foreach ($m in $matches) {
            git add -- $m.FullName
        }
    } elseif (Test-Path $PathSpec) {
        git add -- $PathSpec
    }
}

Write-Host "== Agent safe checkpoint =="
git status -sb

Write-Host "`n== Add allowlisted paths only =="
foreach ($p in $Paths) {
    Add-PathIfPresent $p
}

Write-Host "`n== Safety check: reject forbidden staged files =="
$staged = git diff --cached --name-only

$forbidden = $staged | Where-Object {
    $isAllowedPayloadMetadata = $_ -eq 'artifacts/pass646_10242_payload_classification.csv' -or $_ -eq 'artifacts/pass651_local_payload_triage_summary.csv'
    (-not $isAllowedPayloadMetadata) -and (
        $_ -match '\.(pcap|pcapng|dll|bin|exe|zip|7z|rar|key|pem|pyc)$' -or
        $_ -match '(^|/)(captures|binaries|private|secrets|__pycache__)(/|$)' -or
        $_ -match 'payload|ciphertext|raw_packet|packet_hex|packet_hash'
    )
}

if ($forbidden) {
    Write-Host "Forbidden staged files detected. Unstaging them:"
    $forbidden | ForEach-Object {
        Write-Host "  $_"
        git restore --staged -- "$_"
    }
}

Write-Host "`n== Commit if needed =="
$stillStaged = git diff --cached --name-only

if ($stillStaged) {
    git commit -m "$Message"
} else {
    Write-Host "Nothing safe staged to commit."
}

Write-Host "`n== Always push =="
git push origin main
$pushExit = $LASTEXITCODE
Write-Host "git push origin main exit code: $pushExit"

Write-Host "`n== Final status =="
git status -sb
git log --oneline -5

if ($pushExit -ne 0) {
    Write-Error "git push origin main failed with exit code $pushExit"
    exit $pushExit
}

exit 0


















