param(
    [string]$Message = "Agent checkpoint",
    [string[]]$Paths = @(
        "tools/agent_helpers/agent_safe_checkpoint.ps1",
        "tools/pass638_after_capture",
        "artifacts/pass638_*",
        "inbox/codex_report.md",
        "inbox/antigravity_report.md",
        "inbox/sonnet_report.md",
        "outbox/supervisor_decision.json",
        "outbox/next_task_for_codex.md",
        "outbox/next_task_for_antigravity.md",
        "outbox/next_task_for_openclaw.md",
        "outbox/supervisor_packet.json"
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
    $_ -match '\.(pcap|pcapng|dll|bin|exe|zip|7z|rar|key|pem|pyc)$' -or
    $_ -match '(^|/)(captures|binaries|private|secrets|__pycache__)(/|$)' -or
    $_ -match 'payload|ciphertext|raw_packet|packet_hex|packet_hash'
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
