param(
    [string]$Message = "Agent checkpoint",
    [string[]]$Paths = @(
        "tools",
        "artifacts",
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

Write-Host "== Agent safe checkpoint =="
git status -sb

Write-Host "`n== Add allowlisted paths only =="
foreach ($p in $Paths) {
    if (Test-Path $p) {
        git add $p
    }
}

Write-Host "`n== Safety check: reject forbidden staged files =="
$staged = git diff --cached --name-only

$forbidden = $staged | Where-Object {
    $_ -match '\.(pcap|pcapng|dll|bin|exe|zip|7z|rar|key|pem)$' -or
    $_ -match '(^|/)(captures|binaries|private|secrets)(/|$)' -or
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

Write-Host "`n== Final status =="
git status -sb
git log --oneline -5
