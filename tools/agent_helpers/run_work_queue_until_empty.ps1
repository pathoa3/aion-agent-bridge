param(
    [Parameter(Mandatory=$true)][string]$Queue,
    [Parameter(Mandatory=$true)][string]$MasterRunner
)
$ErrorActionPreference = "Stop"
$repo = "C:\AionTools\aion-agent-bridge"
Set-Location $repo
while ($true) {
    powershell -ExecutionPolicy Bypass -File $MasterRunner
    if (-not (Test-Path $Queue)) { throw "Queue not found: $Queue" }
    $q = Get-Content -LiteralPath $Queue -Raw | ConvertFrom-Json
    $unfinished = @($q.stages | Where-Object { $_.status -in @("pending", "running", "blocked") -or $_.fallback_status -in @("pending", "running", "blocked") })
    if ($unfinished.Count -eq 0) { break }
    Write-Host "Queue still has unfinished stages: $($unfinished.Count); rerunning master runner."
}
Write-Host "Queue completed: $Queue"
