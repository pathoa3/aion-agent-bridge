param(
    [Parameter(Mandatory=$true)][string]$Queue,
    [Parameter(Mandatory=$true)][string]$MasterRunner
)
$ErrorActionPreference = "Stop"
$repo = "C:\AionTools\aion-agent-bridge"
Set-Location $repo

function Test-QueueState {
    param([object]$QueueObject, [string]$QueuePath)
    if (-not $QueueObject.stages) { throw "Queue has no stages: $QueuePath" }
    foreach ($stage in $QueueObject.stages) {
        $name = [string]$stage.name
        if ($stage.status -eq "completed") {
            if ([int]$stage.attempts -le 0) { throw "Completed stage has zero primary attempts: $name" }
            foreach ($artifact in @($stage.produced_artifacts)) {
                if ([string]::IsNullOrWhiteSpace([string]$artifact)) { continue }
                if (-not (Test-Path -LiteralPath $artifact)) { throw "Completed stage missing required artifact: $name -> $artifact" }
                $item = Get-Item -LiteralPath $artifact -ErrorAction Stop
                if ($item.PSIsContainer -eq $false -and $item.Length -eq 0) { throw "Completed stage artifact is empty: $name -> $artifact" }
            }
        }
        if ($stage.fallback_status -eq "completed" -and [int]$stage.fallback_attempts -le 0) {
            throw "Fallback completed with zero attempts: $name"
        }
    }
}

while ($true) {
    powershell -ExecutionPolicy Bypass -File $MasterRunner
    if ($LASTEXITCODE -ne 0) { throw "Master runner failed with exit code ${LASTEXITCODE}: $MasterRunner" }
    if (-not (Test-Path $Queue)) { throw "Queue not found: $Queue" }
    $q = Get-Content -LiteralPath $Queue -Raw | ConvertFrom-Json
    Test-QueueState -QueueObject $q -QueuePath $Queue
    $unfinished = @($q.stages | Where-Object { $_.status -in @("pending", "running", "blocked") -or $_.fallback_status -in @("pending", "running", "blocked") })
    if ($unfinished.Count -eq 0) { break }
    Write-Host "Queue still has unfinished stages: $($unfinished.Count); rerunning master runner."
}
Write-Host "Queue completed: $Queue"

